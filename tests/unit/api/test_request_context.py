"""Every log line of a request says who, from where and which request; every answer has an X-Request-ID (F12.3)."""

from __future__ import annotations

import asyncio
import contextvars
import io
import json
import logging
import re
from collections.abc import Awaitable, Callable, Iterator

import pytest
from authfakes import SETTINGS, FakeVerifier, bearer
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient
from starlette.types import Message, Receive, Scope, Send

from api.app import create_app
from api.auth import InMemoryUserDirectory, Role
from api.request_context import RequestContextMiddleware
from core.logging import configure_logging

pytestmark = pytest.mark.unit


@pytest.fixture
def client() -> Iterator[tuple[TestClient, io.StringIO]]:
    verifier = FakeVerifier()
    verifier.add("reader", Role.READER, uid="uid-reader")
    verifier.add("admin", Role.ADMIN, uid="uid-admin")
    app = create_app(SETTINGS, token_verifier=verifier, user_directory=InMemoryUserDirectory(), role_manager=object())
    stream = io.StringIO()
    configure_logging(SETTINGS.secret_values(), stream=stream)  # create_app logs to stdout; capture instead
    yield TestClient(app), stream
    logging.getLogger().handlers.clear()


def entries(stream: io.StringIO, contains: str) -> list[dict[str, str]]:
    return [e for e in map(json.loads, stream.getvalue().splitlines()) if contains in e["message"]]


def test_every_answer_carries_a_generated_request_id() -> None:
    app = create_app(SETTINGS, token_verifier=FakeVerifier(), role_manager=object())
    first, second = TestClient(app).get("/api/health"), TestClient(app).get("/api/nope")
    assert re.fullmatch(r"[0-9a-f]{32}", first.headers["x-request-id"])
    assert first.headers["x-request-id"] != second.headers["x-request-id"]
    assert second.status_code == 404 and "x-request-id" in second.headers


def test_a_request_id_sent_by_the_client_is_never_reused() -> None:
    """Generated on the server only: two requests can never share an id, and the log never masks it."""
    app = create_app(SETTINGS, token_verifier=FakeVerifier(), role_manager=object())
    answer = TestClient(app).get("/api/health", headers={"X-Request-ID": "proxy-0123456789"})
    assert answer.headers["x-request-id"] != "proxy-0123456789"
    assert answer.headers.get_list("x-request-id") == [answer.headers["x-request-id"]]


def test_a_broken_stream_stays_broken_for_the_client() -> None:
    """ARQ-05: a stream that fails after its first event must not look like a clean end to the front."""

    def broken() -> Iterator[bytes]:
        yield b"data: start\n\n"
        raise RuntimeError("stream broke")

    app = create_app(SETTINGS, token_verifier=FakeVerifier(), role_manager=object())
    app.add_api_route("/api/broken-stream", lambda: StreamingResponse(broken()), methods=["GET"])
    with pytest.raises(RuntimeError, match="stream broke"):
        TestClient(app).get("/api/broken-stream")


def run_isolated(scenario: Callable[[], Awaitable[None]]) -> None:
    """One request per task, like an ASGI server: the context of one run never reaches the test or the next run."""
    contextvars.copy_context().run(asyncio.run, scenario())


def test_the_servers_own_error_log_still_names_the_request() -> None:
    """After an error leaves the middleware, Uvicorn logs it in the same task: that line keeps the context."""
    stream = io.StringIO()
    configure_logging(stream=stream)
    sent: list[Message] = []

    async def streaming_then_failing(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"data: 1\n\n", "more_body": True})
        raise RuntimeError("stream broke")

    async def server() -> None:
        async def send(message: Message) -> None:
            sent.append(message)

        try:
            await RequestContextMiddleware(streaming_then_failing)(SCOPE, receive_nothing, send)
        except RuntimeError:
            logging.getLogger("uvicorn.error").exception("Exception in ASGI application")  # what Uvicorn does next

    try:
        run_isolated(server)
    finally:
        logging.getLogger().handlers.clear()
    (entry,) = entries(stream, "Exception in ASGI application")
    request_id = dict(sent[0]["headers"])[b"x-request-id"].decode()
    assert (entry["request_id"], entry["path"], entry["client"]) == (request_id, "/api/runs/1/events", "10.0.0.7")
    assert not any(m.get("more_body") is False for m in sent)  # never closed as if it had ended well


def test_a_failure_before_the_answer_gets_the_500_envelope_with_its_request_id() -> None:
    """A middleware outside UnhandledErrorMiddleware failing before answering: the 500 carries X-Request-ID and the
    security headers, and the error still reaches the server."""
    sent: list[Message] = []

    async def failing(scope: Scope, receive: Receive, send: Send) -> None:
        raise RuntimeError("outer middleware broke")

    async def server() -> None:
        async def send(message: Message) -> None:
            sent.append(message)

        with pytest.raises(RuntimeError, match="outer middleware broke"):
            await RequestContextMiddleware(failing)(SCOPE, receive_nothing, send)

    run_isolated(server)
    start, body = sent[0], sent[1]
    headers = dict(start["headers"])
    assert start["status"] == 500
    assert re.fullmatch(rb"[0-9a-f]{32}", headers[b"x-request-id"])
    assert headers[b"x-content-type-options"] == b"nosniff"
    assert json.loads(body["body"])["error"]["code"] == "internal_error"


SCOPE: Scope = {
    "type": "http",
    "method": "GET",
    "path": "/api/runs/1/events",
    "headers": [],
    "client": ("10.0.0.7", 5555),
}


async def receive_nothing() -> Message:
    return {"type": "http.disconnect"}


def test_a_rejected_token_is_logged_with_where_and_which_request(client: tuple[TestClient, io.StringIO]) -> None:
    http, stream = client
    answer = http.get("/api/me?secret=1", headers=bearer("unknown-token"))
    assert answer.status_code == 401
    (entry,) = entries(stream, "authentication rejected: token_invalid")
    assert entry["level"] == "WARNING"
    assert entry["request_id"] == answer.headers["x-request-id"]
    assert (entry["method"], entry["path"], entry["client"]) == ("GET", "/api/me", "testclient")  # no query string
    assert "user" not in entry
    assert "unknown-token" not in stream.getvalue()


def test_a_missing_token_is_logged_too(client: tuple[TestClient, io.StringIO]) -> None:
    http, stream = client
    assert http.get("/api/me").status_code == 401
    assert entries(stream, "authentication rejected: missing_bearer")


def test_a_denied_role_names_the_verified_user(client: tuple[TestClient, io.StringIO]) -> None:
    """The user is bound in one dependency (a worker thread) and seen by the next one (another thread)."""
    http, stream = client
    answer = http.put("/api/admin/users/uid-x/role", json={"role": "admin"}, headers=bearer("reader"))
    assert answer.status_code == 403
    (entry,) = entries(stream, "authorization denied")
    assert entry["user"] == "uid-reader"
    assert entry["request_id"] == answer.headers["x-request-id"]
    assert entry["path"] == "/api/admin/users/uid-x/role"


def test_the_context_does_not_leak_into_the_next_request(client: tuple[TestClient, io.StringIO]) -> None:
    http, stream = client
    http.put("/api/admin/users/uid-x/role", json={"role": "admin"}, headers=bearer("reader"))
    http.get("/api/me")
    (entry,) = entries(stream, "missing_bearer")
    assert "user" not in entry
