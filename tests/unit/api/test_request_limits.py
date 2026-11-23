"""Bodies above 1 MiB are refused with 413 before a route reads them (docs/14 §10.4, ASVS V4)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from authfakes import SETTINGS, FakeVerifier
from fastapi.testclient import TestClient

from api.app import create_app
from api.request_limits import MAX_BODY_BYTES, BodySizeLimitMiddleware

pytestmark = pytest.mark.unit


def client() -> TestClient:
    return TestClient(create_app(SETTINGS, token_verifier=FakeVerifier(), role_manager=object()))


def test_a_declared_large_body_is_refused_with_the_envelope_and_headers() -> None:
    response = client().post("/api/feedback", content=b"x" * (MAX_BODY_BYTES + 1))
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_a_normal_body_passes_through() -> None:
    assert client().post("/api/feedback", json={}).status_code == 401  # reaches authentication


def test_a_malformed_content_length_is_refused() -> None:
    response = client().post("/api/feedback", content=b"{}", headers={"content-length": "abc"})
    assert response.status_code in {400, 413}


def _run(app: Any, chunks: list[bytes], scope_type: str = "http") -> list[dict[str, Any]]:
    sent: list[dict[str, Any]] = []
    queue = [{"type": "http.request", "body": c, "more_body": i < len(chunks) - 1} for i, c in enumerate(chunks)]

    async def receive() -> dict[str, Any]:
        return queue.pop(0)

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    middleware = BodySizeLimitMiddleware(app, max_bytes=10)
    asyncio.run(middleware({"type": scope_type, "headers": []}, receive, send))
    return sent


async def _reading_app(scope: Any, receive: Any, send: Any) -> None:
    more = True
    while more:
        message = await receive()
        more = message.get("more_body", False)
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def test_a_chunked_body_is_counted_while_streaming() -> None:
    assert _run(_reading_app, [b"12345", b"67890", b"1"])[0]["status"] == 413
    assert _run(_reading_app, [b"12345", b"67890"])[0]["status"] == 200


def test_a_late_overflow_after_the_response_started_is_not_answered_twice() -> None:
    async def answers_then_reads(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await receive()
        await receive()

    sent = _run(answers_then_reads, [b"123456", b"789012"])
    assert [m.get("status") for m in sent if m["type"] == "http.response.start"] == [200]


def test_other_scopes_pass_through() -> None:
    seen: list[str] = []

    async def lifespan_app(scope: Any, receive: Any, send: Any) -> None:
        seen.append(scope["type"])

    _run(lifespan_app, [b""], scope_type="lifespan")
    assert seen == ["lifespan"]
