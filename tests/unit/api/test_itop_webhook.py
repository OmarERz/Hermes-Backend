"""iTop webhook doorbell: fails closed, checks the bearer, validates the minimal payload, re-reads in background."""

from __future__ import annotations

import logging
from typing import Any

import pytest
from authfakes import SETTINGS, FakeVerifier, bearer
from fastapi.testclient import TestClient
from pydantic import SecretStr

from api.app import create_app
from core.itop.client import ItopUnavailableError

pytestmark = pytest.mark.unit
TOKEN = "webhook-test-secret"  # noqa: S105  (fake credential)
CALL = {"class": "UserRequest", "id": "123", "ref": "R-000123"}


class FakeSync:
    def __init__(self, error: Exception | None = None) -> None:
        self.calls: list[str] = []
        self.error = error

    def sync_itop_ticket(self, itop_id: str) -> bool:
        self.calls.append(itop_id)
        if self.error:
            raise self.error
        return True


def client(token: str | None = TOKEN, sync: Any = None) -> TestClient:
    settings = SETTINGS.model_copy(update={"itop_webhook_token": SecretStr(token) if token else None})
    app = create_app(settings, token_verifier=FakeVerifier(), role_manager=object(), ticket_sync=sync)
    return TestClient(app)


def test_a_valid_call_is_accepted_and_re_read_in_background() -> None:
    sync = FakeSync()
    response = client(sync=sync).post("/api/itop/webhook", json=CALL, headers=bearer(TOKEN))
    assert (response.status_code, response.json()) == (202, {"status": "accepted"})
    assert sync.calls == ["123"]


def test_without_token_or_itop_the_webhook_is_disabled() -> None:
    for app_client in (client(token=None, sync=FakeSync()), client(sync=None)):
        response = app_client.post("/api/itop/webhook", json=CALL, headers=bearer(TOKEN))
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "webhook_disabled"


@pytest.mark.parametrize("headers", [{}, bearer("wrong"), {"Authorization": TOKEN}, bearer(TOKEN + "x")])
def test_a_missing_or_wrong_token_is_rejected(headers: dict[str, str]) -> None:
    sync = FakeSync()
    response = client(sync=sync).post("/api/itop/webhook", json=CALL, headers=headers)
    assert response.status_code == 401
    assert sync.calls == []


@pytest.mark.parametrize(
    "body",
    [
        {"class": "Server", "id": "1"},
        {"class": "UserRequest", "id": "0"},
        {"class": "UserRequest", "id": "1 OR 1=1"},
        {"class": "UserRequest", "id": "1", "title": "x"},
        {"class": "UserRequest"},
    ],
)
def test_only_the_minimal_userrequest_payload_is_accepted(body: dict[str, str]) -> None:
    sync = FakeSync()
    response = client(sync=sync).post("/api/itop/webhook", json=body, headers=bearer(TOKEN))
    assert response.status_code == 422
    assert sync.calls == []


def test_a_failed_re_read_is_logged_not_raised(capsys: pytest.CaptureFixture[str]) -> None:
    sync = FakeSync(error=ItopUnavailableError("down"))
    response = client(sync=sync).post("/api/itop/webhook", json=CALL, headers=bearer(TOKEN))
    assert response.status_code == 202
    assert "periodic sync will retry" in capsys.readouterr().out


def test_the_app_builds_the_ticket_sync_when_itop_is_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    built: list[tuple[Any, ...]] = []
    fake = FakeSync()

    def build(*args: Any) -> FakeSync:
        built.append(args)
        return fake

    monkeypatch.setattr("api.app.TicketStateSync", build)
    settings = SETTINGS.model_copy(
        update={
            "itop_url": "http://localhost:8080",
            "itop_token": SecretStr("tok"),
            "itop_system_user": "Hermes System",
            "itop_webhook_token": SecretStr(TOKEN),
        }
    )
    app = TestClient(create_app(settings, token_verifier=FakeVerifier(), role_manager=object()))
    assert app.post("/api/itop/webhook", json=CALL, headers=bearer(TOKEN)).status_code == 202
    assert fake.calls == ["123"]
    assert built[0][1].endpoint == "http://localhost:8080/webservices/rest.php?version=1.3"
    assert built[0][2] == "Hermes System"


@pytest.mark.parametrize("body", [{}, {"class": "Server"}, {"junk": "x" * 100}])
def test_the_token_is_checked_before_the_body(body: dict[str, str]) -> None:
    """A caller without the token learns nothing about the payload: 401, never a validation 422 (pendientes #49)."""
    assert client(sync=FakeSync()).post("/api/itop/webhook", json=body).status_code == 401
    # disabled (no token configured): nothing to protect, the body is validated first and a valid one gets 503
    assert client(token=None).post("/api/itop/webhook", json=body).status_code == 422


@pytest.mark.parametrize("raw", [b"{not json", b"\xff\xfe", b""])
def test_malformed_json_without_the_token_is_still_401(raw: bytes) -> None:
    headers = {"content-type": "application/json"}
    assert client(sync=FakeSync()).post("/api/itop/webhook", content=raw, headers=headers).status_code == 401
    with_token = {**headers, "Authorization": f"Bearer {TOKEN}"}
    assert client(sync=FakeSync()).post("/api/itop/webhook", content=raw, headers=with_token).status_code == 422


@pytest.fixture
def webhook_client() -> TestClient:
    # Built during setup: create_app reinstalls the log handlers, which would drop caplog's in the test body.
    return client(sync=FakeSync())


def test_a_rejected_webhook_call_is_logged_without_the_header(
    webhook_client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    """ASVS V16.3.1 (F12.3): a failed attempt on the webhook is a WARNING like a rejected Firebase token."""
    with caplog.at_level(logging.WARNING, logger="api.itop_webhook"):
        response = webhook_client.post("/api/itop/webhook", json=CALL, headers=bearer("guess-1234"))
    assert response.status_code == 401
    assert "authentication rejected: webhook_bearer" in caplog.text
    assert "guess-1234" not in caplog.text
