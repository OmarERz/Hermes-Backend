"""Role hierarchy, current-user dependency and /api/me with an injected fake verifier (no network)."""

from __future__ import annotations

import logging
from typing import Annotated, Any

import pytest
from authfakes import SETTINGS, FakeVerifier, bearer
from fastapi import Depends
from fastapi.testclient import TestClient

from api.app import create_app
from api.auth import (
    AuthUnavailableError,
    CurrentUser,
    InMemoryUserDirectory,
    Role,
    require_role,
)
from api.auth.roles import parse_role


@pytest.fixture
def verifier() -> FakeVerifier:
    fake = FakeVerifier()
    for role in Role:
        fake.add(role.value, role)
    return fake


@pytest.fixture
def directory() -> InMemoryUserDirectory:
    return InMemoryUserDirectory()


@pytest.fixture
def client(verifier: FakeVerifier, directory: InMemoryUserDirectory) -> TestClient:
    app = create_app(SETTINGS, token_verifier=verifier, user_directory=directory)

    @app.get("/api/_t/analyst")
    def analyst_only(user: Annotated[CurrentUser, Depends(require_role(Role.ANALYST))]) -> dict[str, str]:
        return {"uid": user.uid}

    @app.get("/api/_t/admin")
    def admin_only(user: Annotated[CurrentUser, Depends(require_role(Role.ADMIN))]) -> dict[str, str]:
        return {"uid": user.uid}

    return TestClient(app)


def test_role_hierarchy() -> None:
    assert Role.ADMIN.at_least(Role.ANALYST)
    assert Role.ANALYST.at_least(Role.READER)
    assert Role.READER.at_least(Role.READER)
    assert not Role.READER.at_least(Role.ANALYST)
    assert not Role.ANALYST.at_least(Role.ADMIN)


@pytest.mark.parametrize(
    ("value", "expected"), [("admin", Role.ADMIN), ("root", None), ("ADMIN", None), (1, None), (None, None)]
)
def test_parse_role_fails_closed(value: Any, expected: Role | None) -> None:
    assert parse_role(value) == expected


def test_me_without_token_is_401_in_error_envelope(client: TestClient) -> None:
    response = client.get("/api/me")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    error = response.json()["error"]
    assert error["code"] == "unauthorized"
    assert error["details"] == []


@pytest.mark.parametrize("header", ["Basic abc", "Bearer ", "Bearer", "abc"])
def test_malformed_authorization_header_is_401(client: TestClient, header: str) -> None:
    assert client.get("/api/me", headers={"Authorization": header}).status_code == 401


def test_invalid_token_is_401(client: TestClient) -> None:
    response = client.get("/api/me", headers=bearer("nope"))
    assert response.status_code == 401
    assert "nope" not in response.text


def test_verifier_unavailable_is_503(client: TestClient, verifier: FakeVerifier) -> None:
    verifier.identities["down"] = AuthUnavailableError()
    response = client.get("/api/me", headers=bearer("down"))
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "auth_unavailable"


@pytest.mark.parametrize("role", list(Role))
def test_me_returns_current_user_for_every_role(client: TestClient, role: Role) -> None:
    response = client.get("/api/me", headers=bearer(role.value))
    assert response.status_code == 200
    assert response.json() == {
        "uid": f"uid-{role.value}",
        "email": f"uid-{role.value}@example.com",
        "display_name": "Ana",
        "role": role.value,
    }


def test_insufficient_role_is_403(client: TestClient) -> None:
    response = client.get("/api/_t/analyst", headers=bearer("reader"))
    assert response.status_code == 403
    error = response.json()["error"]
    assert error["code"] == "forbidden"
    assert error["details"] == [{"field": "role", "issue": "requires_analyst"}]
    assert client.get("/api/_t/admin", headers=bearer("analyst")).status_code == 403


def test_sufficient_or_higher_role_is_200(client: TestClient) -> None:
    assert client.get("/api/_t/analyst", headers=bearer("analyst")).status_code == 200
    assert client.get("/api/_t/analyst", headers=bearer("admin")).status_code == 200
    assert client.get("/api/_t/admin", headers=bearer("admin")).status_code == 200


def test_privileged_route_without_token_is_401_not_403(client: TestClient) -> None:
    assert client.get("/api/_t/admin").status_code == 401


def test_login_syncs_user_directory(
    client: TestClient, directory: InMemoryUserDirectory, verifier: FakeVerifier
) -> None:
    assert directory.get("uid-reader") is None
    client.get("/api/me", headers=bearer("reader"))
    first = directory.get("uid-reader")
    assert first is not None
    assert first.role is Role.READER
    assert first.email == "uid-reader@example.com"
    assert first.last_login_at is not None
    # A claim raised outside the backend (D-030: only the backend assigns roles) is capped by the copy.
    verifier.add("reader", Role.ANALYST)
    assert client.get("/api/me", headers=bearer("reader")).json()["role"] == "reader"
    again = directory.get("uid-reader")
    assert again is not None
    assert again.id == first.id
    assert again.role is Role.READER
    assert again.last_login_at is not None
    assert again.last_login_at >= first.last_login_at


def test_openapi_declares_me_errors() -> None:
    app = create_app(SETTINGS, token_verifier=FakeVerifier(), user_directory=InMemoryUserDirectory())
    responses = app.openapi()["paths"]["/api/me"]["get"]["responses"]
    assert {"200", "401", "403", "503"} <= set(responses)


def test_inactive_user_is_403(client: TestClient, directory: InMemoryUserDirectory) -> None:
    client.get("/api/me", headers=bearer("admin"))
    directory.deactivate("uid-admin")
    response = client.get("/api/me", headers=bearer("admin"))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "user_inactive"


def test_rejection_is_logged_without_the_token(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO):
        client.get("/api/me", headers=bearer("secret-token-value"))
    assert "token_invalid" in caplog.text
    assert "secret-token-value" not in caplog.text
