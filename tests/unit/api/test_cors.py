"""CORS: off by default (same origin), exact origins only when configured, never a wildcard."""

from __future__ import annotations

import pytest
from authfakes import SETTINGS, FakeVerifier
from fastapi.testclient import TestClient
from pydantic import ValidationError

from api.app import create_app
from api.auth import InMemoryUserDirectory
from core.config import Settings

FRONT = "https://hermes-front.example.com"


def client_with(origins: str) -> TestClient:
    settings = SETTINGS.model_copy(update={"cors_allowed_origins": origins})
    return TestClient(create_app(settings, token_verifier=FakeVerifier(), user_directory=InMemoryUserDirectory()))


def test_no_cors_headers_by_default() -> None:
    response = client_with("").get("/api/health", headers={"Origin": FRONT})
    assert "access-control-allow-origin" not in response.headers


def test_configured_origin_gets_cors_and_preflight() -> None:
    client = client_with(f"{FRONT}, http://localhost:5173/")
    assert client.get("/api/health", headers={"Origin": FRONT}).headers["access-control-allow-origin"] == FRONT
    preflight = client.options(
        "/api/me",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-credentials" not in preflight.headers


def test_other_origins_are_not_allowed() -> None:
    response = client_with(FRONT).get("/api/health", headers={"Origin": "https://evil.example.com"})
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.parametrize("bad", ["*", "hermes-front.example.com", "https://front.example.com/app", "ftp://x.y"])
def test_wildcards_and_non_origins_are_refused(bad: str) -> None:
    with pytest.raises(ValidationError, match="CORS_ALLOWED_ORIGINS"):
        Settings(**{**SETTINGS.model_dump(), "cors_allowed_origins": bad})


def test_unhandled_errors_keep_cors_and_the_envelope() -> None:
    settings = SETTINGS.model_copy(update={"cors_allowed_origins": FRONT})
    app = create_app(settings, token_verifier=FakeVerifier(), user_directory=InMemoryUserDirectory())

    @app.get("/api/_t/boom")
    def boom() -> None:
        raise RuntimeError("database down")

    response = TestClient(app, raise_server_exceptions=False).get("/api/_t/boom", headers={"Origin": FRONT})
    assert response.status_code == 500
    assert response.headers["access-control-allow-origin"] == FRONT
    assert response.json()["error"]["code"] == "internal_error"
    assert "database down" not in response.text
