"""API factory and worker entry point start with injected settings."""

from __future__ import annotations

import io
import json
import logging
import threading

from fastapi.testclient import TestClient
from pydantic import SecretStr

from api.app import create_app
from core.config import Settings
from workers.__main__ import run

SETTINGS = Settings(  # type: ignore[call-arg]
    _env_file=None,
    database_url=SecretStr("postgresql://app:pw@db/hermes"),
    firebase_project_id="demo-hermes",
    cursor_signing_key=SecretStr("k" * 40),
)


def test_health_is_public_and_ok() -> None:
    client = TestClient(create_app(SETTINGS))
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_docs_disabled_by_default() -> None:
    client = TestClient(create_app(SETTINGS))
    for path in ("/docs", "/redoc", "/openapi.json", "/api/docs", "/api/openapi.json"):
        assert client.get(path).status_code == 404


def test_docs_only_when_enabled() -> None:
    client = TestClient(create_app(SETTINGS.model_copy(update={"api_docs_enabled": True})))
    assert client.get("/api/docs").status_code == 200
    assert "/api/health" in client.get("/api/openapi.json").json()["paths"]


def test_the_api_links_to_the_itop_console_url() -> None:
    # F16.1: REST goes to the internal name on the shared network; the links shown to people go to the console.
    internal = SETTINGS.model_copy(update={"itop_url": "http://itop:8080/"})
    assert create_app(internal).state.itop_url == "http://itop:8080/"
    console = internal.model_copy(update={"itop_console_url": "http://127.0.0.1:8080/"})
    assert create_app(console).state.itop_url == "http://127.0.0.1:8080/"


def test_worker_starts_and_stops(monkeypatch: object) -> None:
    stop = threading.Event()
    stop.set()
    run(stop, SETTINGS)
    handler = logging.getLogger().handlers[0]
    assert isinstance(handler, logging.StreamHandler)


def test_worker_logs_are_json() -> None:
    stream = io.StringIO()
    stop = threading.Event()
    stop.set()
    run(stop, SETTINGS)
    logging.getLogger().handlers[0].setStream(stream)  # type: ignore[attr-defined]
    logging.getLogger("workers").info("after")
    assert json.loads(stream.getvalue().splitlines()[-1])["message"] == "after"
