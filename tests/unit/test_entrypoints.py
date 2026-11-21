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
    _env_file=None, database_url=SecretStr("postgresql://app:pw@db/hermes"), firebase_project_id="demo-hermes"
)


def test_health_is_public_and_ok() -> None:
    client = TestClient(create_app(SETTINGS))
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_openapi_lists_health() -> None:
    schema = TestClient(create_app(SETTINGS)).get("/openapi.json").json()
    assert "/api/health" in schema["paths"]


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
