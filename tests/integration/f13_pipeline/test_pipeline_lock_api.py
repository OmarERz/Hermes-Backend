"""A pipeline cycle never blocks the API: configuration writes complete while a cycle holds the pipeline lock.

Regression: the pipeline lock used the configuration write lock key (7_001_010), so every `PUT /api/config` waited
for the whole cycle and the API ran out of connections.
"""

from __future__ import annotations

import threading
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pipeline_support import NOW
from pydantic import SecretStr
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from api.app import create_app
from api.auth import CurrentUser, Role, get_current_user
from core.config import Settings
from core.db import models as m
from core.pipeline.locks import cycle_lock

pytestmark = pytest.mark.integration
UID = "uid-lock-admin"
SETTINGS = Settings(
    _env_file=None,
    database_url=SecretStr("postgresql://a:b@db/h"),
    firebase_project_id="p",
    cursor_signing_key=SecretStr("k" * 40),
)


def admin_client(factory: sessionmaker[Session]) -> TestClient:
    with factory() as session, session.begin():
        if session.scalar(select(m.AppUser.id).where(m.AppUser.firebase_uid == UID)) is None:
            session.add(
                m.AppUser(firebase_uid=UID, email="lock-admin@example.test", role="admin", active=True, created_at=NOW)
            )
    app = create_app(SETTINGS)
    # A lock wait fails after 5 s instead of hanging, so a regression fails the test rather than stalling it.
    engine = create_engine(factory.kw["bind"].url, connect_args={"options": "-c lock_timeout=5000"})
    app.state.session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid=UID, email="lock-admin@example.test", display_name=None, role=Role.ADMIN
    )
    return TestClient(app)


def test_a_configuration_write_completes_while_a_cycle_holds_the_lock(factory: sessionmaker[Session]) -> None:
    with admin_client(factory) as client:
        current = client.get("/api/config").json()
        dead_zone = "5" if current["values"]["dead_zone"] != "5" else "6"
        answers: list[Any] = []
        with cycle_lock(factory) as acquired:
            assert acquired
            worker = threading.Thread(
                target=lambda: answers.append(
                    client.put(
                        "/api/config",
                        json={"expected_version": current["version"], "changes": {"dead_zone": dead_zone}},
                    )
                ),
                daemon=True,
            )
            worker.start()
            worker.join(timeout=10)
        assert not worker.is_alive(), "PUT /api/config waited for the pipeline lock"
        assert answers[0].status_code == 200, "PUT /api/config waited for the pipeline lock: " + answers[0].text
        assert answers[0].json()["values"]["dead_zone"] == dead_zone


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("PUT", "/api/config", {"changes": {"dead_zone": "5"}, "expected_version": 9223372036854775808}),
        ("POST", "/api/config/versions/9223372036854775808/restore", {"expected_version": 1}),
        ("POST", "/api/config/versions/1/restore", {"expected_version": 2147483648}),
    ],
)
def test_out_of_range_versions_are_a_validation_error(
    factory: sessionmaker[Session], method: str, path: str, body: dict[str, Any]
) -> None:
    with admin_client(factory) as client:
        response = client.request(method, path, json=body)
    assert (response.status_code, response.json()["error"]["code"]) == (422, "validation_error")
