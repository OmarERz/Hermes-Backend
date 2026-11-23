"""Admin routes over the real notification outbox: list events in error and retry them (NOT-02)."""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from f05data import T0, make_ticket
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy.orm import Session, sessionmaker

from api.app import create_app
from api.auth import CurrentUser, Role, get_current_user
from core.config import Settings
from core.db import models as m

pytestmark = pytest.mark.integration
SETTINGS = Settings(
    _env_file=None,
    database_url=SecretStr("postgresql://a:b@db/h"),
    firebase_project_id="p",
    cursor_signing_key=SecretStr("k" * 40),
)


def event(session: Session, status: str, *, minutes: int = 0) -> uuid.UUID:
    ticket = make_ticket(session)
    row = m.NotificationEvent(
        contract_version="1.0",
        event_type="new_ticket",
        priority="immediate",
        ticket_id=ticket.id,
        payload={},
        status=status,
        attempts=10 if status == "failed" else 1,
        last_error="consumer raised RuntimeError" if status == "failed" else None,
        delivered_at=T0 if status == "delivered" else None,
        created_at=T0 + timedelta(minutes=minutes),
    )
    session.add(row)
    session.flush()
    return row.id


def client(factory: sessionmaker[Session]) -> TestClient:
    app = create_app(SETTINGS)
    app.state.session_factory = factory
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid="u", email="admin@example.test", display_name=None, role=Role.ADMIN
    )
    return TestClient(app)


def test_failed_events_are_listed_and_can_be_retried(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        older, newer = event(session, "failed"), event(session, "failed", minutes=5)
        delivered = event(session, "delivered")

    with client(factory) as api:
        listed = api.get("/api/notifications/events").json()["items"]
        assert [e["id"] for e in listed] == [str(newer), str(older)]
        assert listed[0] == {
            "id": str(newer),
            "type": "new_ticket",
            "priority": "immediate",
            "status": "error",
            "attempts": 10,
            "last_error": "consumer raised RuntimeError",
            "created_at": "2026-11-22T12:05:00Z",
        }
        retried = api.post(f"/api/notifications/events/{older}/retry")
        assert (retried.status_code, retried.json()["status"], retried.json()["attempts"]) == (202, "pending", 0)
        assert api.post(f"/api/notifications/events/{delivered}/retry").status_code == 409
        assert api.post("/api/notifications/events/not-a-uuid/retry").status_code == 422  # F12.3: UUID path ids
        assert api.post(f"/api/notifications/events/{uuid.uuid4()}/retry").status_code == 404
        assert [
            e["id"] for e in api.get("/api/notifications/events", params={"status": "pending"}).json()["items"]
        ] == [str(older)]

    with factory() as session:
        row = session.get_one(m.NotificationEvent, older)
        assert (row.status, row.attempts, row.last_error) == ("pending", 0, None)
        assert row.next_attempt_at is not None
