"""Ticket events are stored in notification_event inside the caller's transaction (NOT-02)."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
from f05data import T0, make_ticket
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from core.notifications.events import CONTRACT_VERSION, EventRecorder, TicketEvent
from core.tickets.content import CiLine, TicketContext

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]
SCHEMA = json.loads((ROOT / "schemas" / "notification_event.schema.json").read_text(encoding="utf-8"))
CONTEXT = TicketContext(
    cve="CVE-2026-2000",
    product="nginx",
    custodian="Ops",
    custodian_itop_id="10",
    cis=[CiLine("100", "web-01", 77, "high", True, "public", False, "Ana", "20", "ana@example.test")],
    score=77,
    driving_ci="web-01",
    base=77,
)


def count_events(factory: sessionmaker[Session]) -> int:
    with factory() as session:
        return session.scalar(select(func.count()).select_from(m.NotificationEvent)) or 0


def test_record_inserts_a_pending_event_with_the_ticket_link(factory: sessionmaker[Session]) -> None:
    recorder = EventRecorder("https://itop.example.test")
    with factory() as session, session.begin():
        ticket = make_ticket(session, itop_id="321")
        row = recorder.record(session, ticket, CONTEXT, TicketEvent("level_up", "normal", 2, 60, None), T0)
        event_id, ticket_id = row.id, ticket.id

    with factory() as session:
        stored = session.get_one(m.NotificationEvent, event_id)
        assert (stored.contract_version, stored.event_type, stored.priority, stored.ticket_id) == (
            CONTRACT_VERSION,
            "level_up",
            "normal",
            ticket_id,
        )
        assert (stored.status, stored.attempts, stored.next_attempt_at, stored.created_at) == ("pending", 0, T0, T0)
        assert (stored.delivered_at, stored.last_error, stored.alert_id, stored.assessment_id) == (
            None,
            None,
            None,
            None,
        )
        assert stored.payload["event_id"] == str(event_id)
        assert stored.payload["ticket"]["itop_id"] == "321"
        assert stored.payload["ticket"]["url"] == (
            "https://itop.example.test/pages/UI.php?operation=details&class=UserRequest&id=321"
        )
        jsonschema.validate(stored.payload, SCHEMA)


def test_a_ticket_not_yet_in_itop_leaves_the_link_for_the_dispatcher(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        ticket = make_ticket(session)
        row = EventRecorder(None).record(
            session, ticket, CONTEXT, TicketEvent("new_ticket", "normal", 2, None, None), T0
        )
        assert (row.payload["ticket"]["itop_id"], row.payload["ticket"]["url"]) == ("", "")


def test_a_rolled_back_change_leaves_no_event(factory: sessionmaker[Session]) -> None:
    with factory() as session:
        session.begin()
        ticket = make_ticket(session, itop_id="322")
        EventRecorder(None).record(session, ticket, CONTEXT, TicketEvent("reopened", "digest", 4, None, None), T0)
        session.rollback()

    assert count_events(factory) == 0
