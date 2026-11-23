"""Ticket state read back from iTop (ARQ-02) and the human-change rule's detection (D-007)."""

from __future__ import annotations

import logging
import uuid
from datetime import timedelta
from typing import Any

import pytest
from f05data import T0, make_ticket
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from core.itop.client import ItopReader
from core.itop.outbox import ItopWrite, record_write, update_payload
from core.tickets.sync import TicketStateSync
from doubles.itop import ItopDouble

pytestmark = pytest.mark.integration
SYSTEM = "Hermes System"


def syncer(factory: sessionmaker[Session], double: ItopDouble, system_user: str | None = SYSTEM) -> TicketStateSync:
    reader = ItopReader("http://localhost", str(double.token), http=double.client(), sleep=lambda _: None)
    return TicketStateSync(factory, reader, system_user, clock=lambda: T0 + timedelta(hours=1))


def setup(factory: sessionmaker[Session], double: ItopDouble, **remote: Any) -> uuid.UUID:
    fields = {"title": "t", "status": "assigned", "urgency": "3", "impact": "2", "ref": "R-000500", **remote}
    double.add("UserRequest", 500, **fields)
    with factory() as session, session.begin():
        return make_ticket(session, itop_id="500", urgency=3).id


def reload(factory: sessionmaker[Session], ticket_id: uuid.UUID) -> m.Ticket:
    with factory() as session:
        return session.get_one(m.Ticket, ticket_id)


def history(double: ItopDouble, change_id: int, date: str, author: str, value: str = "1") -> None:
    double.add(
        "CMDBChangeOpSetAttributeScalar",
        change_id,
        objclass="UserRequest",
        objkey="500",
        attcode="urgency",
        date=date,
        userinfo=author,
        newvalue=value,
    )


def test_an_unchanged_ticket_stays_as_it_is(factory: sessionmaker[Session]) -> None:
    double = ItopDouble()
    ticket_id = setup(factory, double)

    assert syncer(factory, double).sync_open_tickets() == 1

    ticket = reload(factory, ticket_id)
    assert (ticket.status, ticket.current_urgency, ticket.current_impact, ticket.last_human_change_at) == (
        "open",
        3,
        "service",
        None,
    )


def test_resolved_and_closed_states_are_mirrored_with_their_dates(factory: sessionmaker[Session]) -> None:
    double = ItopDouble()
    ticket_id = setup(factory, double, status="resolved")
    run = syncer(factory, double)

    run.sync_open_tickets()
    ticket = reload(factory, ticket_id)
    assert (ticket.status, ticket.resolved_at, ticket.closed_at) == ("resolved", T0 + timedelta(hours=1), None)

    double.data["UserRequest"]["500"]["status"] = "closed"
    run.sync_open_tickets()
    ticket = reload(factory, ticket_id)
    assert (ticket.status, ticket.closed_at) == ("closed", T0 + timedelta(hours=1))

    assert run.sync_open_tickets() == 0  # closed tickets are no longer polled


def test_a_human_urgency_change_is_detected_from_the_history(factory: sessionmaker[Session]) -> None:
    double = ItopDouble()
    ticket_id = setup(factory, double, urgency="1")
    history(double, 1, "2026-11-22 10:00:00", SYSTEM, "3")
    history(double, 2, "2026-11-22 12:30:00", "Ana Rivera", "1")

    syncer(factory, double).sync_open_tickets()

    ticket = reload(factory, ticket_id)
    assert ticket.current_urgency == 1
    assert (ticket.last_human_change_at, ticket.last_human_change_by) == (T0 + timedelta(minutes=30), "Ana Rivera")


def test_a_change_by_the_system_user_is_not_human(factory: sessionmaker[Session]) -> None:
    double = ItopDouble()
    ticket_id = setup(factory, double, urgency="2")
    history(double, 1, "2026-11-22 12:30:00", "hermes system", "2")

    syncer(factory, double).sync_open_tickets()

    ticket = reload(factory, ticket_id)
    assert (ticket.current_urgency, ticket.last_human_change_at) == (2, None)


def test_without_history_the_shadow_urgency_decides(factory: sessionmaker[Session]) -> None:
    double = ItopDouble()
    ticket_id = setup(factory, double, urgency="2")

    syncer(factory, double, system_user=None).sync_open_tickets()

    ticket = reload(factory, ticket_id)
    assert (ticket.current_urgency, ticket.last_human_change_at, ticket.last_human_change_by) == (
        2,
        T0 + timedelta(hours=1),
        None,
    )


def test_an_unreadable_history_falls_back_to_the_shadow(factory: sessionmaker[Session]) -> None:
    double = ItopDouble()
    ticket_id = setup(factory, double, urgency="2")
    original = double.handle

    def refuse_history(op: dict[str, Any]) -> dict[str, Any]:
        if op.get("class") == "CMDBChangeOpSetAttributeScalar":
            return {"code": 1, "message": "Error: not allowed"}
        return original(op)

    double.handle = refuse_history
    syncer(factory, double).sync_open_tickets()

    assert reload(factory, ticket_id).last_human_change_at == T0 + timedelta(hours=1)


def test_a_queued_urgency_write_is_not_mistaken_for_a_human_change(factory: sessionmaker[Session]) -> None:
    double = ItopDouble()
    ticket_id = setup(factory, double, urgency="1")
    with factory() as session, session.begin():
        write = ItopWrite(ticket_id, "raise_urgency", update_payload({"urgency": "1"}), "u-1")
        record_write(session, write, T0)

    syncer(factory, double).sync_open_tickets()

    ticket = reload(factory, ticket_id)
    assert (ticket.current_urgency, ticket.last_human_change_at) == (3, None)


def test_the_webhook_path_reads_only_our_tickets(factory: sessionmaker[Session]) -> None:
    double = ItopDouble()
    ticket_id = setup(factory, double, status="resolved")
    run = syncer(factory, double)

    assert run.sync_itop_ticket("999") is False
    assert run.sync_itop_ticket("500") is True
    assert reload(factory, ticket_id).status == "resolved"


def test_itop_down_stops_the_pass_and_refusals_skip_one_ticket(
    factory: sessionmaker[Session], caplog: pytest.LogCaptureFixture
) -> None:
    double = ItopDouble()
    setup(factory, double)
    with factory() as session, session.begin():
        make_ticket(session, itop_id="501", urgency=3)  # not in the double: iTop answers no object
    caplog.set_level(logging.WARNING, "core.tickets.sync")

    assert syncer(factory, double).sync_open_tickets() == 2
    assert "no longer in iTop" in caplog.text

    double.down = True
    assert syncer(factory, double).sync_open_tickets() == 0
    assert "sync stopped after 0 of 2" in caplog.text


def test_an_itop_refusal_on_one_ticket_does_not_stop_the_pass(factory: sessionmaker[Session]) -> None:
    double = ItopDouble()
    setup(factory, double)
    double.handle = lambda _op: {"code": 100, "message": "Error: refused"}  # every call is refused

    assert syncer(factory, double).sync_open_tickets() == 1


def test_an_urgency_write_that_lands_while_itop_is_read_is_not_human(factory: sessionmaker[Session]) -> None:
    """iTop answered with the old urgency, but our write finished meanwhile (pending F5.1 #44)."""
    double = ItopDouble()
    ticket_id = setup(factory, double, urgency="1")
    with factory() as session, session.begin():
        write = ItopWrite(ticket_id, "raise_urgency", update_payload({"urgency": "1"}), "u-2")
        row = record_write(session, write, T0)
        assert row is not None
        row.status, row.done_at = "done", T0 + timedelta(hours=1)  # the sync's clock: it started reading then

    syncer(factory, double).sync_open_tickets()

    ticket = reload(factory, ticket_id)
    assert (ticket.current_urgency, ticket.last_human_change_at) == (3, None)


def test_demo_tickets_are_never_read_from_itop(factory: sessionmaker[Session]) -> None:
    double = ItopDouble()
    with factory() as session, session.begin():
        make_ticket(session, itop_id="900", urgency=3).itop_ticket_id = "DEMO-1"
    run = syncer(factory, double)
    assert run.sync_open_tickets() == 0
    assert run.sync_itop_ticket("DEMO-1") is False
    assert double.operations == []
