"""Notification dispatcher against PostgreSQL 18 (NOT-02): priority, retries, waiting for iTop, never losing events."""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import pytest
from f05data import T0, make_ticket
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from core.itop.outbox import ItopWrite, create_payload, record_write
from core.notifications.dispatcher import NotificationDispatcher, configured_consumer_name, consumer_for
from core.notifications.events import EventRecorder, TicketEvent
from core.tickets.content import CiLine, TicketContext
from notifications_api import LogConsumer, NotificationEvent
from workers.jobs import DispatchJob

pytestmark = pytest.mark.integration
ITOP = "https://itop.example.test"
CONTEXT = TicketContext(
    cve="CVE-2026-3000",
    product="nginx",
    custodian="Ops",
    custodian_itop_id="10",
    cis=[CiLine("100", "web-01", 92, "high", True, "public", False, "Ana", "20", "ana@example.test")],
    score=92,
    driving_ci="web-01",
    base=85,
    judge_adjustment=7,
)


@dataclass
class Clock:
    now: datetime = T0

    def __call__(self) -> datetime:
        return self.now


@dataclass
class Consumer:
    """Records what it receives; fails the first `failures` calls."""

    failures: int = 0
    received: list[NotificationEvent] = field(default_factory=list)

    def process(self, event: NotificationEvent) -> None:
        if self.failures > 0:
            self.failures -= 1
            raise RuntimeError("slack is down")
        self.received.append(event)


def record(
    factory: sessionmaker[Session], *, itop_id: str | None = "500", priority: str = "normal", **ticket: Any
) -> tuple[uuid.UUID, uuid.UUID]:
    with factory() as session, session.begin():
        row = make_ticket(session, itop_id=itop_id, **ticket)
        event = TicketEvent("new_ticket", priority, 1, None, None)
        stored = EventRecorder(ITOP).record(session, row, CONTEXT, event, T0)
        return stored.id, row.id


def stored(factory: sessionmaker[Session], event_id: uuid.UUID) -> m.NotificationEvent:
    with factory() as session:
        return session.get_one(m.NotificationEvent, event_id)


def dispatcher(factory: sessionmaker[Session], consumer: Consumer, clock: Clock, **kw: Any) -> NotificationDispatcher:
    return NotificationDispatcher(factory, consumer, itop_base_url=ITOP, clock=clock, **kw)


def test_an_event_is_validated_delivered_and_kept_as_delivered(factory: sessionmaker[Session]) -> None:
    consumer, clock = Consumer(), Clock()
    event_id, _ = record(factory)

    assert dispatcher(factory, consumer, clock).drain() == 1

    (delivered,) = consumer.received
    assert delivered.event_id == str(event_id)
    assert delivered.ticket is not None
    assert delivered.ticket.itop_id == "500"
    row = stored(factory, event_id)
    assert (row.status, row.attempts, row.delivered_at, row.last_error, row.next_attempt_at) == (
        "delivered",
        1,
        T0,
        None,
        None,
    )
    assert row.payload == delivered.model_dump(mode="json")


def test_immediate_events_go_first(factory: sessionmaker[Session]) -> None:
    consumer, clock = Consumer(), Clock()
    digest, _ = record(factory, priority="digest", itop_id="501")
    immediate, _ = record(factory, priority="immediate", itop_id="502")
    normal, _ = record(factory, priority="normal", itop_id="503")

    dispatcher(factory, consumer, clock).drain()

    assert [e.event_id for e in consumer.received] == [str(immediate), str(normal), str(digest)]


def test_an_event_waits_for_itop_to_create_its_ticket(factory: sessionmaker[Session]) -> None:
    consumer, clock = Consumer(), Clock()
    event_id, ticket_id = record(factory, itop_id=None)
    with factory() as session, session.begin():
        record_write(session, ItopWrite(ticket_id, "create", create_payload({"title": "t"}), "c-1"), T0)
    run = dispatcher(factory, consumer, clock)

    assert run.drain() == 0
    with factory() as session, session.begin():  # what the outbox does when iTop answers
        ticket = session.get_one(m.Ticket, ticket_id)
        ticket.itop_ticket_id, ticket.itop_ref, ticket.status = "777", "R-000777", "open"
        outbox = session.query(m.ItopOutbox).one()
        outbox.status, outbox.done_at = "done", T0

    assert run.drain() == 1
    ticket_info = consumer.received[0].ticket
    assert ticket_info is not None
    assert (ticket_info.itop_id, ticket_info.url) == (
        "777",
        f"{ITOP}/pages/UI.php?operation=details&class=UserRequest&id=777",
    )
    assert stored(factory, event_id).payload["ticket"]["itop_id"] == "777"


def test_an_event_whose_ticket_will_never_be_created_is_still_delivered(factory: sessionmaker[Session]) -> None:
    consumer, clock = Consumer(), Clock()
    record(factory, itop_id=None)  # no create queued (it failed for good): the event is not held forever

    assert dispatcher(factory, consumer, clock).drain() == 1
    assert consumer.received[0].ticket is not None
    assert consumer.received[0].ticket.itop_id == ""


def test_a_failing_consumer_is_retried_with_backoff_and_a_restart_loses_nothing(factory: sessionmaker[Session]) -> None:
    consumer, clock = Consumer(failures=2), Clock()
    event_id, _ = record(factory)

    dispatcher(factory, consumer, clock).drain()
    row = stored(factory, event_id)
    assert (row.status, row.attempts, row.next_attempt_at, row.last_error) == (
        "pending",
        1,
        T0 + timedelta(minutes=1),
        "consumer raised RuntimeError",
    )
    clock.now += timedelta(minutes=1)
    dispatcher(factory, consumer, clock).drain()
    assert stored(factory, event_id).next_attempt_at == clock.now + timedelta(minutes=2)

    clock.now += timedelta(minutes=2)
    restarted = dispatcher(factory, consumer, clock)  # a new process after a restart
    assert restarted.drain() == 1
    assert stored(factory, event_id).status == "delivered"
    assert len(consumer.received) == 1


def test_after_the_last_attempt_the_event_is_failed_not_dropped(factory: sessionmaker[Session]) -> None:
    consumer, clock = Consumer(failures=5), Clock()
    event_id, _ = record(factory)
    run = dispatcher(factory, consumer, clock, max_attempts=2)

    run.drain()
    clock.now += timedelta(minutes=1)
    run.drain()

    row = stored(factory, event_id)
    assert (row.status, row.attempts, row.next_attempt_at) == ("failed", 2, None)


def test_a_dispatcher_dying_on_the_last_attempt_never_exceeds_the_budget(factory: sessionmaker[Session]) -> None:
    consumer, clock = Consumer(), Clock()
    event_id, _ = record(factory)
    run = dispatcher(factory, consumer, clock, max_attempts=1)
    claim = run._claim()  # claimed, then the process dies
    assert claim is not None

    clock.now += timedelta(minutes=6)
    assert run.run_once() is True

    row = stored(factory, event_id)
    assert (row.status, row.last_error) == ("failed", "lease expired during the last attempt")
    assert consumer.received == []
    assert not isinstance(claim, str)
    run._finish(claim, "delivered")  # the dead process's late outcome is dropped
    assert stored(factory, event_id).status == "failed"


def test_a_payload_the_contract_rejects_fails_at_once(factory: sessionmaker[Session]) -> None:
    consumer, clock = Consumer(), Clock()
    event_id, _ = record(factory)
    with factory() as session, session.begin():
        row = session.get_one(m.NotificationEvent, event_id)
        row.payload = {**row.payload, "priority": "urgent", "extra": 1}

    dispatcher(factory, consumer, clock).drain()

    row = stored(factory, event_id)
    assert row.status == "failed"
    assert row.last_error == "payload rejected by the contract: extra, priority"
    assert consumer.received == []


@pytest.mark.parametrize(("payload", "error"), [([1, 2], "not an object"), (None, "not an object")])
def test_a_payload_that_is_not_an_object_fails(factory: sessionmaker[Session], payload: Any, error: str) -> None:
    consumer, clock = Consumer(), Clock()
    event_id, _ = record(factory)
    with factory() as session, session.begin():
        session.get_one(m.NotificationEvent, event_id).payload = payload if payload is not None else "x"

    dispatcher(factory, consumer, clock).drain()

    assert stored(factory, event_id).last_error == f"payload rejected by the contract: {error}"


def test_a_null_ticket_with_an_itop_id_fails_cleanly(factory: sessionmaker[Session]) -> None:
    consumer, clock = Consumer(), Clock()
    event_id, _ = record(factory)
    with factory() as session, session.begin():
        row = session.get_one(m.NotificationEvent, event_id)
        row.payload = {**row.payload, "ticket": None, "score": "bad"}

    dispatcher(factory, consumer, clock).drain()

    assert stored(factory, event_id).last_error == "payload rejected by the contract: score"


def test_an_event_that_already_has_its_link_does_not_wait_for_a_re_creation(factory: sessionmaker[Session]) -> None:
    consumer, clock = Consumer(), Clock()
    event_id, ticket_id = record(factory)  # recorded while the ticket was 500
    with factory() as session, session.begin():  # the ticket was closed and is being re-created
        ticket = session.get_one(m.Ticket, ticket_id)
        ticket.itop_ticket_id, ticket.itop_ref, ticket.status = None, None, "pending_creation"
        record_write(session, ItopWrite(ticket_id, "create", create_payload({"title": "t"}), "c-2"), T0)

    assert dispatcher(factory, consumer, clock).drain() == 1
    assert consumer.received[0].ticket is not None
    assert consumer.received[0].ticket.itop_id == "500"
    assert stored(factory, event_id).status == "delivered"


def test_the_consumer_comes_from_the_setting(factory: sessionmaker[Session]) -> None:
    with factory() as session:
        assert configured_consumer_name(session) == "log"  # no catalog seeded: the default
    assert isinstance(consumer_for("log"), LogConsumer)
    with pytest.raises(ValueError, match="not available"):
        consumer_for("slack")


def test_the_worker_job_delivers_with_the_log_consumer(factory: sessionmaker[Session]) -> None:
    event_id, _ = record(factory)

    assert DispatchJob(factory, ITOP)() == 1

    assert stored(factory, event_id).status == "delivered"


def test_an_immediate_event_does_not_wait_for_itop(factory: sessionmaker[Session]) -> None:
    consumer, clock = Consumer(), Clock()
    event_id, ticket_id = record(factory, itop_id=None, priority="immediate")
    with factory() as session, session.begin():
        record_write(session, ItopWrite(ticket_id, "create", create_payload({"title": "t"}), "c-3"), T0)
    run = dispatcher(factory, consumer, clock)

    assert run.drain() == 1  # it never waits for the link (NOT-03)
    assert consumer.received[0].ticket is not None
    assert consumer.received[0].ticket.itop_id == ""
    assert stored(factory, event_id).status == "delivered"


def test_a_late_outcome_respects_a_later_claim(factory: sessionmaker[Session]) -> None:
    consumer, clock = Consumer(failures=1), Clock()
    event_id, _ = record(factory)
    first = dispatcher(factory, consumer, clock)
    old_claim = first._claim()  # claimed, then the process hangs
    assert old_claim is not None
    assert not isinstance(old_claim, str)

    clock.now += timedelta(minutes=6)
    second = dispatcher(factory, consumer, clock)
    assert second.run_once() is True  # the lease expired: attempt 2 fails and schedules a retry
    retry_at = stored(factory, event_id).next_attempt_at

    first._finish(old_claim, "delivered")  # the hung process wakes up late

    row = stored(factory, event_id)
    assert (row.status, row.attempts, row.next_attempt_at) == ("pending", 2, retry_at)


def test_with_the_default_budget_the_tenth_failure_is_final(factory: sessionmaker[Session]) -> None:
    consumer, clock = Consumer(failures=100), Clock()
    event_id, _ = record(factory)
    run = dispatcher(factory, consumer, clock)
    for attempt in range(1, 10):
        run.drain()
        row = stored(factory, event_id)
        assert (row.status, row.attempts) == ("pending", attempt)
        assert row.next_attempt_at is not None
        clock.now = row.next_attempt_at

    run.drain()

    row = stored(factory, event_id)
    assert (row.status, row.attempts, row.next_attempt_at) == ("failed", 10, None)


def test_a_shutdown_stops_the_drain_between_events(factory: sessionmaker[Session]) -> None:
    """The event in hand is finished; the rest stay pending for the next worker (pending F5.3 #65)."""
    stop = threading.Event()

    @dataclass
    class StoppingConsumer(Consumer):
        def process(self, event: NotificationEvent) -> None:
            super().process(event)
            stop.set()  # the shutdown signal arrives while the first event is being delivered

    consumer, clock = StoppingConsumer(), Clock()
    first, _ = record(factory, priority="immediate", itop_id="511")
    second, _ = record(factory, priority="normal", itop_id="512")

    assert dispatcher(factory, consumer, clock).drain(stop=stop) == 1
    assert [e.event_id for e in consumer.received] == [str(first)]
    assert (stored(factory, first).status, stored(factory, second).status) == ("delivered", "pending")
