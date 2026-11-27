"""Notification dispatcher (NOT-02): delivers the `notification_event` outbox to the `NotificationConsumer`.

* Events are taken by priority (`immediate` first), then by age, with `FOR UPDATE SKIP LOCKED`; a claim adds an
  attempt and leases the row (its `next_attempt_at` moves forward), so a crashed worker's event comes back when the
  lease expires and several dispatchers can run at once.
* An event of a ticket that iTop has not created yet waits (its create is still in the iTop outbox); then the iTop
  id and URL are filled in before delivery (`complete_ticket_link`).
* The payload is validated with the contract model `NotificationEvent` before delivery; a payload the contract
  rejects can never succeed and ends as `failed` at once.
* If `process` raises, the event is retried after 1, 2, 4 ... minutes (at most 60); after `max_attempts` (10) it
  ends as `failed`, where the frontend lists it. No event is ever discarded (D-023).
* Delivery is at least once: the consumer is idempotent by `event_id` (NOT-02). `payload` keeps the event exactly as
  it was delivered.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Event
from typing import Any, Final

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from core.notifications.events import complete_ticket_link
from notifications_api import LogConsumer, NotificationConsumer, NotificationEvent

log = logging.getLogger("core.notifications.dispatcher")

MAX_BACKOFF_MINUTES: Final = 60

# An event waits only while it still needs the iTop link (its payload has no iTop id, its ticket has none either and
# the ticket's create is still queued in the iTop outbox), and never longer than its grace period: an immediate event
# does not wait at all by default (`immediate_link_wait`, NOT-03), the others wait up to `link_wait`.
_CLAIM_SQL: Final = text(
    """
    SELECT e.id
      FROM notification_event e
      LEFT JOIN ticket t ON t.id = e.ticket_id
     WHERE e.status = 'pending'
       AND e.next_attempt_at <= :now
       AND (t.id IS NULL OR t.itop_ticket_id IS NOT NULL
            OR COALESCE(e.payload -> 'ticket' ->> 'itop_id', '') <> ''
            OR e.created_at <= CASE WHEN e.priority = 'immediate' THEN :immediate_since ELSE :link_since END
            OR NOT EXISTS (
             SELECT 1
               FROM itop_outbox o
               JOIN ticket_update u ON u.id = o.ticket_update_id
              WHERE u.ticket_id = t.id AND o.operation = 'create' AND o.status IN ('pending', 'in_progress')))
     ORDER BY CASE e.priority WHEN 'immediate' THEN 0 WHEN 'normal' THEN 1 ELSE 2 END, e.created_at, e.id
     LIMIT 1
       FOR UPDATE OF e SKIP LOCKED
    """
)


_CONSUMER_SETTING: Final = text("SELECT value FROM setting_current WHERE setting_key = 'notifications.consumer'")


# Consumers that run in a service of their own: `slack` is delivered by the Slack service (`python -m slack_app`, the
# composition root of `notifications_slack`, D-085), so the worker leaves those events to it.
EXTERNAL_CONSUMERS: Final = frozenset({"slack"})


def delivered_by(name: str) -> str:
    """Which process delivers the outbox for a `notifications.consumer` value: `worker` for `log`, otherwise the service
    of that name (`slack`). The worker and the Slack service both decide with this, so they never split the events."""
    return name if name in EXTERNAL_CONSUMERS else "worker"


# Immediate events never wait for the iTop link (`immediate_link_wait` is 0) and a claim moves `next_attempt_at`
# forward, so one still due long after its time means nothing is delivering (normal ones may wait for iTop).
_WAITING_IMMEDIATE: Final = text(
    "SELECT count(*) FROM notification_event"
    " WHERE status = 'pending' AND priority = 'immediate' AND next_attempt_at <= :since"
)


def waiting_immediate_events(session: Session, since: datetime) -> int:
    """Pending immediate events that were already due at `since` and nobody claimed (NOT-03)."""
    return int(session.scalar(_WAITING_IMMEDIATE, {"since": since}) or 0)


def consumer_for(name: str) -> NotificationConsumer:
    """NOT-05: `log` (default) writes each event to the log. `slack` is not built here: it lives in its own service."""
    if name == "log":
        return LogConsumer()
    if name in EXTERNAL_CONSUMERS:
        raise ValueError(f"notification consumer {name!r} runs in its own service")
    raise ValueError(f"unknown notification consumer {name!r}")


def configured_consumer_name(session: Session) -> str:
    """The `notifications.consumer` parameter (docs/11), `log` when it is not set."""
    value = session.scalar(_CONSUMER_SETTING)
    return str(value) if value else "log"


def utcnow() -> datetime:
    return datetime.now(UTC)


def backoff(attempts: int) -> timedelta:
    """1, 2, 4, 8 ... minutes after the 1st, 2nd, 3rd, 4th failed attempt; never more than an hour (NOT-02)."""
    return timedelta(minutes=min(2 ** max(attempts - 1, 0), MAX_BACKOFF_MINUTES))


@dataclass(frozen=True)
class _Claim:
    event_id: uuid.UUID
    attempts: int
    payload: Any
    itop_ticket_id: str | None


@dataclass
class NotificationDispatcher:
    """Delivers pending events to the configured consumer (`LogConsumer` by default, NOT-05)."""

    session_factory: sessionmaker[Session]
    consumer: NotificationConsumer
    itop_base_url: str | None = None
    clock: Callable[[], datetime] = utcnow
    max_attempts: int = 10
    lease: timedelta = timedelta(minutes=5)
    immediate_link_wait: timedelta = timedelta(0)
    link_wait: timedelta = timedelta(minutes=30)

    def drain(self, limit: int = 100, stop: Event | None = None) -> int:
        """Deliver due events until none is left, `limit` is reached or `stop` is set; returns how many were handled.

        `stop` is checked between events (pending F5.3 #65): a worker shutting down finishes the event in hand and
        leaves the rest pending, instead of being killed mid-delivery and redelivering it after the lease.
        """
        handled = 0
        while handled < limit and not (stop is not None and stop.is_set()) and self.run_once():
            handled += 1
        return handled

    def run_once(self) -> bool:
        claim = self._claim()
        if claim is None:
            return False
        if isinstance(claim, str):
            return True  # an abandoned event was closed without a new attempt
        payload = claim.payload
        if not isinstance(payload, dict):
            self._finish(claim, "failed", error="payload rejected by the contract: not an object")
            return True
        ticket = payload.get("ticket")
        if claim.itop_ticket_id and isinstance(ticket, dict) and not ticket.get("itop_id"):
            payload = complete_ticket_link(payload, claim.itop_ticket_id, self.itop_base_url)
        try:
            event = NotificationEvent.model_validate(payload)
        except ValidationError as exc:
            # Field paths only, never the values (SEG-21).
            fields = sorted({".".join(str(p) for p in err["loc"]) for err in exc.errors()})
            self._finish(claim, "failed", error="payload rejected by the contract: " + ", ".join(fields))
            return True
        try:
            self.consumer.process(event)
        except Exception as exc:  # noqa: BLE001 - the contract: any exception means "retry" (NOT-04)
            # Only the exception type: its text may carry remote answers or event content (SEG-21).
            log.warning(
                "consumer raised %s on event %s (attempt %d)", type(exc).__name__, claim.event_id, claim.attempts
            )
            status = "failed" if claim.attempts >= self.max_attempts else "pending"
            self._finish(claim, status, error=f"consumer raised {type(exc).__name__}")
        else:
            self._finish(claim, "delivered", payload=event.model_dump(mode="json"))
        return True

    # --- steps ----------------------------------------------------------------------------------------------
    def _claim(self) -> _Claim | str | None:
        now = self.clock()
        with self.session_factory() as session, session.begin():
            params = {"now": now, "immediate_since": now - self.immediate_link_wait, "link_since": now - self.link_wait}
            event_id = session.scalar(_CLAIM_SQL, params)
            if event_id is None:
                return None
            row = session.get_one(m.NotificationEvent, event_id)
            if row.attempts >= self.max_attempts:
                # The worker died during the last allowed attempt: never exceed the attempt budget.
                row.status, row.next_attempt_at = "failed", None
                row.last_error = "lease expired during the last attempt"
                return "abandoned"
            row.attempts += 1
            row.next_attempt_at = now + self.lease
            ticket = session.get(m.Ticket, row.ticket_id) if row.ticket_id is not None else None
            return _Claim(row.id, row.attempts, row.payload, ticket.itop_ticket_id if ticket else None)

    def _finish(
        self, claim: _Claim, status: str, *, error: str | None = None, payload: dict[str, Any] | None = None
    ) -> None:
        now = self.clock()
        with self.session_factory() as session, session.begin():
            row = session.get(m.NotificationEvent, claim.event_id, with_for_update=True)
            if row is None or row.status != "pending" or row.attempts != claim.attempts:
                log.warning("event %s was reclaimed while being delivered; outcome dropped", claim.event_id)
                return
            row.status = status
            row.last_error = error
            row.delivered_at = now if status == "delivered" else None
            row.next_attempt_at = now + backoff(claim.attempts) if status == "pending" else None
            if payload is not None:
                row.payload = payload
        log.info("event %s -> %s (attempt %d)", claim.event_id, status, claim.attempts)
