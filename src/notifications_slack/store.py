"""What the Slack module remembers (its own `slack_*` tables, NOT-07): deliveries, ticket threads, the digest queue.

`SlackStore` is the seam: `SqlSlackStore` (PostgreSQL, the `slack_module` role) in the service and
`InMemorySlackStore` in tests. Both follow the same rules:

* Idempotency by `event_id` and audience (NOT-02): an event already delivered, or already waiting in a digest, is
  never posted or queued again.
* Once an event is queued the outbox has marked it delivered, so the queue owns NOT-02 for it: a transient failure
  adds an attempt and waits 1, 2, 4 ... minutes (at most 60); a permanent one, or `MAX_ATTEMPTS`, ends as `failed`.
* A digest is published item by item: each posted item is recorded and leaves the queue in one step, so a crash
  half-way never posts the same item twice; the digest root (`digest_ts`) is saved first so a retry continues it.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any, Final, Literal, Protocol

from notifications_slack.routing import Audience

Delivery = Literal["message", "reply", "digest"]
MAX_ATTEMPTS: Final = 10
MAX_BACKOFF_MINUTES: Final = 60


def backoff(attempts: int) -> timedelta:
    """1, 2, 4, 8 ... minutes after the 1st, 2nd, 3rd ... failed attempt; never more than an hour (NOT-02)."""
    return timedelta(minutes=min(2 ** max(attempts - 1, 0), MAX_BACKOFF_MINUTES))


@dataclass(frozen=True)
class DeliveryRecord:
    """One posted copy of an event: where it went, how and when."""

    event_id: str
    audience: Audience
    channel_id: str
    kind: Delivery
    message_ts: str
    at: datetime


@dataclass(frozen=True)
class ThreadRef:
    channel_id: str
    root_ts: str


@dataclass(frozen=True)
class QueuedItem:
    event_id: str
    channel_id: str
    payload: dict[str, Any]
    queued_at: datetime
    attempts: int
    digest_ts: str | None


class SlackStore(Protocol):
    def is_known(self, event_id: str, audience: Audience) -> bool:
        """Delivered already, or (standard audience) waiting in the digest queue."""
        ...

    def record_delivery(self, record: DeliveryRecord) -> None: ...

    def thread(self, thread_key: str, audience: Audience) -> ThreadRef | None: ...

    def save_thread(self, thread_key: str, audience: Audience, ref: ThreadRef, now: datetime) -> None: ...

    def enqueue(self, event_id: str, channel_id: str, payload: dict[str, Any], now: datetime, due: datetime) -> None:
        """Queue an event (standard audience) for the channel's digest; `due` is when the digest may go out."""
        ...

    def due_channels(self, now: datetime) -> list[str]:
        """Channels with at least one queued item whose time has come."""
        ...

    def due_items(self, channel_id: str, now: datetime) -> list[QueuedItem]:
        """What a due channel publishes now, oldest first: every queued item never tried (the whole window groups into
        one digest, SLK-07) plus the retries whose wait is over; never an item still backing off."""
        ...

    def set_digest_ts(self, event_ids: list[str], digest_ts: str, channel_id: str) -> None:
        """The summary of these items was posted (`digest_ts` in `channel_id`, maybe the fallback channel)."""
        ...

    def complete_item(self, record: DeliveryRecord) -> None:
        """The queued item was posted (standard copy): record its delivery and remove it from the queue, in one step."""
        ...

    def fail_item(self, event_id: str, code: str, now: datetime, *, permanent: bool) -> bool:
        """A failed attempt: retry later, or `failed` when permanent or out of attempts. True if it is now failed."""
        ...

    def purge(self, deliveries_before: datetime, threads_before: datetime) -> int: ...


# --- in-memory implementation (tests, and the reference behaviour of the SQL store) -----------------------------
@dataclass
class _Item:
    item: QueuedItem
    status: str = "queued"
    next_attempt_at: datetime | None = None
    last_error: str | None = None


@dataclass
class _Thread:
    ref: ThreadRef
    created_at: datetime
    updated_at: datetime


class InMemorySlackStore:
    """`SlackStore` in memory, thread-safe. Same rules as the SQL store."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.deliveries: dict[tuple[str, str], DeliveryRecord] = {}
        self.threads: dict[tuple[str, str], _Thread] = {}
        self.queue: dict[str, _Item] = {}

    def is_known(self, event_id: str, audience: Audience) -> bool:
        with self._lock:
            return (event_id, audience) in self.deliveries or (audience == "standard" and event_id in self.queue)

    def record_delivery(self, record: DeliveryRecord) -> None:
        with self._lock:
            self.deliveries.setdefault((record.event_id, record.audience), record)

    def thread(self, thread_key: str, audience: Audience) -> ThreadRef | None:
        with self._lock:
            found = self.threads.get((thread_key, audience))
            return found.ref if found else None

    def save_thread(self, thread_key: str, audience: Audience, ref: ThreadRef, now: datetime) -> None:
        with self._lock:
            found = self.threads.get((thread_key, audience))
            created = found.created_at if found else now
            self.threads[(thread_key, audience)] = _Thread(ref, created, max(now, created))

    def enqueue(self, event_id: str, channel_id: str, payload: dict[str, Any], now: datetime, due: datetime) -> None:
        with self._lock:
            if event_id in self.queue or (event_id, "standard") in self.deliveries:
                return
            self.queue[event_id] = _Item(QueuedItem(event_id, channel_id, payload, now, 0, None), next_attempt_at=due)

    def due_channels(self, now: datetime) -> list[str]:
        with self._lock:
            return sorted({i.item.channel_id for i in self._due(now)})

    def due_items(self, channel_id: str, now: datetime) -> list[QueuedItem]:
        with self._lock:
            items = [
                i.item
                for i in self.queue.values()
                if i.status == "queued"
                and i.item.channel_id == channel_id
                and (i.item.attempts == 0 or (i.next_attempt_at is not None and i.next_attempt_at <= now))
            ]
            return sorted(items, key=lambda i: (i.queued_at, i.event_id))

    def _due(self, now: datetime) -> list[_Item]:
        return [
            i for i in self.queue.values() if i.status == "queued" and i.next_attempt_at and i.next_attempt_at <= now
        ]

    def set_digest_ts(self, event_ids: list[str], digest_ts: str, channel_id: str) -> None:
        with self._lock:
            for event_id in event_ids:
                if event_id in self.queue:
                    entry = self.queue[event_id]
                    entry.item = replace(entry.item, digest_ts=digest_ts, channel_id=channel_id)

    def complete_item(self, record: DeliveryRecord) -> None:
        with self._lock:
            self.queue.pop(record.event_id, None)
            self.deliveries.setdefault((record.event_id, "standard"), record)

    def fail_item(self, event_id: str, code: str, now: datetime, *, permanent: bool) -> bool:
        with self._lock:
            entry = self.queue.get(event_id)
            if entry is None:
                return False
            attempts = entry.item.attempts + 1
            entry.item = replace(entry.item, attempts=attempts)
            entry.last_error = code[:200]
            if permanent or attempts >= MAX_ATTEMPTS:
                entry.status, entry.next_attempt_at = "failed", None
                return True
            entry.next_attempt_at = now + backoff(attempts)
            return False

    def purge(self, deliveries_before: datetime, threads_before: datetime) -> int:
        with self._lock:
            old = [k for k, record in self.deliveries.items() if record.at < deliveries_before]
            idle = [k for k, t in self.threads.items() if t.updated_at < threads_before]
            failed = [k for k, i in self.queue.items() if i.status == "failed" and i.item.queued_at < deliveries_before]
            for key in old:
                del self.deliveries[key]
            for thread_key in idle:
                del self.threads[thread_key]
            for event_id in failed:
                del self.queue[event_id]
            return len(old) + len(idle) + len(failed)

    def status_of(self, event_id: str) -> tuple[str, int, str | None] | None:
        """Test helper: (status, attempts, last_error) of a queued item."""
        with self._lock:
            entry = self.queue.get(event_id)
            return (entry.status, entry.item.attempts, entry.last_error) if entry else None
