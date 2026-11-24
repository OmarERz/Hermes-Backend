"""Channel digests (SLK-07): queued `normal` and `digest` events go out together once the window has passed.

* A batch of two or more events: a summary message with the first 10 by final score and a count of the rest, then
  each event's full message (with its feedback buttons) as a reply in the summary's thread. A batch of one: its own
  top-level message. Either way the message becomes the root of the ticket's thread (SLK-03).
* Item by item (see `store`): the summary's ts is saved on the batch first; each posted reply is recorded and leaves
  the queue at once. An interrupted digest continues under the same summary, never posting an item twice.
* A transient failure (rate limit, 5xx, network) retries the item later with the NOT-02 backoff and stops the
  channel for this round; a permanent one (`invalid_blocks`, `msg_too_long`, ...) fails that item and goes on.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from pydantic import ValidationError

from notifications_api import NotificationEvent
from notifications_slack import render
from notifications_slack.gateway import SlackError, SlackGateway
from notifications_slack.routing import NEW_ROOT_TYPES, PRIORITY_RANK, thread_key
from notifications_slack.store import DeliveryRecord, QueuedItem, SlackStore, ThreadRef

log = logging.getLogger("notifications_slack.digest")
RANK = PRIORITY_RANK["digest"]


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class DigestPublisher:
    store: SlackStore
    gateway: SlackGateway
    clock: Callable[[], datetime] = field(default=utcnow)

    def publish_due(self) -> int:
        """Publish every channel whose oldest queued item is due; returns how many events were posted."""
        now = self.clock()
        return sum(self._publish(channel, now) for channel in self.store.due_channels(now))

    def _publish(self, channel: str, now: datetime) -> int:
        batch: list[tuple[QueuedItem, NotificationEvent]] = []
        for item in self.store.due_items(channel, now):
            try:
                batch.append((item, NotificationEvent.model_validate(item.payload)))
            except ValidationError:
                self.store.fail_item(item.event_id, "invalid_payload", now, permanent=True)
                log.error("digest item %s failed: invalid_payload", item.event_id)  # noqa: TRY400 - no traceback (SEG-21)
        posted = 0
        # Items of an interrupted digest continue under its summary; the rest start a new one.
        for digest_ts in sorted({item.digest_ts for item, _ in batch if item.digest_ts}):
            rest = [(item, event) for item, event in batch if item.digest_ts == digest_ts]
            done, stop = self._replies(channel, digest_ts, rest, now)
            posted += done
            if stop:
                return posted
        fresh = [(item, event) for item, event in batch if item.digest_ts is None]
        if len(fresh) == 1:
            return posted + self._single(channel, *fresh[0], now)
        if fresh:
            posted += self._summary_and_replies(channel, fresh, now)
        return posted

    def _single(self, channel: str, item: QueuedItem, event: NotificationEvent, now: datetime) -> int:
        try:
            channel_id, ts = self.gateway.post(channel, render.message(event, "standard"), rank=RANK)
        except SlackError as error:
            self._failed(item, error, now)
            return 0
        self.store.complete_item(DeliveryRecord(item.event_id, "standard", channel_id, "message", ts, now))
        self._root(event, ThreadRef(channel_id, ts), now)
        return 1

    def _summary_and_replies(
        self, channel: str, fresh: list[tuple[QueuedItem, NotificationEvent]], now: datetime
    ) -> int:
        ranked = render.rank(event for _, event in fresh)
        try:
            _, root_ts = self.gateway.post(channel, render.digest(ranked), rank=RANK)
        except SlackError as error:
            for item, _ in fresh:
                self._failed(item, error, now)
            return 0
        self.store.set_digest_ts([item.event_id for item, _ in fresh], root_ts)
        order = {event.event_id: i for i, event in enumerate(ranked)}
        fresh = sorted(fresh, key=lambda pair: order[pair[1].event_id])
        done, _ = self._replies(channel, root_ts, fresh, now)
        return done

    def _replies(
        self, channel: str, root_ts: str, items: list[tuple[QueuedItem, NotificationEvent]], now: datetime
    ) -> tuple[int, bool]:
        """Each event's full message in the summary's thread. Returns (posted, stopped by a transient error)."""
        done = 0
        for item, event in items:
            try:
                channel_id, ts = self.gateway.post(
                    channel, render.message(event, "standard"), thread_ts=root_ts, rank=RANK
                )
            except SlackError as error:
                self._failed(item, error, now)
                if error.retryable:
                    return done, True
                continue
            self.store.complete_item(DeliveryRecord(item.event_id, "standard", channel_id, "digest", ts, now))
            self._root(event, ThreadRef(channel_id, root_ts), now)
            done += 1
        return done, False

    def _root(self, event: NotificationEvent, ref: ThreadRef, now: datetime) -> None:
        key = thread_key(event)
        if key is not None and (event.type in NEW_ROOT_TYPES or self.store.thread(key, "standard") is None):
            self.store.save_thread(key, "standard", ref, now)

    def _failed(self, item: QueuedItem, error: SlackError, now: datetime) -> None:
        if self.store.fail_item(item.event_id, error.code, now, permanent=not error.retryable):
            log.error("digest item %s failed: slack %s", item.event_id, error.code)
        else:
            log.warning("digest item %s: slack %s; retrying later", item.event_id, error.code)
