"""`SlackConsumer`: the `NotificationConsumer` of the Slack module (NOT-04, NOT-07). It imports only the contract.

For each route of the event (standard copy and, for highly classified assets, the restricted copy):

1. Already delivered or queued (`event_id` + audience) → nothing (NOT-02: delivery is at least once).
2. `partially_fixed` / `fixed` with a known thread → a reply in that thread.
3. Digestible (not immediate, not restricted) → queued for the channel's digest (`DigestPublisher`).
4. Otherwise → its own top-level message, at once; for a ticket it becomes the thread's root (a `level_up` or
   `reopened` moves the root, SLK-03).

A failed post raises, so the outbox retries the event (NOT-02); copies already posted are not posted again. A standard
copy whose channel is gone (`channel_not_found`, `not_in_channel`, `is_archived`) falls back to the default channel;
a restricted copy never does (NOT-08).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from notifications_api import NotificationEvent
from notifications_slack import render
from notifications_slack.gateway import CHANNEL_ERRORS, SlackError, SlackGateway
from notifications_slack.routing import FOLLOW_UP_TYPES, PRIORITY_RANK, Route, Router
from notifications_slack.store import DeliveryRecord, SlackStore, ThreadRef

log = logging.getLogger("notifications_slack.consumer")


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class SlackConsumer:
    store: SlackStore
    gateway: SlackGateway
    router: Router
    digest_window: timedelta = timedelta(seconds=120)
    clock: Callable[[], datetime] = field(default=utcnow)

    def process(self, event: NotificationEvent) -> None:
        for route in self.router.routes(event):
            if self.store.is_known(event.event_id, route.audience):
                continue
            self._deliver(event, route)

    def _deliver(self, event: NotificationEvent, route: Route) -> None:
        now = self.clock()
        rank = PRIORITY_RANK[event.priority]
        thread = self.store.thread(route.thread_key, route.audience) if route.thread_key else None
        if event.type in FOLLOW_UP_TYPES and thread is not None:
            _, ts = self.gateway.post(
                thread.channel_id, render.follow_up(event, route.audience), thread_ts=thread.root_ts, rank=rank
            )
            self.store.record_delivery(
                DeliveryRecord(event.event_id, route.audience, thread.channel_id, "reply", ts, now)
            )
            assert route.thread_key is not None  # noqa: S101 - a thread was found by this key
            self.store.save_thread(route.thread_key, route.audience, thread, now)
            return
        if route.digestible:
            self.store.enqueue(
                event.event_id, route.channel, event.model_dump(mode="json"), now, due=now + self.digest_window
            )
            return
        channel_id, ts = self._post_top_level(event, route, rank)
        self.store.record_delivery(DeliveryRecord(event.event_id, route.audience, channel_id, "message", ts, now))
        if route.thread_key is not None:
            self.store.save_thread(route.thread_key, route.audience, ThreadRef(channel_id, ts), now)
        log.info("event %s posted (%s, %s)", event.event_id, route.audience, event.priority)

    def _post_top_level(self, event: NotificationEvent, route: Route, rank: int) -> tuple[str, str]:
        msg = render.message(event, route.audience)
        try:
            return self.gateway.post(route.channel, msg, rank=rank)
        except SlackError as error:
            fallback = self.router.default_channel
            if error.code not in CHANNEL_ERRORS or route.audience != "standard" or route.channel == fallback:
                log.warning("event %s not posted: slack %s (%s copy)", event.event_id, error.code, route.audience)
                raise
            log.warning("event %s: slack %s in its channel; posting to the default channel", event.event_id, error.code)
            return self.gateway.post(fallback, msg, rank=rank)
