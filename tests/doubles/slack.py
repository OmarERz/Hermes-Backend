"""Simulated Slack consumer: stores the messages the real module would send, sends nothing anywhere.

It follows the `NotificationConsumer` protocol of docs/08 NOT-04 structurally: a `process(event)` method that
raises to ask for a retry and is idempotent by `event_id` (delivery is at least once, NOT-02).

TODO(F0.5): when `notifications_api` defines NotificationEvent and NotificationConsumer, type `process` with
NotificationEvent and assert in a test that this class satisfies the Protocol. Until then events are duck typed:
a mapping or an object with `event_id`, `type` and `priority` attributes
(the field names of notification_event.schema.json).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


class SlackDeliveryError(RuntimeError):
    """Raised on purpose to simulate a Slack outage, so the outbox retries the event."""


def _read(event: Any, name: str) -> Any:
    if isinstance(event, Mapping):
        return event.get(name)
    return getattr(event, name, None)


@dataclass(frozen=True)
class SentMessage:
    event_id: str
    event_type: str | None
    priority: str | None
    event: Any


@dataclass
class SimulatedSlack:
    sent: list[SentMessage] = field(default_factory=list)
    attempts: int = 0
    duplicates: int = 0
    _failures_left: int = 0

    def fail_next(self, times: int = 1) -> None:
        """Make the next `times` calls to `process` raise SlackDeliveryError."""
        self._failures_left = times

    def process(self, event: Any) -> None:
        self.attempts += 1
        if self._failures_left > 0:
            self._failures_left -= 1
            raise SlackDeliveryError("simulated Slack outage")
        event_id = _read(event, "event_id")
        if event_id is None:
            raise ValueError("the event has no event_id")
        if any(message.event_id == str(event_id) for message in self.sent):
            self.duplicates += 1  # idempotent by event_id: a redelivery sends nothing new
            return
        self.sent.append(SentMessage(str(event_id), _read(event, "type"), _read(event, "priority"), event))

    def of_type(self, event_type: str) -> list[SentMessage]:
        return [m for m in self.sent if m.event_type == event_type]
