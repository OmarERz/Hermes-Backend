"""Interfaces of the notification contract (NOT-04)."""

from __future__ import annotations

from typing import Protocol

from notifications_api.models import FeedbackInput, FeedbackResult, NotificationEvent


class NotificationConsumer(Protocol):
    def process(self, event: NotificationEvent) -> None:
        """Deliver the event. Raise an exception to have it retried. Must be idempotent by event_id."""
        ...


class FeedbackService(Protocol):
    def record(self, feedback: FeedbackInput) -> FeedbackResult:
        """Validate the user, store the feedback and apply its effects (NOT-06).

        Raise `FeedbackRejected` (with a stable `code`) when the feedback is not accepted; nothing is stored then.
        """
        ...
