"""Notification contract shared with the Slack team: NotificationEvent, NotificationConsumer, FeedbackService.

This package imports nothing from the rest of the backend (D-043).
"""

from notifications_api.interfaces import FeedbackService, NotificationConsumer
from notifications_api.log_consumer import LogConsumer
from notifications_api.models import FeedbackInput, FeedbackResult, NotificationEvent

__all__ = [
    "FeedbackInput",
    "FeedbackResult",
    "FeedbackService",
    "LogConsumer",
    "NotificationConsumer",
    "NotificationEvent",
]
