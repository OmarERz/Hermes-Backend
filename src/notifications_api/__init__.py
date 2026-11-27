"""Notification contract of the Slack module: events, consumer, FeedbackService and its FeedbackRejected error.

This package imports nothing from the rest of the backend (D-043).
"""

from notifications_api.errors import FEEDBACK_REJECTION_CODES, FeedbackRejected, FeedbackRejectionCode
from notifications_api.interfaces import FeedbackService, NotificationConsumer
from notifications_api.log_consumer import LogConsumer
from notifications_api.models import FeedbackInput, FeedbackResult, NotificationEvent

__all__ = [
    "FEEDBACK_REJECTION_CODES",
    "FeedbackInput",
    "FeedbackRejected",
    "FeedbackRejectionCode",
    "FeedbackResult",
    "FeedbackService",
    "LogConsumer",
    "NotificationConsumer",
    "NotificationEvent",
]
