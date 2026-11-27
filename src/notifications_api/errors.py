"""Errors of the notification contract (NOT-04, NOT-06). This module imports nothing from the rest of the backend."""

from __future__ import annotations

from typing import Final, Literal, get_args

FeedbackRejectionCode = Literal["unauthorized_user", "unknown_assessment", "unknown_ticket"]

# The stable codes `FeedbackService.record` can reject with (the consumer maps each one to its own message).
FEEDBACK_REJECTION_CODES: Final[frozenset[str]] = frozenset(get_args(FeedbackRejectionCode))


class FeedbackRejected(Exception):  # noqa: N818 - contract name: the service "rejects" the feedback
    """`FeedbackService.record` did not accept the feedback.

    `code` is stable (`FeedbackRejectionCode`): `unauthorized_user` (the e-mail is not an active analyst or admin,
    D-030), `unknown_assessment` (no such assessment) or `unknown_ticket` (the ticket is not one the assessment
    rated). The message is the code only: it never echoes the input (SEG-21). Nothing was stored.
    """

    def __init__(self, code: FeedbackRejectionCode) -> None:
        super().__init__(code)
        self.code: FeedbackRejectionCode = code
