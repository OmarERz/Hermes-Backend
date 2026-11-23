"""FeedbackService pieces without a database."""

from __future__ import annotations

from datetime import UTC

import pytest

from core.feedback.service import FeedbackRejectedError, utcnow

pytestmark = pytest.mark.unit


def test_rejections_carry_a_stable_code_only() -> None:
    error = FeedbackRejectedError("unauthorized_user")
    assert (error.code, str(error)) == ("unauthorized_user", "unauthorized_user")


def test_utcnow_is_aware() -> None:
    assert utcnow().tzinfo is UTC
