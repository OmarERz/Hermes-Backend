"""FeedbackService pieces without a database."""

from __future__ import annotations

import re
from datetime import UTC
from pathlib import Path

import pytest

from api.routes.findings import FEEDBACK_ERRORS
from core.feedback import service
from core.feedback.service import FeedbackRejectedError, utcnow
from notifications_api import FEEDBACK_REJECTION_CODES, FeedbackRejected

pytestmark = pytest.mark.unit


def test_rejections_carry_a_stable_code_only() -> None:
    error = FeedbackRejectedError("unauthorized_user")
    assert (error.code, str(error)) == ("unauthorized_user", "unauthorized_user")


def test_core_rejections_are_the_contract_error() -> None:
    """The Slack module imports only notifications_api: it must catch what the SQL service raises (NOT-04)."""
    with pytest.raises(FeedbackRejected) as raised:
        raise FeedbackRejectedError("unknown_ticket")
    assert raised.value.code == "unknown_ticket"


def test_every_code_the_service_raises_is_in_the_contract() -> None:
    """Drift check: each code the SQL service raises (and the API maps) is one the Slack module knows."""
    source = Path(service.__file__).read_text(encoding="utf-8")
    raised = set(re.findall(r'FeedbackRejectedError\("([a-z_]+)"\)', source))
    assert raised == FEEDBACK_REJECTION_CODES
    assert set(FEEDBACK_ERRORS) == FEEDBACK_REJECTION_CODES


def test_utcnow_is_aware() -> None:
    assert utcnow().tzinfo is UTC
