"""Which consumer the dispatcher builds for each `notifications.consumer` value (NOT-05, D-085)."""

from __future__ import annotations

import pytest

from core.notifications.dispatcher import EXTERNAL_CONSUMERS, consumer_for
from notifications_api import LogConsumer

pytestmark = pytest.mark.unit


def test_log_is_built_here() -> None:
    assert isinstance(consumer_for("log"), LogConsumer)


def test_slack_runs_in_its_own_service() -> None:
    assert "slack" in EXTERNAL_CONSUMERS
    with pytest.raises(ValueError, match="its own service"):
        consumer_for("slack")


def test_an_unknown_consumer_is_refused() -> None:
    with pytest.raises(ValueError, match="unknown notification consumer"):
        consumer_for("pager")
