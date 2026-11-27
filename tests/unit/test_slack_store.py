"""The in-memory `SlackStore` follows the same rules as the PostgreSQL one (tests/harness/slack_store_cases.py)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

import pytest

from harness.slack_store_cases import CASES
from notifications_slack.store import InMemorySlackStore, SlackStore, backoff

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.__name__)
def test_in_memory_store(case: Callable[[SlackStore], None]) -> None:
    case(InMemorySlackStore())


def test_backoff_follows_not_02() -> None:
    assert [backoff(n) for n in (1, 2, 3, 4)] == [timedelta(minutes=m) for m in (1, 2, 4, 8)]
    assert backoff(30) == timedelta(minutes=60)


def test_status_helper_reports_queue_state() -> None:
    store = InMemorySlackStore()
    assert store.status_of("nothing") is None
