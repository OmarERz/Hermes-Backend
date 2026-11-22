"""Dispatcher retry delays (NOT-02) and clock."""

from __future__ import annotations

from datetime import UTC, timedelta

import pytest

from core.notifications.dispatcher import backoff, utcnow

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(("attempts", "minutes"), [(1, 1), (2, 2), (3, 4), (4, 8), (7, 60), (10, 60)])
def test_backoff_grows_to_an_hour(attempts: int, minutes: int) -> None:
    assert backoff(attempts) == timedelta(minutes=minutes)


def test_utcnow_is_aware() -> None:
    assert utcnow().tzinfo is UTC
