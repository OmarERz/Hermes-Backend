"""Budget rules (docs/09 §4) with Decimal arithmetic."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest

from core.validation.budget import (
    COMPLEX,
    FALLBACKS,
    NORMAL,
    BudgetConfig,
    WorkItem,
    can_start,
    classify,
    limit_usd,
    next_turn,
    prioritize,
    token_cap,
    warning,
)

CONFIG = BudgetConfig()
D = Decimal


def test_limits_reserve_part_of_the_day_for_critical_work() -> None:
    assert limit_usd(CONFIG, critical=False) == D("4.00")
    assert limit_usd(CONFIG, critical=True) == D(5)


def test_normal_work_stops_at_the_reserve_and_critical_work_goes_on() -> None:
    assert can_start(CONFIG, D("3.90"), D("0.10"), critical=False)
    assert not can_start(CONFIG, D("3.90"), D("0.11"), critical=False)
    assert can_start(CONFIG, D("3.90"), D("1.10"), critical=True)
    assert not can_start(CONFIG, D("4.95"), D("0.06"), critical=True)


def test_warning_from_eighty_percent() -> None:
    assert not warning(CONFIG, D("3.99"))
    assert warning(CONFIG, D("4.00"))


def test_between_turns_the_review_closes_as_partial_when_the_next_turn_does_not_fit() -> None:
    assert next_turn(CONFIG, D("1"), D("0.5"), critical=False) == "continue"
    assert next_turn(CONFIG, D("3.8"), D("0.5"), critical=False) == "partial_review"
    assert next_turn(CONFIG, D("3.8"), D("0.5"), critical=True) == "continue"


@pytest.mark.parametrize(
    ("news", "chars", "assets", "probability", "expected"),
    [
        (1, 1_000, 2, D("0.1"), NORMAL),
        (6, 1_000, 2, D("0.1"), COMPLEX),
        (1, 20_001, 2, D("0.1"), COMPLEX),
        (1, 1_000, 11, D("0.1"), COMPLEX),
        (1, 1_000, 2, D("0.5"), COMPLEX),
        (5, 20_000, 10, D("0.49"), NORMAL),
    ],
)
def test_complexity(news: int, chars: int, assets: int, probability: Decimal, expected: str) -> None:
    assert classify(CONFIG, news, chars, assets, probability) == expected


def test_token_caps_double_for_critical_packages() -> None:
    assert token_cap(CONFIG, "judge", NORMAL, critical=False) == 6_000
    assert token_cap(CONFIG, "judge", NORMAL, critical=True) == 12_000
    assert token_cap(CONFIG, "judge", COMPLEX, critical=False) > token_cap(CONFIG, "judge", NORMAL, critical=False)


def test_fallbacks_per_piece() -> None:
    assert FALLBACKS == {"news_analyst": "unanalyzed", "cve_analyst": "unrated", "judge": "no_judge_review"}


def test_critical_first_then_oldest() -> None:
    t = [datetime(2026, 11, 22, h, tzinfo=UTC) for h in (8, 9, 10)]
    items = [WorkItem("late-normal", False, t[2]), WorkItem("old-normal", False, t[0]), WorkItem("crit", True, t[1])]
    assert [i.key for i in prioritize(items)] == ["crit", "old-normal", "late-normal"]
