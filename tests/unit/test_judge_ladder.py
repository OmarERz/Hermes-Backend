"""Judge degradation ladder rules (L14, docs/07 §8, TODO(P-006))."""

from __future__ import annotations

from datetime import date, timedelta
from decimal import Decimal

import pytest

from core.metrics.ladder import LadderEffects, Level, effects, next_level, signals_of

pytestmark = pytest.mark.unit
TODAY = date(2026, 11, 22)
VALIDATION = "validation_failure_rate"
DISAGREEMENT = "double_review_disagreement"


def ago(days: int) -> date:
    return TODAY - timedelta(days=days)


def day(days_ago: int, *signals: str) -> tuple[date, frozenset[str]]:
    return ago(days_ago), frozenset(signals)


def test_signals_use_strict_thresholds() -> None:
    values = {VALIDATION: Decimal("0.10"), DISAGREEMENT: Decimal("0.31"), "wrong_priority_judged": Decimal("0.3")}
    assert signals_of(values) == {DISAGREEMENT, "wrong_priority_judged"}
    assert signals_of({}) == frozenset()


def test_effects_per_level() -> None:
    assert effects(Level.NORMAL) == LadderEffects(None, apply_adjustments=True, judge_enabled=True)
    assert effects(Level.WATCHED) == LadderEffects(10, apply_adjustments=True, judge_enabled=True)
    assert effects(Level.CAUTIOUS) == LadderEffects(None, apply_adjustments=False, judge_enabled=True)
    assert effects(Level.OFF) == LadderEffects(None, apply_adjustments=False, judge_enabled=False)


def test_one_signal_watches_the_judge() -> None:
    transition = next_level(Level.NORMAL, [day(0, VALIDATION)], TODAY, None, False)
    assert transition is not None
    assert (transition.level, transition.reason) == (Level.WATCHED, f"Señal leve: {VALIDATION}")


def test_two_signals_at_once_make_it_cautious() -> None:
    transition = next_level(Level.NORMAL, [day(0, VALIDATION, DISAGREEMENT)], TODAY, None, False)
    assert transition is not None
    assert transition.level == Level.CAUTIOUS


def test_a_signal_sustained_three_days_makes_it_cautious() -> None:
    days = [day(2, VALIDATION), day(1, VALIDATION), day(0, VALIDATION)]
    transition = next_level(Level.WATCHED, days, TODAY, ago(2), False)
    assert transition is not None
    assert transition.reason == f"Señal sostenida 3 días: {VALIDATION}"
    broken = [day(2, VALIDATION), day(0, VALIDATION)]
    assert next_level(Level.WATCHED, broken, TODAY, ago(2), False) is None


def test_a_failed_regression_turns_the_judge_off() -> None:
    transition = next_level(Level.CAUTIOUS, [], TODAY, ago(1), True)
    assert transition is not None
    assert transition.level == Level.OFF
    assert next_level(Level.OFF, [], TODAY, ago(1), True) is None


def test_watched_returns_to_normal_after_seven_quiet_days() -> None:
    assert next_level(Level.WATCHED, [day(8, VALIDATION)], TODAY, ago(8), False) == next_level(
        Level.WATCHED, [], TODAY, ago(7), False
    )
    transition = next_level(Level.WATCHED, [], TODAY, ago(7), False)
    assert transition is not None
    assert transition.level == Level.NORMAL
    assert next_level(Level.WATCHED, [], TODAY, ago(6), False) is None  # not 7 days at this level yet
    assert next_level(Level.WATCHED, [day(3, VALIDATION)], TODAY, ago(10), False) is None


def test_high_levels_never_leave_alone() -> None:
    assert next_level(Level.CAUTIOUS, [], TODAY, ago(30), False) is None
    assert next_level(Level.OFF, [], TODAY, ago(30), False) is None
    assert next_level(Level.CAUTIOUS, [day(0, VALIDATION, DISAGREEMENT)], TODAY, ago(1), False) is None
