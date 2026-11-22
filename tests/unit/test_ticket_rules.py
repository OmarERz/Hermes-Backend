"""Pure ticket rules: bands (TIC-03), hysteresis (D-006), human changes (D-007/TIC-07), impact (P-012), P-004."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from core.tickets.rules import (
    CiFacts,
    Hysteresis,
    PriorityThresholds,
    UrgencyAction,
    UrgencyBands,
    impact,
    level,
    priority,
    target_urgency,
    urgency_action,
)

pytestmark = pytest.mark.unit
BANDS = UrgencyBands({1: 90, 2: 75, 3: 50, 4: 0})
RULE = Hysteresis(margin=5, evaluations=2, days=7)
NOW = datetime(2026, 11, 22, 12, tzinfo=UTC)


def days_ago(days: float) -> datetime:
    return NOW - timedelta(days=days)


@pytest.mark.parametrize(("score", "urgency"), [(100, 1), (90, 1), (89, 2), (75, 2), (74, 3), (50, 3), (49, 4), (0, 4)])
def test_bands_map_scores_to_urgency(score: int, urgency: int) -> None:
    assert BANDS.urgency(score) == urgency


def test_bands_without_a_zero_floor_fall_back_to_the_least_urgent() -> None:
    assert UrgencyBands({1: 90, 2: 75}).urgency(10) == 2
    with pytest.raises(ValueError, match="no urgency bands"):
        UrgencyBands({})


def test_levels() -> None:
    assert [level(u) for u in (1, 2, 3, 4)] == ["critical", "high", "medium", "low"]


def test_a_new_ticket_takes_the_band_of_its_score() -> None:
    assert target_urgency(None, [(NOW, 30)], BANDS, RULE, NOW) == 4


def test_urgency_rises_at_once() -> None:
    assert target_urgency(3, [(days_ago(1), 60), (NOW, 91)], BANDS, RULE, NOW) == 1


def test_urgency_does_not_fall_on_a_single_evaluation() -> None:
    assert target_urgency(2, [(days_ago(1), 80), (NOW, 60)], BANDS, RULE, NOW) == 2


def test_urgency_does_not_fall_within_the_margin() -> None:
    history = [(days_ago(2), 72), (days_ago(1), 71), (NOW, 73)]  # below 75 but not 5 points below
    assert target_urgency(2, history, BANDS, RULE, NOW) == 2


def test_urgency_falls_after_two_evaluations_below_the_margin() -> None:
    history = [(days_ago(2), 80), (days_ago(1), 69), (NOW, 60)]
    assert target_urgency(2, history, BANDS, RULE, NOW) == 3


def test_urgency_falls_after_seven_days_below_the_margin() -> None:
    assert target_urgency(2, [(days_ago(8), 60)], BANDS, RULE, NOW) == 3
    assert target_urgency(2, [(days_ago(6), 60)], BANDS, RULE, NOW) == 2


def test_the_streak_restarts_after_a_score_back_above_the_margin() -> None:
    history = [(days_ago(3), 60), (days_ago(2), 72), (NOW, 60)]
    assert target_urgency(2, history, BANDS, RULE, NOW) == 2


def test_falling_lands_on_the_band_every_streak_score_reaches() -> None:
    history = [(days_ago(1), 60), (NOW, 20)]
    assert target_urgency(1, history, BANDS, RULE, NOW) == 3


def test_an_empty_history_is_an_error() -> None:
    with pytest.raises(ValueError, match="history"):
        target_urgency(2, [], BANDS, RULE, NOW)


@pytest.mark.parametrize(
    ("current", "target", "switches", "expected"),
    [
        (None, 2, (False, True, True), UrgencyAction.KEEP),
        (2, 2, (False, True, True), UrgencyAction.KEEP),
        (3, 1, (False, True, True), UrgencyAction.RAISE),
        (1, 3, (False, True, True), UrgencyAction.LOWER),
        (3, 1, (True, True, True), UrgencyAction.SUGGEST),
        (3, 1, (True, False, True), UrgencyAction.AUDIT_ONLY),
        (3, 1, (True, True, False), UrgencyAction.AUDIT_ONLY),
        (1, 3, (True, True, True), UrgencyAction.SUGGEST),
    ],
)
def test_a_human_change_blocks_urgency_changes(
    current: int | None, target: int, switches: tuple[bool, bool, bool], expected: UrgencyAction
) -> None:
    human, ticket_on, global_on = switches
    action = urgency_action(
        current, target, human_changed=human, ticket_suggestions=ticket_on, global_suggestions=global_on
    )
    assert action is expected


def test_impact_rule() -> None:
    assert impact([CiFacts("medium", True)]) == "service"
    assert impact([CiFacts("high", False), CiFacts("high", None)]) == "service"
    assert impact([CiFacts("high", True)]) == "department"
    assert impact([CiFacts("low", False)] * 10) == "department"


@pytest.mark.parametrize(
    ("score", "expected"),
    [(None, "digest"), (30, "digest"), (49, "digest"), (50, "normal"), (89, "normal"), (90, "immediate")],
)
def test_event_priority(score: int | None, expected: str) -> None:
    assert priority(score, PriorityThresholds()) == expected
