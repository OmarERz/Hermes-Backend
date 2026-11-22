"""Pure ticket rules: urgency bands (TIC-03), hysteresis (D-006), human changes (D-007, TIC-06/TIC-07), impact
(P-012) and event priority (P-004). No I/O: the lifecycle loads the inputs and applies the decisions.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final

LEVELS: Final[dict[int, str]] = {1: "critical", 2: "high", 3: "medium", 4: "low"}
DEPARTMENT_MIN_CIS: Final = 10  # TODO(P-012): confirm the impact rule (critical exposed CI or >= 10 CIs)


@dataclass(frozen=True)
class UrgencyBands:
    """`urgency -> min_score` of the formula version (`formula_urgency_band`), e.g. {1: 90, 2: 75, 3: 50, 4: 0}."""

    minimums: Mapping[int, int]

    def __post_init__(self) -> None:
        if not self.minimums:
            raise ValueError("the formula has no urgency bands")

    def urgency(self, score: int) -> int:
        """The most urgent band whose minimum the score reaches; the least urgent band otherwise."""
        for urgency in sorted(self.minimums):
            if score >= self.minimums[urgency]:
                return urgency
        return max(self.minimums)

    def floor(self, urgency: int) -> int:
        """Lowest score that still belongs to `urgency` (the band's limit)."""
        return self.minimums[urgency]


def level(urgency: int) -> str:
    return LEVELS[urgency]


@dataclass(frozen=True)
class Hysteresis:
    """D-006: down only when the score stays `margin` points under the band's limit for `evaluations` evaluations
    in a row or for `days` days. Values come from the formula version (`hysteresis_*`)."""

    margin: int = 5
    evaluations: int = 2
    days: int = 7


def target_urgency(
    current: int | None,
    history: Sequence[tuple[datetime, int]],
    bands: UrgencyBands,
    rule: Hysteresis,
    now: datetime,
) -> int:
    """Urgency the ticket should have after the latest evaluation (`history` is oldest first, newest last).

    It rises (or appears) at once; it falls only after the hysteresis, and then to the band that every score of the
    qualifying streak reaches.
    """
    if not history:
        raise ValueError("a ticket score history needs at least the latest evaluation")
    latest = bands.urgency(history[-1][1])
    if current is None or latest <= current:
        return latest
    limit = bands.floor(current) - rule.margin
    streak: list[tuple[datetime, int]] = []
    for at, score in reversed(history):
        if score > limit:
            break
        streak.append((at, score))
    if not streak:
        return current
    started = streak[-1][0]
    if len(streak) >= rule.evaluations or now - started >= timedelta(days=rule.days):
        return max(bands.urgency(max(score for _, score in streak)), current)
    return current


class UrgencyAction(StrEnum):
    KEEP = "keep"
    RAISE = "raise"
    LOWER = "lower"
    SUGGEST = "suggest"  # human change: comment the suggestion instead (TIC-06)
    AUDIT_ONLY = "audit_only"  # human change and suggestions off: only recorded (TIC-07)


def urgency_action(
    current: int | None,
    target: int,
    *,
    human_changed: bool,
    ticket_suggestions: bool,
    global_suggestions: bool,
) -> UrgencyAction:
    """What to do with the urgency in iTop. A person's last change always wins (D-007)."""
    if current is None or target == current:
        return UrgencyAction.KEEP
    if human_changed:
        return UrgencyAction.SUGGEST if ticket_suggestions and global_suggestions else UrgencyAction.AUDIT_ONLY
    return UrgencyAction.RAISE if target < current else UrgencyAction.LOWER


@dataclass(frozen=True)
class CiFacts:
    criticality: str
    exposed: bool | None


def impact(cis: Sequence[CiFacts]) -> str:
    """`department` if the ticket touches a critical exposed CI or many CIs, `service` otherwise (TIC-03)."""
    # TODO(P-012): default rule until the user confirms it.
    if len(cis) >= DEPARTMENT_MIN_CIS or any(ci.criticality == "high" and ci.exposed is True for ci in cis):
        return "department"
    return "service"


@dataclass(frozen=True)
class PriorityThresholds:
    """P-004 (`event_priority.immediate` / `event_priority.normal`)."""

    immediate: int = 90
    normal: int = 50


def priority(score: int | None, thresholds: PriorityThresholds) -> str:
    """`immediate` (>= 90), `normal` (>= 50) or `digest`; an event without a score is a digest."""
    # TODO(P-004): default thresholds until the user confirms them.
    if score is None:
        return "digest"
    if score >= thresholds.immediate:
        return "immediate"
    if score >= thresholds.normal:
        return "normal"
    return "digest"
