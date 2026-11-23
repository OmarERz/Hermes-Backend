"""Judge degradation ladder (L14, docs/07 §8, `TODO(P-006)`: proposed ladder, not confirmed by the user).

Signals of failure come from the nightly metrics of each day (`daily_metric`):
* judge answers that do not pass validation > 10 % (`validation_failure_rate`);
* disagreement in double reviews > 30 % (`double_review_disagreement`);
* "wrong priority" feedback on assessments the judge adjusted > 25 % (`wrong_priority_judged`);
* a failed regression set or an adversarial case that passes (reported by the caller: the regression set E12 is
  not part of the minimal F8).

Levels: 0 normal · 1 watched (one signal; double-review threshold 15 -> 10, admin warning; back to 0 alone after
7 days without signals) · 2 cautious (a signal 3 days in a row, or two signals the same day; adjustments are only
suggestions) · 3 off (the regression fails or an adversarial case passes; final = base). Levels 2 and 3 are left
only when the regression set passes and a person reactivates the judge.

Every change is a row of `judge_ladder_change` (`changed_by` NULL when automatic); the current level is the view
`judge_ladder_current`. The judge (F6) reads `effects(level)`; nothing here calls an LLM.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from decimal import Decimal
from enum import IntEnum
from typing import Final

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from core.db import models as m

log = logging.getLogger("core.metrics.ladder")

# TODO(P-006): thresholds of docs/07 §8 until the user confirms the ladder.
SIGNAL_THRESHOLDS: Final[dict[str, Decimal]] = {
    "validation_failure_rate": Decimal("0.10"),
    "double_review_disagreement": Decimal("0.30"),
    "wrong_priority_judged": Decimal("0.25"),
}
SUSTAINED_DAYS: Final = 3
SIMULTANEOUS_SIGNALS: Final = 2  # "two signals at the same time" (docs/07 §8)
QUIET_DAYS: Final = 7
WATCHED_DOUBLE_REVIEW_THRESHOLD: Final = 10


class Level(IntEnum):
    NORMAL = 0
    WATCHED = 1
    CAUTIOUS = 2
    OFF = 3


@dataclass(frozen=True)
class LadderEffects:
    """What the judge must do at a level."""

    double_review_threshold: int | None  # None = the configured threshold (P-005)
    apply_adjustments: bool  # False: the adjustment is recorded and shown as a suggestion only
    judge_enabled: bool  # False: final = base, marked no_judge_review


def effects(level: int) -> LadderEffects:
    if level >= Level.OFF:
        return LadderEffects(double_review_threshold=None, apply_adjustments=False, judge_enabled=False)
    if level == Level.CAUTIOUS:
        return LadderEffects(double_review_threshold=None, apply_adjustments=False, judge_enabled=True)
    if level == Level.WATCHED:
        return LadderEffects(WATCHED_DOUBLE_REVIEW_THRESHOLD, apply_adjustments=True, judge_enabled=True)
    return LadderEffects(double_review_threshold=None, apply_adjustments=True, judge_enabled=True)


def signals_of(values: Mapping[str, Decimal]) -> frozenset[str]:
    """The signals a day's metric values raise."""
    return frozenset(code for code, limit in SIGNAL_THRESHOLDS.items() if code in values and values[code] > limit)


@dataclass(frozen=True)
class Transition:
    level: int
    reason: str


def next_level(
    current: int,
    days: Sequence[tuple[date, frozenset[str]]],
    today: date,
    since: date | None,
    regression_failed: bool,
) -> Transition | None:
    """The automatic move after `today`'s metrics, or None. `days` holds the recent days' signals (any order).

    Automatic moves only go up, except 1 -> 0 after `QUIET_DAYS` days without signals; levels 2 and 3 only go down
    through `reactivate`.
    """
    if regression_failed:
        return (
            Transition(Level.OFF, "Falló el set de regresión o pasó un caso adversarial")
            if current < Level.OFF
            else None
        )
    by_day = dict(days)
    if current < Level.CAUTIOUS:
        escalation = _escalation(by_day, today)
        if escalation is not None:
            return escalation
    today_signals = by_day.get(today, frozenset())
    if current == Level.NORMAL and today_signals:
        return Transition(Level.WATCHED, "Señal leve: " + ", ".join(sorted(today_signals)))
    quiet = all(not by_day.get(today - timedelta(days=i)) for i in range(QUIET_DAYS))
    if current == Level.WATCHED and quiet and since is not None and since <= today - timedelta(days=QUIET_DAYS):
        return Transition(Level.NORMAL, f"{QUIET_DAYS} días sin señales")
    return None


def _escalation(by_day: Mapping[date, frozenset[str]], today: date) -> Transition | None:
    """Level 2: two signals on the same day, or the same signal on each of the last `SUSTAINED_DAYS` days."""
    today_signals = by_day.get(today, frozenset())
    if len(today_signals) >= SIMULTANEOUS_SIGNALS:
        return Transition(Level.CAUTIOUS, "Dos señales a la vez: " + ", ".join(sorted(today_signals)))
    window = [by_day.get(today - timedelta(days=i), frozenset()) for i in range(SUSTAINED_DAYS)]
    sustained = sorted(frozenset.intersection(*window))
    if sustained:
        return Transition(Level.CAUTIOUS, f"Señal sostenida {SUSTAINED_DAYS} días: " + ", ".join(sustained))
    return None


# --- database --------------------------------------------------------------------------------------------------


class LadderError(Exception):
    """A manual change the ladder does not allow."""


def current_level(session: Session) -> tuple[int, datetime | None]:
    """The latest level and when it was set (0 and None if it never changed)."""
    row = session.execute(
        select(m.JudgeLadderChange.level, m.JudgeLadderChange.changed_at)
        .order_by(m.JudgeLadderChange.changed_at.desc(), m.JudgeLadderChange.id.desc())
        .limit(1)
    ).first()
    return (int(row.level), row.changed_at) if row else (Level.NORMAL, None)


def _last_manual_change(session: Session) -> datetime | None:
    """When a person last changed the level (a reactivation), or None if no one ever did."""
    return session.scalar(
        select(m.JudgeLadderChange.changed_at)
        .where(m.JudgeLadderChange.changed_by.is_not(None))
        .order_by(m.JudgeLadderChange.changed_at.desc(), m.JudgeLadderChange.id.desc())
        .limit(1)
    )


def _last_change_was_manual(session: Session) -> bool:
    changed_by = session.scalar(
        select(m.JudgeLadderChange.changed_by)
        .order_by(m.JudgeLadderChange.changed_at.desc(), m.JudgeLadderChange.id.desc())
        .limit(1)
    )
    return changed_by is not None


METRIC_LAG: Final = timedelta(days=1)  # the nightly job evaluates yesterday's metrics (`workers.jobs.NightlyJob`)
_SIGNAL_VALUES: Final = text(
    """SELECT metric_date, metric_code, value FROM daily_metric
    WHERE dimension = '' AND metric_code = ANY(:codes) AND metric_date > :since AND metric_date <= :today"""
)


def daily_signals(session: Session, today: date) -> list[tuple[date, frozenset[str]]]:
    """Signals of the last `QUIET_DAYS` days, read from `daily_metric`."""
    values: dict[date, dict[str, Decimal]] = {}
    params = {"codes": list(SIGNAL_THRESHOLDS), "since": today - timedelta(days=QUIET_DAYS), "today": today}
    for row in session.execute(_SIGNAL_VALUES, params).all():
        values.setdefault(row.metric_date, {})[row.metric_code] = Decimal(row.value)
    return [(day, signals_of(day_values)) for day, day_values in sorted(values.items())]


def _record(session: Session, transition: Transition, now: datetime, changed_by: uuid.UUID | None) -> None:
    session.add(
        m.JudgeLadderChange(level=transition.level, reason=transition.reason, changed_by=changed_by, changed_at=now)
    )
    session.flush()
    # Admin warning (F-19): the dashboard shows the level; a notification channel for admins is not built yet.
    log.warning("judge ladder -> level %d: %s", transition.level, transition.reason)


def evaluate(session: Session, today: date, now: datetime, *, regression_failed: bool = False) -> Transition | None:
    """Apply the automatic rule after `today`'s metrics; records and returns the change, if any."""
    level, changed_at = current_level(session)
    since: date | None = None
    if changed_at is not None:
        # An automatic change is recorded by the nightly job the day after the metrics that caused it; counting the
        # quiet days from the metric day keeps 1 -> 0 on time (pending F8.1 #59).
        since = changed_at.date() if _last_change_was_manual(session) else changed_at.date() - METRIC_LAG
    days = daily_signals(session, today)
    reviewed = _last_manual_change(session)
    if reviewed is not None:
        # A person reviewed everything up to the last reactivation: older signal days never count again, even after
        # a later automatic change (pending F8.1 #58).
        days = [(day, signals) for day, signals in days if day >= reviewed.date()]
    transition = next_level(level, days, today, since, regression_failed)
    if transition is not None and transition.level != level:
        _record(session, transition, now, None)
        return transition
    return None


def reactivate(session: Session, user_id: uuid.UUID, now: datetime, *, regression_passed: bool, reason: str) -> None:
    """A person brings the judge back to normal. From levels 2 and 3 the regression set must have passed."""
    level, _ = current_level(session)
    if level == Level.NORMAL:
        raise LadderError("the judge is already at the normal level")
    if level >= Level.CAUTIOUS and not regression_passed:
        raise LadderError("leaving levels 2 and 3 requires the regression set to pass")
    if not reason.strip():
        raise LadderError("a reactivation needs a reason")
    _record(session, Transition(Level.NORMAL, f"Reactivación humana: {reason.strip()}"), now, user_id)
