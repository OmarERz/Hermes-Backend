"""The ladder reads its signals from daily_metric and records every change in judge_ladder_change."""

from __future__ import annotations

from datetime import date, timedelta
from decimal import Decimal

import f08data as d
import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from core.metrics.ladder import LadderError, Level, current_level, evaluate, reactivate

pytestmark = pytest.mark.integration
TODAY = date(2026, 11, 21)


def metric(session: Session, day: date, code: str, value: str) -> None:
    session.add(m.DailyMetric(metric_date=day, metric_code=code, dimension="", value=Decimal(value)))
    session.flush()


def view_level(session: Session) -> int:
    return int(session.scalar(text("SELECT level FROM judge_ladder_current")) or 0)


def test_a_signal_is_recorded_as_an_automatic_change(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        metric(session, TODAY, "validation_failure_rate", "0.25")
        metric(session, TODAY, "double_review_disagreement", "0.05")
        transition = evaluate(session, TODAY, d.NOW)
        assert transition is not None
        assert transition.level == Level.WATCHED
        change = session.scalars(select(m.JudgeLadderChange)).one()
        assert (change.level, change.changed_by, change.changed_at) == (1, None, d.NOW)
        assert view_level(session) == 1
        assert evaluate(session, TODAY, d.NOW) is None  # same day again: no new row


def test_three_days_of_disagreement_escalate_and_only_a_person_brings_it_back(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        for back in (2, 1, 0):
            metric(session, TODAY - timedelta(days=back), "double_review_disagreement", "0.4")
        evaluate(session, TODAY - timedelta(days=2), d.NOW - timedelta(days=2))
        transition = evaluate(session, TODAY, d.NOW)
        assert transition is not None
        assert transition.level == Level.CAUTIOUS
        analyst = d.user(session)
        with pytest.raises(LadderError, match="regression"):
            reactivate(session, analyst.id, d.NOW, regression_passed=False, reason="Revisado")
        with pytest.raises(LadderError, match="reason"):
            reactivate(session, analyst.id, d.NOW, regression_passed=True, reason=" ")
        reactivate(session, analyst.id, d.NOW + timedelta(hours=1), regression_passed=True, reason="Revisado")
        level, changed_at = current_level(session)
        assert (level, changed_at) == (Level.NORMAL, d.NOW + timedelta(hours=1))
        latest = session.scalars(select(m.JudgeLadderChange).order_by(m.JudgeLadderChange.changed_at.desc())).first()
        assert latest is not None
        assert (latest.changed_by, latest.reason) == (analyst.id, "Reactivación humana: Revisado")
        with pytest.raises(LadderError, match="already"):
            reactivate(session, analyst.id, d.NOW, regression_passed=True, reason="x")


def test_a_failed_regression_turns_it_off(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        transition = evaluate(session, TODAY, d.NOW, regression_failed=True)
        assert transition is not None
        assert view_level(session) == Level.OFF


def test_watched_can_be_reactivated_without_regression(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        metric(session, TODAY, "wrong_priority_judged", "0.5")
        evaluate(session, TODAY, d.NOW)
        reactivate(session, d.user(session).id, d.NOW, regression_passed=False, reason="Falsa alarma")
        assert current_level(session)[0] == Level.NORMAL


def test_a_reactivation_is_not_undone_by_re_evaluating_reviewed_days(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        for back in (2, 1, 0):
            metric(session, TODAY - timedelta(days=back), "double_review_disagreement", "0.4")
        evaluate(session, TODAY, d.NOW)
        assert current_level(session)[0] == Level.CAUTIOUS
        reactivate(session, d.user(session).id, d.NOW + timedelta(hours=1), regression_passed=True, reason="Revisado")

        assert evaluate(session, TODAY, d.NOW + timedelta(hours=2)) is None  # e.g. a worker restart
        assert current_level(session)[0] == Level.NORMAL

        tomorrow = TODAY + timedelta(days=1)
        metric(session, tomorrow, "double_review_disagreement", "0.4")
        transition = evaluate(session, tomorrow, d.NOW + timedelta(days=1))
        assert transition is not None
        assert transition.level == Level.WATCHED  # a new signal after the reactivation still counts


def test_watched_returns_to_normal_seven_quiet_days_after_the_metric_day(factory: sessionmaker[Session]) -> None:
    """The change is recorded the day after the metrics that caused it; the quiet days count from the metric day
    (pending F8.1 #59)."""
    with factory() as session, session.begin():
        metric(session, TODAY, "validation_failure_rate", "0.25")
        assert evaluate(session, TODAY, d.NOW) is not None  # recorded on TODAY + 1
        later = TODAY + timedelta(days=7)
        transition = evaluate(session, later, d.NOW + timedelta(days=7))
        assert transition is not None
        assert transition.level == Level.NORMAL


def test_days_reviewed_at_a_reactivation_never_count_again(factory: sessionmaker[Session]) -> None:
    """Even after a later automatic change, signal days before the reactivation stay reviewed (pending F8.1 #58)."""
    with factory() as session, session.begin():
        for back in (2, 1, 0):
            metric(session, TODAY - timedelta(days=back), "double_review_disagreement", "0.4")
        evaluate(session, TODAY, d.NOW)
        reactivate(session, d.user(session).id, d.NOW + timedelta(hours=1), regression_passed=True, reason="Revisado")
        tomorrow, after = TODAY + timedelta(days=1), TODAY + timedelta(days=2)
        metric(session, tomorrow, "double_review_disagreement", "0.4")
        assert evaluate(session, tomorrow, d.NOW + timedelta(days=1)) is not None  # watched (automatic)
        metric(session, after, "double_review_disagreement", "0.4")
        assert evaluate(session, after, d.NOW + timedelta(days=2)) is None  # TODAY was reviewed: no 3-day streak
        assert current_level(session)[0] == Level.WATCHED
