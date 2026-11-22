"""The worker's nightly job: yesterday's metrics, then the ladder rule on them."""

from __future__ import annotations

import f08data as d
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from workers.jobs import NightlyJob

pytestmark = pytest.mark.integration


def test_the_nightly_job_aggregates_yesterday_and_moves_the_ladder(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        for status in ("rejected", "rejected", "applied"):
            d.review(session, status)  # 2 of 3 judge answers fail validation on 2026-11-21

    NightlyJob(factory, clock=lambda: d.NOW)()

    with factory() as session:
        dates = session.scalars(select(func.distinct(m.DailyMetric.metric_date))).all()
        assert [day.isoformat() for day in dates] == ["2026-11-21"]
        change = session.scalars(select(m.JudgeLadderChange)).one()
        assert (change.level, change.reason) == (1, "Señal leve: validation_failure_rate")
