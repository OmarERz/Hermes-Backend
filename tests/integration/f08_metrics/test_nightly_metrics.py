"""Nightly metrics into daily_metric (docs/10 §1): values, empty days and idempotency."""

from __future__ import annotations

from datetime import date, timedelta
from decimal import Decimal

import f08data as d
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from core.metrics.nightly import NightlyMetrics, compute_daily_metrics

pytestmark = pytest.mark.integration
DAY = date(2026, 11, 21)


def q(value: object) -> Decimal:
    """Six decimals: enough to compare SQL numerics with exact fractions."""
    return Decimal(str(value)).quantize(Decimal("0.000001"))


def stored(factory: sessionmaker[Session]) -> dict[tuple[str, str], Decimal]:
    with factory() as session:
        rows = session.scalars(select(m.DailyMetric).where(m.DailyMetric.metric_date == DAY)).all()
        return {(r.metric_code, r.dimension): r.value for r in rows}


def seed_day(session: Session) -> None:
    d.formula(session)  # also seeds the judge reason catalog
    first = d.review(session, "applied")
    d.review(session, "judge_disagreement", attempts=2)
    disagreeing = session.scalars(select(m.LlmReview).where(m.LlmReview.status == "judge_disagreement")).one()
    d.review(session, "applied", second_review_of_id=disagreeing.id)
    d.review(session, "rejected", attempts=3)
    d.review(session, "no_judge_review")
    d.review(session, "applied", agent="news_analyst")
    d.review(session, "applied", at=d.NOON - timedelta(days=1))  # another day: ignored
    session.add(
        m.JudgeReason(
            llm_review_id=first.id,
            seq=1,
            reason_code="mass_exploitation",
            points=8,
            element_id="n1",
            quote="q",
            status="accepted",
        )
    )
    session.add(
        m.JudgeReason(
            llm_review_id=first.id,
            seq=2,
            reason_code="other",
            points=3,
            element_id="n2",
            quote="q",
            status="rejected",
            rejection_rule="L5",
        )
    )
    adjusted = [d.assessment(session, adj) for adj in (10, -5, 0, 20)]
    d.feedback(session, adjusted[0], "relevant")
    d.feedback(session, adjusted[1], "relevant")
    d.feedback(session, adjusted[2], "false_positive")
    d.feedback(session, adjusted[3], "wrong_priority")
    d.feedback(session, adjusted[3], "false_positive", superseded=True)
    raw = d.assessment(session, 0, cvss="6.5")
    d.score(session, raw, 80)  # hidden critical; level high vs CVSS medium -> reclassified
    noisy = d.assessment(session, 0, cvss="9.8")
    d.score(session, noisy, 40)  # noise avoided
    d.event(session, adjusted[0], level="critical", latency_s=30)
    d.event(session, adjusted[3], level="critical", latency_s=90)
    d.event(session, status="pending", priority="immediate", created=d.NOW - timedelta(minutes=12))
    d.event(session, status="failed")
    cve_id = d.group(session).cve_id
    session.add(
        m.ErrorQueue(
            component="cve_analyst",
            cve_id=cve_id,
            reason="x",
            attempts=1,
            status="pending",
            created_at=d.NOW - timedelta(hours=30),
        )
    )
    session.flush()


def test_the_nightly_job_stores_every_metric_with_data(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        seed_day(session)

    written = NightlyMetrics(factory, clock=lambda: d.NOW).run()

    values = stored(factory)
    assert written == len(values)
    assert q(values[("precision", "")]) == q(Decimal(2) / 3)
    assert q(values[("feedback_rate", "")]) == q(1)
    assert q(values[("critical_precision", "")]) == q(Decimal("0.5"))
    assert q(values[("reason_usage", "reason:mass_exploitation")]) == q(1)
    assert q(values[("rule_rejections", "rule:L5")]) == q(1)
    assert q(values[("double_review_rate", "")]) == q(Decimal("0.25"))
    assert q(values[("double_review_disagreement", "")]) == q(1)
    assert q(values[("validation_failure_rate", "")]) == q(Decimal("0.2"))
    assert q(values[("fallback_rate", "")]) == q(Decimal("0.2"))
    assert q(values[("judge_adjustment_avg", "")]) == q(Decimal("4.1666666666666667"))
    assert q(values[("judge_adjustment_up", "")]) == q(Decimal(2) / 6)
    assert q(values[("judge_adjustment_large", "")]) == q(Decimal(1) / 6)
    assert q(values[("wrong_priority_judged", "")]) == q(Decimal(1) / 3)
    assert q(values[("first_pass_validation", "agent:judge")]) == q(Decimal("0.6"))
    assert q(values[("first_pass_validation", "agent:news_analyst")]) == q(1)
    assert q(values[("retries", "agent:judge")]) == q(3)
    assert q(values[("cost_usd", "agent:judge")]) == q(Decimal("0.05"))
    assert q(values[("error_queue_size", "")]) == q(1)
    assert q(values[("error_queue_oldest_hours", "")]) == q(30)
    assert q(values[("hidden_criticals", "")]) == q(1)
    assert q(values[("noise_avoided", "")]) == q(1)
    assert q(values[("reclassified", "")]) == q(1)
    assert q(values[("notification_pending", "")]) == q(1)
    assert q(values[("notification_failed", "")]) == q(1)
    assert q(values[("immediate_oldest_pending_minutes", "")]) == q(12)
    assert q(values[("delivery_latency_p95_seconds", "")]) == q(87)


def test_running_twice_leaves_the_same_rows(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        seed_day(session)
    job = NightlyMetrics(factory, clock=lambda: d.NOW)
    job.run()
    first = stored(factory)
    job.run(DAY)
    assert stored(factory) == first


def test_an_empty_day_stores_counts_but_no_ratios(factory: sessionmaker[Session]) -> None:
    with factory() as session:
        values = {(v.code, v.dimension) for v in compute_daily_metrics(session, DAY, d.NOW)}
    assert ("precision", "") not in values
    assert ("fallback_rate", "") not in values
    assert ("error_queue_oldest_hours", "") not in values
    assert ("notification_pending", "") in values
