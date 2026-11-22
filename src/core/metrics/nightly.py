"""Nightly metrics (docs/10 §1): one aggregation per UTC day into `daily_metric` (exception X-6).

Each metric is one SQL query over the day `[day 00:00 UTC, day + 1)` that returns `(dimension, value)` rows; the
dimension is `''` when it does not apply (e.g. `agent:judge`, `reason:mass_exploitation`, `source:thn`). Ratios are
stored as fractions 0..1. A ratio whose denominator is zero is not stored: "no data" never shows up as 0 %.
Snapshot metrics (queues, health, inventory) describe the state when the job runs.

Storing is an upsert per (date, code, dimension): running the job twice for the same day leaves the same rows.
Metrics that need data the system does not produce yet (canary, regression set, weekly sampling) are out of the
minimal F8 scope: MET-04, 05, 06, 08, 09, 12, 19, 20, 23, 27 and 28.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from typing import Final

from sqlalchemy import TextClause, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m

log = logging.getLogger("core.metrics.nightly")


@dataclass(frozen=True)
class MetricValue:
    code: str
    dimension: str
    value: Decimal


# Every query receives :start and :end (the UTC day) and :now (when the job runs). Literal SQL only; a ratio
# divides by NULLIF(denominator, 0) so an empty day gives NULL, which is not stored.
QUERIES: Final[dict[str, TextClause]] = {
    # MET-01 · Precision: relevant / (relevant + false positive), current feedback given that day.
    "precision": text(
        """SELECT '' AS dimension, (count(*) FILTER (WHERE verdict = 'relevant'))::numeric / NULLIF(count(*)
        FILTER (WHERE verdict IN ('relevant', 'false_positive')), 0) AS value FROM feedback WHERE
        superseded_at IS NULL AND created_at >= :start AND created_at < :end"""
    ),
    # MET-02 · Feedback rate: delivered events of the day whose assessment received any feedback.
    "feedback_rate": text(
        """SELECT '' AS dimension, (count(*) FILTER (WHERE EXISTS (SELECT 1 FROM feedback f WHERE
        f.assessment_id = e.assessment_id)))::numeric / NULLIF(count(*), 0) AS value FROM notification_event
        e WHERE e.status = 'delivered' AND e.assessment_id IS NOT NULL AND e.delivered_at >= :start AND
        e.delivered_at < :end"""
    ),
    # MET-03 · Precision of criticals: critical events of the day without a "wrong priority" feedback.
    "critical_precision": text(
        """SELECT '' AS dimension, (count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM feedback f WHERE
        f.assessment_id = e.assessment_id AND f.verdict = 'wrong_priority' AND f.superseded_at IS
        NULL)))::numeric / NULLIF(count(*), 0) AS value FROM notification_event e WHERE e.status =
        'delivered' AND e.assessment_id IS NOT NULL AND e.payload -> 'score' ->> 'level' = 'critical' AND
        e.delivered_at >= :start AND e.delivered_at < :end"""
    ),
    # MET-07 · Use per judge reason (accepted reasons of the day's judge reviews).
    "reason_usage": text(
        """SELECT 'reason:' || r.reason_code AS dimension, count(*)::numeric AS value FROM judge_reason r JOIN
        llm_review v ON v.id = r.llm_review_id WHERE v.agent = 'judge' AND r.status = 'accepted' AND
        v.created_at >= :start AND v.created_at < :end GROUP BY r.reason_code"""
    ),
    # MET-10 · Rejections per rule (L5, L6, L7 ...).
    "rule_rejections": text(
        """SELECT 'rule:' || COALESCE(r.rejection_rule, 'unknown') AS dimension, count(*)::numeric AS value
        FROM judge_reason r JOIN llm_review v ON v.id = r.llm_review_id WHERE v.agent = 'judge' AND r.status
        = 'rejected' AND v.created_at >= :start AND v.created_at < :end GROUP BY 1"""
    ),
    # MET-11 · Double review: share of first reviews that triggered a second one ...
    "double_review_rate": text(
        """SELECT '' AS dimension, (count(*) FILTER (WHERE EXISTS (SELECT 1 FROM llm_review s WHERE
        s.second_review_of_id = v.id)))::numeric / NULLIF(count(*), 0) AS value FROM llm_review v WHERE
        v.agent = 'judge' AND v.second_review_of_id IS NULL AND v.created_at >= :start AND v.created_at <
        :end"""
    ),
    # ... and share of double reviews that disagreed (also a ladder signal, docs/07 §8).
    "double_review_disagreement": text(
        """SELECT '' AS dimension, (count(*) FILTER (WHERE v.status = 'judge_disagreement'))::numeric /
        NULLIF(count(*), 0) AS value FROM llm_review v WHERE v.agent = 'judge' AND v.second_review_of_id IS
        NULL AND v.created_at >= :start AND v.created_at < :end AND EXISTS (SELECT 1 FROM llm_review s WHERE
        s.second_review_of_id = v.id)"""
    ),
    # MET-13 · Distribution of the judge's adjustment over the day's group assessments.
    "judge_adjustment_avg": text(
        """SELECT '' AS dimension, avg(judge_adjustment)::numeric AS value FROM assessment WHERE
        finding_group_id IS NOT NULL AND assessed_at >= :start AND assessed_at < :end"""
    ),
    "judge_adjustment_up": text(
        """SELECT '' AS dimension, (count(*) FILTER (WHERE judge_adjustment > 0))::numeric / NULLIF(count(*),
        0) AS value FROM assessment WHERE finding_group_id IS NOT NULL AND assessed_at >= :start AND
        assessed_at < :end"""
    ),
    "judge_adjustment_down": text(
        """SELECT '' AS dimension, (count(*) FILTER (WHERE judge_adjustment < 0))::numeric / NULLIF(count(*),
        0) AS value FROM assessment WHERE finding_group_id IS NOT NULL AND assessed_at >= :start AND
        assessed_at < :end"""
    ),
    "judge_adjustment_large": text(
        """SELECT '' AS dimension, (count(*) FILTER (WHERE abs(judge_adjustment) >= 15))::numeric /
        NULLIF(count(*), 0) AS value FROM assessment WHERE finding_group_id IS NOT NULL AND assessed_at >=
        :start AND assessed_at < :end"""
    ),
    # MET-14 · Fallbacks: judge reviews closed as no_judge_review.
    "fallback_rate": text(
        """SELECT '' AS dimension, (count(*) FILTER (WHERE status = 'no_judge_review'))::numeric /
        NULLIF(count(*), 0) AS value FROM llm_review WHERE agent = 'judge' AND created_at >= :start AND
        created_at < :end"""
    ),
    # Ladder signal: judge answers that did not pass validation (docs/07 §8, > 10 %).
    "validation_failure_rate": text(
        """SELECT '' AS dimension, (count(*) FILTER (WHERE status = 'rejected'))::numeric / NULLIF(count(*), 0)
        AS value FROM llm_review WHERE agent = 'judge' AND status <> 'queued' AND created_at >= :start AND
        created_at < :end"""
    ),
    # MET-15 · Validation at the first attempt, per LLM piece.
    "first_pass_validation": text(
        """SELECT 'agent:' || agent AS dimension, (count(*) FILTER (WHERE attempts <= 1))::numeric /
        NULLIF(count(*), 0) AS value FROM llm_review WHERE status <> 'queued' AND created_at >= :start AND
        created_at < :end GROUP BY agent"""
    ),
    # MET-16 · Retries per piece.
    "retries": text(
        """SELECT 'agent:' || agent AS dimension, sum(greatest(attempts - 1, 0))::numeric AS value FROM
        llm_review WHERE created_at >= :start AND created_at < :end GROUP BY agent"""
    ),
    # MET-17 · Cost in USD per piece (the price is stored with each review).
    "cost_usd": text(
        """SELECT 'agent:' || agent AS dimension, sum(cost_usd)::numeric AS value FROM llm_review WHERE
        created_at >= :start AND created_at < :end GROUP BY agent"""
    ),
    # Ladder signal: "wrong priority" on assessments the judge adjusted (docs/07 §8, > 25 %).
    "wrong_priority_judged": text(
        """SELECT '' AS dimension, (count(*) FILTER (WHERE f.verdict = 'wrong_priority'))::numeric /
        NULLIF(count(*), 0) AS value FROM feedback f JOIN assessment a ON a.id = f.assessment_id WHERE
        f.superseded_at IS NULL AND a.judge_adjustment <> 0 AND f.created_at >= :start AND f.created_at <
        :end"""
    ),
    # MET-18 · Error queue: size and age of the oldest pending item (snapshot).
    "error_queue_size": text(
        """SELECT '' AS dimension, count(*)::numeric AS value FROM error_queue WHERE status = 'pending'"""
    ),
    "error_queue_oldest_hours": text(
        """SELECT '' AS dimension, (extract(epoch FROM :now - min(created_at)) / 3600)::numeric AS value FROM
        error_queue WHERE status = 'pending'"""
    ),
    # MET-21 · Share of iTop software with a CPE mapping (snapshot).
    "cpe_mapping_coverage": text(
        """SELECT '' AS dimension, (count(*) FILTER (WHERE EXISTS (SELECT 1 FROM cpe_mapping c WHERE
        c.software_product_id = p.id)))::numeric / NULLIF(count(*), 0) AS value FROM software_product p"""
    ),
    # MET-22 · Hours since the last successful fetch of each enabled source (snapshot).
    "source_hours_since_ok": text(
        """SELECT 'source:' || s.code AS dimension, (extract(epoch FROM :now - h.last_ok_at) / 3600)::numeric
        AS value FROM source s JOIN source_health h ON h.source_id = s.id WHERE s.enabled"""
    ),
    # MET-24/25/26 · Raw vs processed (D-039) over the day's scored CIs.
    "reclassified": text(
        """SELECT '' AS dimension, (count(*) FILTER (WHERE d.level IS DISTINCT FROM CASE WHEN a.raw_cvss_score
        >= 9 THEN 'critical' WHEN a.raw_cvss_score >= 7 THEN 'high' WHEN a.raw_cvss_score >= 4 THEN 'medium'
        ELSE 'low' END))::numeric / NULLIF(count(*), 0) AS value FROM asset_score_detail d JOIN assessment a
        ON a.id = d.assessment_id WHERE a.raw_cvss_score IS NOT NULL AND a.assessed_at >= :start AND
        a.assessed_at < :end"""
    ),
    "hidden_criticals": text(
        """SELECT '' AS dimension, count(*)::numeric AS value FROM asset_score s JOIN assessment a ON a.id =
        s.assessment_id WHERE a.raw_cvss_score < 7.0 AND s.final >= 75 AND a.assessed_at >= :start AND
        a.assessed_at < :end"""
    ),
    "noise_avoided": text(
        """SELECT '' AS dimension, count(*)::numeric AS value FROM asset_score s JOIN assessment a ON a.id =
        s.assessment_id WHERE a.raw_cvss_score >= 9.0 AND s.final < 50 AND a.assessed_at >= :start AND
        a.assessed_at < :end"""
    ),
    # MET-29 · Live CIs with an inventory issue (no classification, exposure, owner or custodian; snapshot).
    "inventory_pending": text(
        """SELECT '' AS dimension, (count(*) FILTER (WHERE EXISTS (SELECT 1 FROM inventory_issue i WHERE
        i.asset_id = a.id)))::numeric / NULLIF(count(*), 0) AS value FROM asset a WHERE a.decommissioned_at
        IS NULL"""
    ),
    # MET-30 · Notification events: pending and failed (snapshot), oldest pending immediate, delivery latency.
    "notification_pending": text(
        """SELECT '' AS dimension, count(*)::numeric AS value FROM notification_event WHERE status = 'pending'"""
    ),
    "notification_failed": text(
        """SELECT '' AS dimension, count(*)::numeric AS value FROM notification_event WHERE status = 'failed'"""
    ),
    "immediate_oldest_pending_minutes": text(
        """SELECT '' AS dimension, (extract(epoch FROM :now - min(created_at)) / 60)::numeric AS value FROM
        notification_event WHERE status = 'pending' AND priority = 'immediate'"""
    ),
    "delivery_latency_p95_seconds": text(
        """SELECT '' AS dimension, percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM delivered_at
        - created_at))::numeric AS value FROM notification_event WHERE status = 'delivered' AND delivered_at
        >= :start AND delivered_at < :end"""
    ),
}


def day_window(day: date) -> tuple[datetime, datetime]:
    start = datetime.combine(day, time.min, tzinfo=UTC)
    return start, start + timedelta(days=1)


def compute_daily_metrics(session: Session, day: date, now: datetime) -> list[MetricValue]:
    """Every metric of `day` that has data; snapshot metrics are taken at `now`."""
    start, end = day_window(day)
    values: list[MetricValue] = []
    for code, query in QUERIES.items():
        for row in session.execute(query, {"start": start, "end": end, "now": now}).all():
            if row.value is not None:
                values.append(MetricValue(code, row.dimension, Decimal(row.value)))
    return values


def store_daily_metrics(session: Session, day: date, values: Sequence[MetricValue]) -> int:
    """Upsert the values of `day`; returns how many rows were written."""
    for value in values:
        statement = pg_insert(m.DailyMetric).values(
            metric_date=day, metric_code=value.code, dimension=value.dimension, value=value.value
        )
        session.execute(
            statement.on_conflict_do_update(
                index_elements=["metric_date", "metric_code", "dimension"], set_={"value": statement.excluded.value}
            )
        )
    return len(values)


@dataclass
class NightlyMetrics:
    """The nightly job: aggregates the previous UTC day (and refreshes it if run again)."""

    session_factory: sessionmaker[Session]
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def run(self, day: date | None = None) -> int:
        now = self.clock()
        target = day or (now.astimezone(UTC).date() - timedelta(days=1))
        with self.session_factory() as session, session.begin():
            written = store_daily_metrics(session, target, compute_daily_metrics(session, target, now))
        log.info("daily metrics for %s: %d values", target.isoformat(), written)
        return written
