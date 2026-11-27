"""Agent telemetry for the front (D-088, IN-4, AG-1 to AG-12, HI-3): runs and LLM reviews, read from the database.

Only metadata leaves this module: counts, statuses, latencies, tokens and costs. Prompts, raw calls, the review
package and news text never do (X-2, SEG-02). The dashboards stay inside the installation (D-001 forbids sending
telemetry out, not showing it here).

A review succeeds when it reached a valid outcome (`applied`, `suggestion`, `partial_review` or
`judge_disagreement`); it fails when it fell back (`no_judge_review`) or was rejected; a `queued` one is pending and
counts for neither.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Final

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.metrics.ladder import current_level

AGENTS: Final = ("news_analyst", "cve_analyst", "judge")
SUCCESS: Final = frozenset({"applied", "suggestion", "partial_review", "judge_disagreement"})
FAILURE: Final = frozenset({"no_judge_review", "rejected"})
# The database names of the run kinds and the API names (`news` runs are the ingestion, `mode4` the calibration).
RUN_KINDS: Final = {
    "scan": "scan",
    "news": "ingestion",
    "recalculation": "recalculation",
    "nightly": "nightly",
    "inventory_sync": "inventory_sync",
    "mode4": "calibration",
}
RUN_STATUSES: Final = {"queued": "queued", "running": "running", "succeeded": "succeeded", "failed": "failed"}
WINDOWS: Final = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
LADDER_LABELS: Final = {0: "Normal", 1: "Vigilado", 2: "Cauteloso", 3: "Apagado"}
LADDER_OFF: Final = 3
DEFAULT_BUDGET: Final = Decimal(5)
TOP_REASONS: Final = 10
ReviewKey = tuple[datetime, uuid.UUID]  # (created_at, id): newest first

_RUNS: Final = text(
    """
    SELECT kind, CASE status WHEN 'cancelled' THEN 'failed' ELSE status END AS status, count(*)::integer AS runs
      FROM run
     WHERE started_at >= :since OR status IN ('queued', 'running')  -- what runs now counts whatever the window (AG-9)
     GROUP BY 1, 2
    """
)
_REVIEWS: Final = text(
    """
    SELECT agent, status, count(*)::integer AS reviews,
           COALESCE(sum(tokens_input), 0)::bigint AS tokens_input,
           COALESCE(sum(tokens_output), 0)::bigint AS tokens_output,
           COALESCE(sum(cost_usd), 0) AS cost_usd
      FROM llm_review
     WHERE created_at >= :since
     GROUP BY agent, status
    """
)
# Percentiles cannot be summed across statuses: one row per agent for the latency over the whole window.
_LATENCY: Final = text(
    """
    SELECT agent, avg(latency_ms) AS latency_avg,
           percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) AS latency_p95
      FROM llm_review WHERE created_at >= :since GROUP BY agent
    """
)
_LAST_MODEL: Final = text(
    "SELECT DISTINCT ON (agent) agent, model FROM llm_review ORDER BY agent, created_at DESC, id DESC"
)
_SPEND: Final = text(
    "SELECT agent, COALESCE(sum(cost_usd), 0) AS cost FROM llm_review WHERE created_at >= :t GROUP BY 1"
)
_REASONS: Final = text(
    """
    SELECT jr.reason_code AS code, t.description AS label,
           count(*) FILTER (WHERE jr.status = 'accepted')::integer AS accepted,
           count(*) FILTER (WHERE jr.status = 'rejected')::integer AS rejected
      FROM judge_reason jr
      JOIN llm_review r ON r.id = jr.llm_review_id
      JOIN judge_reason_type t ON t.code = jr.reason_code
     WHERE r.created_at >= :since
     GROUP BY jr.reason_code, t.description
     ORDER BY count(*) FILTER (WHERE jr.status = 'accepted') DESC, count(*) DESC, jr.reason_code
     LIMIT :limit
    """
)
_SETTINGS: Final = text(
    "SELECT setting_key, value FROM setting_current WHERE setting_key IN ('daily_budget_usd', 'judge_model', "
    "'analyst_model')"
)
_DAILY_RUNS: Final = text(
    """
    SELECT (finished_at AT TIME ZONE 'UTC')::date AS day,
           count(*) FILTER (WHERE status = 'succeeded')::integer AS succeeded,
           count(*) FILTER (WHERE status IN ('failed', 'cancelled'))::integer AS failed
      FROM run WHERE finished_at >= :since GROUP BY 1
    """
)
_DAILY_REVIEWS: Final = text(
    """
    SELECT (created_at AT TIME ZONE 'UTC')::date AS day, agent, count(*)::integer AS reviews,
           count(*) FILTER (WHERE status = ANY(CAST(:success AS text[])))::integer AS succeeded,
           count(*) FILTER (WHERE status = ANY(CAST(:failure AS text[])))::integer AS failed,
           avg(latency_ms) AS latency_avg, COALESCE(sum(cost_usd), 0) AS cost_usd
      FROM llm_review WHERE created_at >= :since GROUP BY 1, 2
    """
)
_LOG: Final = text(
    """
    SELECT r.id, r.created_at, r.agent, r.mode, r.model, r.status, r.attempts, r.latency_ms, r.tokens_input,
           r.tokens_cached, r.tokens_output, r.tokens_reasoning, r.cost_usd, r.ladder_level,
           (r.second_review_of_id IS NOT NULL) AS second_review,
           (SELECT a.id FROM assessment a
             WHERE a.llm_review_id = COALESCE(r.second_review_of_id, r.id)
             ORDER BY a.assessed_at, a.id LIMIT 1) AS assessment_id,
           (SELECT count(*) FROM judge_reason jr WHERE jr.llm_review_id = r.id AND jr.status = 'accepted')::integer
             AS reasons_accepted,
           (SELECT count(*) FROM judge_reason jr WHERE jr.llm_review_id = r.id AND jr.status = 'rejected')::integer
             AS reasons_rejected
      FROM llm_review r
     WHERE (CAST(:agent AS text) IS NULL OR r.agent = CAST(:agent AS text))
       AND (CAST(:status AS text) IS NULL OR r.status = CAST(:status AS text))
       AND (CAST(:date_from AS timestamptz) IS NULL OR r.created_at >= CAST(:date_from AS timestamptz))
       AND (CAST(:date_to AS timestamptz) IS NULL OR r.created_at <= CAST(:date_to AS timestamptz))
       AND (CAST(:after_at AS timestamptz) IS NULL
            OR (r.created_at, r.id) < (CAST(:after_at AS timestamptz), CAST(:after_id AS uuid)))
     ORDER BY r.created_at DESC, r.id DESC
     LIMIT :limit
    """
)


@dataclass(frozen=True)
class LlmSetup:
    """Where the LLM calls go (D-084): the provider and, for Claude Code, the model of each role. No keys."""

    provider: str = "deepseek"
    judge_model: str | None = None  # Claude Code alias of the judge; None with DeepSeek (the database setting rules)
    analysts_model: str | None = None


@dataclass(frozen=True)
class RunCount:
    kind: str
    queued: int = 0
    running: int = 0
    succeeded: int = 0
    failed: int = 0


@dataclass(frozen=True)
class AgentStats:
    agent: str
    reviews: int
    by_status: dict[str, int]
    success_percent: str | None
    latency_avg_ms: int | None
    latency_p95_ms: int | None
    tokens_input: int
    tokens_output: int
    cost_usd: str
    provider: str
    model: str
    last_model: str | None
    spend_today_usd: str
    active: bool
    ladder_level: int | None


@dataclass(frozen=True)
class ReasonUse:
    code: str
    label: str
    accepted: int
    rejected: int


@dataclass(frozen=True)
class Summary:
    window: str
    since: datetime
    generated_at: datetime
    runs: list[RunCount]
    run_totals: dict[str, int]
    run_success_percent: str | None
    agents: list[AgentStats]
    top_reasons: list[ReasonUse]
    daily_budget_usd: str
    spend_today_usd: str
    ladder_level: int


@dataclass(frozen=True)
class AgentDay:
    agent: str
    reviews: int
    success_percent: str | None
    latency_avg_ms: int | None
    cost_usd: str


@dataclass(frozen=True)
class Day:
    day: date
    runs_succeeded: int
    runs_failed: int
    agents: list[AgentDay] = field(default_factory=list)


@dataclass(frozen=True)
class ReviewEntry:
    id: uuid.UUID
    created_at: datetime
    agent: str
    mode: str | None
    model: str
    status: str
    attempts: int
    latency_ms: int
    tokens_input: int
    tokens_cached: int
    tokens_output: int
    tokens_reasoning: int
    cost_usd: str
    ladder_level: int
    second_review: bool
    assessment_id: uuid.UUID | None
    reasons_accepted: int
    reasons_rejected: int


@dataclass(frozen=True)
class ReviewQuery:
    agent: str | None = None
    status: str | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None


def percent(part: int, whole: int) -> str | None:
    """`part` of `whole` as a percentage with one decimal ("95.0"), or None when there is nothing to divide."""
    if whole <= 0:
        return None
    return str((Decimal(part) * 100 / Decimal(whole)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def money(value: Any) -> str:
    """USD with six decimals, the precision `llm_review.cost_usd` keeps."""
    return str(Decimal(str(value or 0)).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP))


def _ms(value: Any) -> int | None:
    return None if value is None else int(Decimal(str(value)).quantize(Decimal(1), rounding=ROUND_HALF_UP))


def _start_of_day(now: datetime) -> datetime:
    return datetime.combine(now.astimezone(UTC).date(), datetime.min.time(), tzinfo=UTC)


def _settings(session: Session) -> dict[str, Any]:
    return {str(row[0]): row[1] for row in session.execute(_SETTINGS)}


def _budget(settings: dict[str, Any]) -> Decimal:
    try:
        return Decimal(str(settings.get("daily_budget_usd", DEFAULT_BUDGET)))
    except ArithmeticError:
        return DEFAULT_BUDGET


def _configured_model(agent: str, setup: LlmSetup, settings: dict[str, Any]) -> str:
    if setup.provider == "claude-code":
        return (setup.judge_model if agent == "judge" else setup.analysts_model) or ""
    return str(settings.get("judge_model" if agent == "judge" else "analyst_model", ""))


def _run_counts(session: Session, since: datetime) -> list[RunCount]:
    counts: dict[str, dict[str, int]] = {api: {} for api in RUN_KINDS.values()}
    for kind, status, runs in session.execute(_RUNS, {"since": since}):
        if kind in RUN_KINDS and status in RUN_STATUSES:
            bucket = counts[RUN_KINDS[kind]]
            bucket[status] = bucket.get(status, 0) + int(runs)
    return [RunCount(kind, **values) for kind, values in counts.items()]


def summary(session: Session, window: str, now: datetime, setup: LlmSetup) -> Summary:
    """Runs and reviews of the window, one card per agent, the reasons the judge used most and today's spend."""
    since = now - WINDOWS[window]
    runs = _run_counts(session, since)
    totals = {s: sum(getattr(r, s) for r in runs) for s in ("queued", "running", "succeeded", "failed")}
    by_agent: dict[str, dict[str, Any]] = defaultdict(lambda: {"status": {}, "ti": 0, "to": 0, "cost": Decimal(0)})
    for row in session.execute(_REVIEWS, {"since": since}):
        entry = by_agent[row.agent]
        entry["status"][row.status] = int(row.reviews)
        entry["ti"] += int(row.tokens_input)
        entry["to"] += int(row.tokens_output)
        entry["cost"] += Decimal(str(row.cost_usd))
    latency = {row.agent: (row.latency_avg, row.latency_p95) for row in session.execute(_LATENCY, {"since": since})}
    last_model: dict[str, str] = {str(row[0]): str(row[1]) for row in session.execute(_LAST_MODEL)}
    today = _start_of_day(now)
    spend = {agent: Decimal(str(cost)) for agent, cost in session.execute(_SPEND, {"t": today})}
    settings = _settings(session)
    budget = _budget(settings)
    spent_today = sum(spend.values(), Decimal(0))
    level, _ = current_level(session)
    agents: list[AgentStats] = []
    for agent in AGENTS:
        entry = by_agent[agent]
        statuses: dict[str, int] = entry["status"]
        ok = sum(n for s, n in statuses.items() if s in SUCCESS)
        bad = sum(n for s, n in statuses.items() if s in FAILURE)
        avg, p95 = latency.get(agent, (None, None))
        agents.append(
            AgentStats(
                agent=agent,
                reviews=sum(statuses.values()),
                by_status=dict(sorted(statuses.items())),
                success_percent=percent(ok, ok + bad),
                latency_avg_ms=_ms(avg),
                latency_p95_ms=_ms(p95),
                tokens_input=entry["ti"],
                tokens_output=entry["to"],
                cost_usd=money(entry["cost"]),
                provider=setup.provider,
                model=_configured_model(agent, setup, settings),
                last_model=last_model.get(agent),
                spend_today_usd=money(spend.get(agent, 0)),
                # The budget is shared by the three agents; the ladder only switches the judge off (L14).
                active=spent_today < budget and (agent != "judge" or level < LADDER_OFF),
                ladder_level=level if agent == "judge" else None,
            )
        )
    reasons = [
        ReasonUse(row.code, row.label, int(row.accepted), int(row.rejected))
        for row in session.execute(_REASONS, {"since": since, "limit": TOP_REASONS})
    ]
    return Summary(
        window=window,
        since=since,
        generated_at=now,
        runs=runs,
        run_totals=totals,
        run_success_percent=percent(totals["succeeded"], totals["succeeded"] + totals["failed"]),
        agents=agents,
        top_reasons=reasons,
        daily_budget_usd=money(budget),
        spend_today_usd=money(spent_today),
        ladder_level=level,
    )


def daily(session: Session, days: int, now: datetime) -> list[Day]:
    """One entry per UTC day, oldest first, today included; days without activity carry zeros."""
    first = now.astimezone(UTC).date() - timedelta(days=days - 1)
    since = datetime.combine(first, datetime.min.time(), tzinfo=UTC)
    runs = {row.day: (int(row.succeeded), int(row.failed)) for row in session.execute(_DAILY_RUNS, {"since": since})}
    reviews: dict[tuple[date, str], Any] = {
        (row.day, row.agent): row
        for row in session.execute(
            _DAILY_REVIEWS, {"since": since, "success": sorted(SUCCESS), "failure": sorted(FAILURE)}
        )
    }
    series: list[Day] = []
    for offset in range(days):
        day = first + timedelta(days=offset)
        succeeded, failed = runs.get(day, (0, 0))
        agents = []
        for agent in AGENTS:
            row = reviews.get((day, agent))
            agents.append(
                AgentDay(
                    agent=agent,
                    reviews=int(row.reviews) if row else 0,
                    success_percent=percent(int(row.succeeded), int(row.succeeded) + int(row.failed)) if row else None,
                    latency_avg_ms=_ms(row.latency_avg) if row else None,
                    cost_usd=money(row.cost_usd if row else 0),
                )
            )
        series.append(Day(day, succeeded, failed, agents))
    return series


def reviews_page(
    session: Session, query: ReviewQuery, *, after: ReviewKey | None, limit: int
) -> tuple[list[ReviewEntry], ReviewKey | None]:
    """The review log, newest first; the second value keys the next page."""
    rows = session.execute(
        _LOG,
        {
            "agent": query.agent,
            "status": query.status,
            "date_from": query.date_from,
            "date_to": query.date_to,
            "after_at": after[0] if after else None,
            "after_id": after[1] if after else None,
            "limit": limit + 1,
        },
    ).all()
    kept = rows[:limit]
    entries = [
        ReviewEntry(
            id=row.id,
            created_at=row.created_at,
            agent=row.agent,
            mode=row.mode,
            model=row.model,
            status=row.status,
            attempts=int(row.attempts),
            latency_ms=int(row.latency_ms),
            tokens_input=int(row.tokens_input),
            tokens_cached=int(row.tokens_cached),
            tokens_output=int(row.tokens_output),
            tokens_reasoning=int(row.tokens_reasoning),
            cost_usd=money(row.cost_usd),
            ladder_level=int(row.ladder_level),
            second_review=bool(row.second_review),
            assessment_id=row.assessment_id,
            reasons_accepted=int(row.reasons_accepted),
            reasons_rejected=int(row.reasons_rejected),
        )
        for row in kept
    ]
    next_key = (kept[-1].created_at, kept[-1].id) if len(rows) > limit else None
    return entries, next_key
