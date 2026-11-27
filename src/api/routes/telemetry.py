"""Agent telemetry and the history timeline (D-088, F18.1): read-only views of runs, LLM reviews and changes."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Query, Request

from api.pagination import PAGINATED_RESPONSES, Page, PageQuery, Signer, decode_key, encode_key
from api.routes._auth import guard
from api.routes._db import SessionDep
from api.routes.models import (
    AgentDay,
    AgentTelemetry,
    HistoryEvent,
    HistoryFilters,
    LlmReviewEntry,
    LlmReviewFilters,
    ReasonUsage,
    RunCounts,
    TelemetryDaily,
    TelemetryDay,
    TelemetrySummary,
    TelemetryWindow,
)
from core.views import telemetry, timeline
from core.views.common import iso

router = APIRouter(tags=["telemetry"])
MAX_DAYS: Final = 90


def get_llm_setup(request: Request) -> telemetry.LlmSetup:
    setup: telemetry.LlmSetup = getattr(request.app.state, "llm_setup", telemetry.LlmSetup())
    return setup


LlmSetupDep = Annotated[telemetry.LlmSetup, Depends(get_llm_setup)]


def parse_moment(value: str | None) -> datetime | None:
    """An RFC 3339 filter already checked by its model (`DateTimeString`)."""
    return datetime.fromisoformat(value.upper()) if value else None


@router.get("/api/telemetry/summary", dependencies=[guard("GET", "/api/telemetry/summary")])
def telemetry_summary(session: SessionDep, setup: LlmSetupDep, window: TelemetryWindow = "24h") -> TelemetrySummary:
    """Runs and LLM reviews of the window, one card per agent, the judge reasons used most and today's spend."""
    found = telemetry.summary(session, window, datetime.now(UTC), setup)
    return TelemetrySummary(
        window=window,
        since=iso(found.since),
        generated_at=iso(found.generated_at),
        runs=[RunCounts.model_validate(vars(r)) for r in found.runs],
        runs_queued=found.run_totals["queued"],
        runs_running=found.run_totals["running"],
        runs_succeeded=found.run_totals["succeeded"],
        runs_failed=found.run_totals["failed"],
        run_success_percent=found.run_success_percent,
        agents=[AgentTelemetry.model_validate(vars(a)) for a in found.agents],
        top_reasons=[ReasonUsage.model_validate(vars(r)) for r in found.top_reasons],
        daily_budget_usd=found.daily_budget_usd,
        spend_today_usd=found.spend_today_usd,
        ladder_level=found.ladder_level,
        ladder_label=telemetry.LADDER_LABELS.get(found.ladder_level, ""),
    )


@router.get("/api/telemetry/daily", dependencies=[guard("GET", "/api/telemetry/daily")])
def telemetry_daily(
    session: SessionDep, days: Annotated[int, Query(ge=1, le=MAX_DAYS, description="Days back")] = 7
) -> TelemetryDaily:
    """Daily series, oldest first and with zeros on quiet days: runs finished and LLM reviews per agent."""
    series = telemetry.daily(session, days, datetime.now(UTC))
    return TelemetryDaily(
        days=days,
        series=[
            TelemetryDay(
                date=d.day.isoformat(),
                runs_succeeded=d.runs_succeeded,
                runs_failed=d.runs_failed,
                agents=[AgentDay.model_validate(vars(a)) for a in d.agents],
            )
            for d in series
        ],
    )


@router.get(
    "/api/telemetry/reviews", dependencies=[guard("GET", "/api/telemetry/reviews")], responses=PAGINATED_RESPONSES
)
def llm_reviews(
    params: PageQuery, signer: Signer, session: SessionDep, filters: Annotated[LlmReviewFilters, Query()]
) -> Page[LlmReviewEntry]:
    """The LLM review log, newest first: metadata only, never prompts, raw calls or news text (X-2, SEG-02)."""
    key = decode_key(params, "llm_reviews", ("time", "uuid"))
    found, next_key = telemetry.reviews_page(
        session,
        telemetry.ReviewQuery(
            agent=filters.agent,
            status=filters.status,
            date_from=parse_moment(filters.date_from),
            date_to=parse_moment(filters.date_to),
        ),
        after=None if key is None else (key[0], key[1]),
        limit=params.limit,
    )
    return Page[LlmReviewEntry](
        items=[
            LlmReviewEntry.model_validate(
                {
                    **vars(r),
                    "id": str(r.id),
                    "created_at": iso(r.created_at),
                    "assessment_id": str(r.assessment_id) if r.assessment_id else None,
                }
            )
            for r in found
        ],
        next_cursor=encode_key(signer, "llm_reviews", next_key),
    )


@router.get("/api/history", dependencies=[guard("GET", "/api/history")], responses=PAGINATED_RESPONSES)
def history(
    params: PageQuery, signer: Signer, session: SessionDep, filters: Annotated[HistoryFilters, Query()]
) -> Page[HistoryEvent]:
    """One timeline of runs, LLM reviews and configuration changes, newest first (HI-1). Reviews carry the
    assessment they fed (HI-8); configuration changes carry the version and its author (HI-10)."""
    key = decode_key(params, "history", ("time", "uuid"))
    found, next_key = timeline.events(
        session,
        timeline.Query(
            type=filters.type,
            status=filters.status,
            date_from=parse_moment(filters.date_from),
            date_to=parse_moment(filters.date_to),
        ),
        after=None if key is None else (key[0], key[1]),
        limit=params.limit,
    )
    return Page[HistoryEvent](
        items=[
            HistoryEvent.model_validate(
                {
                    **vars(e),
                    "id": str(e.id),
                    "at": iso(e.at),
                    "assessment_id": str(e.assessment_id) if e.assessment_id else None,
                }
            )
            for e in found
        ],
        next_cursor=encode_key(signer, "history", next_key),
    )
