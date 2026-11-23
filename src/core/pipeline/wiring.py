"""Production steps of the pipeline (what the worker runs): the services of F1 to F6 behind the `Steps` seams.

Each builder fails closed: without the DeepSeek key there is no analyst and no judge (the cycles still ingest,
correlate and fall back to the base score); without the iTop identity there is no ticket lifecycle. Scoring is
F4.3 (`evaluate_group`, `recalculate_open_groups`, `EngineScorer`).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import astuple
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from core.analysts.news import NewsResult, analyze_pending
from core.correlation.packages import build_dismissal_package
from core.db import models as m
from core.ingestion.embeddings import EmbedFn
from core.ingestion.fetcher import Fetcher
from core.ingestion.pipeline import PipelineOptions, run_news_pipeline
from core.itop.client import ItopReader
from core.llm import LlmClient
from core.pipeline.cycles import NewsCycleOutput, ScanCycleOutput, TicketApplier
from core.pipeline.judging import JudgeFn
from core.scan.engine import ScanOptions, run_scan
from core.scoring.evaluate import (
    EngineScorer,
    EvaluationOptions,
    GroupNotActiveError,
    JudgeVerdict,
    evaluate_group,
    recalculate_open_groups,
)
from core.scoring.formula_repo import load_active_formula


def news_step(fetcher: Fetcher, embed: EmbedFn, analyst: LlmClient | None) -> Callable[[Session, str], NewsCycleOutput]:
    """F-05 + F-06: ingestion, deduplication, keyword filter, source health, then the analyst on pending stories."""

    def run(session: Session, trigger_reason: str) -> NewsCycleOutput:
        analyze = (lambda db: analyze_pending(db, analyst)) if analyst is not None else None
        result = run_news_pipeline(
            session, fetcher, embed, PipelineOptions(trigger_reason=trigger_reason, analyze=analyze)
        )
        run_id = session.scalar(
            select(m.Run.id).where(m.Run.kind == "news").order_by(m.Run.started_at.desc(), m.Run.id.desc()).limit(1)
        )
        analyzed = [r.story_id for r in result.analyses if isinstance(r, NewsResult) and r.status == "analyzed"]
        return NewsCycleOutput(run_id, analyzed)

    return run


def scan_step(
    factory: sessionmaker[Session], reader: ItopReader | None
) -> Callable[[uuid.UUID | None, str], ScanCycleOutput]:
    """F-02 + F-04: inventory refresh from iTop (when configured) and the simulated scan, on a queued run if given."""

    def run(run_id: uuid.UUID | None, reason: str) -> ScanCycleOutput:
        result = run_scan(factory, ScanOptions(reason=reason, run_id=run_id, reader=reader))
        return ScanCycleOutput(result.run_id)

    return run


def engine_evaluate(
    session: Session, group_id: uuid.UUID, run_id: uuid.UUID, trigger: str, judge: JudgeFn | None
) -> uuid.UUID | None:
    """F4.3 `evaluate_group` with the pipeline's judge; the assessment to apply tickets with, if any.

    A group with no current finding left (every CI fixed) is not assessed again: its latest assessment is returned
    so the ticket lifecycle still reports the fixes (comment and `fixed` event, TIC-05).
    """
    verdicts = (lambda package: JudgeVerdict(*astuple(judge(package)))) if judge is not None else None
    try:
        return evaluate_group(session, group_id, run_id, trigger, EvaluationOptions(judge=verdicts)).assessment_id
    except GroupNotActiveError:
        return session.scalar(
            select(m.Assessment.id)
            .where(m.Assessment.finding_group_id == group_id)
            .order_by(m.Assessment.assessed_at.desc(), m.Assessment.id.desc())
            .limit(1)
        )


def engine_recalculate(tickets: TicketApplier | None) -> Callable[[Session], object]:
    """F-17 / COR-05: every open group with the formula and the clock, never the judge; tickets follow the scores."""

    def run(session: Session) -> object:
        return recalculate_open_groups(session, "nightly", EvaluationOptions(tickets=tickets), commit=False)

    return run


def engine_dismissal_package(session: Session, story_id: uuid.UUID) -> dict[str, Any]:
    """The mode 2 package of a dismissal candidate, scored with the active formula (F4.3 `EngineScorer`)."""
    _, formula = load_active_formula(session)
    return build_dismissal_package(session, story_id, EngineScorer(formula))
