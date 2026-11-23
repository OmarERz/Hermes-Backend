"""The pipeline jobs of the worker (docs/03 §2): news every hour, queued scan requests, the scheduled scan, and the
nightly recalculation. Built from the configuration; what is not configured is left out (fail closed)."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy.orm import Session, sessionmaker

from core.config import Settings
from core.ingestion.embeddings import HttpEmbedder
from core.ingestion.fetcher import Fetcher
from core.itop.client import reader_from_settings
from core.llm import ClaudeCodeClient, LlmClient, LlmRequestError, RetryPolicy, ToolCaller
from core.llm.client import Role
from core.llm.stoppable import StoppableCaller, stoppable_runner
from core.pipeline.cycles import Pipeline, Steps
from core.pipeline.wiring import (
    cve_step,
    engine_dismissal_package,
    engine_evaluate,
    engine_recalculate,
    engine_recalculate_queued,
    inventory_refresh,
    news_step,
    refresh_vulndata,
    scan_step,
)
from core.scan.engine import ScanAlreadyRunningError, fail_stale_scans, next_queued_scan
from core.shutdown import StopSignal
from core.tickets.content import ItopIdentity
from core.tickets.lifecycle import TicketLifecycle
from core.vulndata.http import JsonSource
from core.vulndata.nvd import nvd_client

if TYPE_CHECKING:
    from workers.jobs import PeriodicJob

log = logging.getLogger("workers.pipeline")

NEWS_SECONDS = 3600.0  # D-010: news every hour
SCAN_REQUEST_SECONDS = 10.0  # POST /api/scans is picked up within seconds
RECALC_REQUEST_SECONDS = 10.0  # a saved formula is recalculated within seconds (FRO-08)
NIGHTLY_RECALC_SECONDS = 24 * 3600.0  # F-17
VULNDATA_SECONDS = 24 * 3600.0  # ESC-09: NVD recent publications, KEV and EPSS once a day (and at start)
INVENTORY_SECONDS = 6 * 3600.0  # ARQ-03


@dataclass
class QueuedScans:
    """Runs the oldest scan request (`POST /api/scans`) on its own run row; one per tick. A scan left `running` by a
    crashed worker is closed first (it would block every later scan, ARQ-04)."""

    pipeline: Pipeline
    session_factory: sessionmaker[Session]

    def __call__(self) -> bool:
        with self.session_factory() as session, session.begin():
            fail_stale_scans(session)
        with self.session_factory() as session:
            run_id = next_queued_scan(session)
        if run_id is None:
            return False
        try:
            self.pipeline.scan_cycle(run_id, "manual")
        except ScanAlreadyRunningError:
            log.info("scan request %s waits: a scan is already running", run_id)
            return False
        return True


def _embedder(settings: Settings, stop: StopSignal) -> HttpEmbedder | None:
    """News deduplication needs the embeddings service (ING-07, `docker/embeddings`); without it the cycle is off."""
    if settings.embeddings_url is None:
        log.error("EMBEDDINGS_URL is not configured: the news cycle is off")
        return None
    return HttpEmbedder(str(settings.embeddings_url), stop=stop)


def _llm(settings: Settings, role: str, stop: StopSignal) -> ToolCaller | None:
    """The LLM client of a role for the configured provider (D-084), or None (fail closed: that role is off).

    Every call checks the worker's stop signal first and the retry backoff sleeps on it; the Claude Code CLI is
    killed if the worker is asked to stop while it answers (#170).
    """
    llm_role: Role = "judge" if role == "judge" else "analysts"
    retry = RetryPolicy(sleep=stop.sleep)
    if settings.llm_provider == "claude-code":
        try:
            return StoppableCaller(
                ClaudeCodeClient.from_settings(settings, llm_role, retry=retry, runner=stoppable_runner(stop)), stop
            )
        except LlmRequestError as exc:
            reason = str(exc)
        # Inside the containers the CLI is never there: claude-code is for a worker on the host (make worker-host).
        log.error("LLM_PROVIDER=claude-code but %s: the %s is off", reason, llm_role)
        return None
    if settings.deepseek_api_key is None:
        return None
    return StoppableCaller(LlmClient.from_settings(settings, llm_role, retry=retry), stop)


def _tickets(settings: Settings) -> TicketLifecycle | None:
    if settings.itop_org_id is None or settings.itop_caller_id is None:
        log.info("ITOP_ORG_ID / ITOP_CALLER_ID are not configured: assessments do not open tickets")
        return None
    identity = ItopIdentity(settings.itop_org_id, settings.itop_caller_id, settings.itop_service_id)
    return TicketLifecycle(identity, itop_base_url=str(settings.itop_url) if settings.itop_url else None)


def build_pipeline(
    settings: Settings, session_factory: sessionmaker[Session], stop: StopSignal | None = None
) -> Pipeline:
    """The pipeline with the production services (F1 to F6, scoring of F4.3, tickets of F5).

    `stop` is the worker's shutdown signal: every client that waits on the network checks it (#170).
    """
    stop = stop or StopSignal()
    reader = reader_from_settings(settings) if settings.itop_url and settings.itop_token else None
    tickets = _tickets(settings)
    analyst = _llm(settings, "analysts", stop)
    fetcher = Fetcher(stop=stop)
    embedder = _embedder(settings, stop)
    steps = Steps(
        news=news_step(fetcher, embedder, analyst) if embedder is not None else None,
        analyze_cves=cve_step(analyst, Fetcher(stop=stop)) if analyst is not None else None,
        refresh=refresh_vulndata(session_factory, nvd_client(settings.nvd_api_key, stop=stop), JsonSource(stop=stop)),
        scan=scan_step(session_factory, reader),
        evaluate=engine_evaluate,
        recalculate=engine_recalculate(tickets),
        recalculate_queued=engine_recalculate_queued(tickets),
        dismissal_package=engine_dismissal_package,
        judge_caller=_llm(settings, "judge", stop),
        tickets=tickets,
    )
    return Pipeline(session_factory, steps)


def pipeline_jobs(
    settings: Settings,
    session_factory: sessionmaker[Session],
    job: Callable[[str, float, Callable[[], object]], PeriodicJob],
    stop: StopSignal | None = None,
) -> list[PeriodicJob]:
    pipeline = build_pipeline(settings, session_factory, stop)
    jobs = [
        job("news_cycle", NEWS_SECONDS, pipeline.news_cycle),
        job("scan_requests", SCAN_REQUEST_SECONDS, QueuedScans(pipeline, session_factory)),
        job("recalculation_requests", RECALC_REQUEST_SECONDS, pipeline.recalculation_requests_cycle),
        job("nightly_recalculation", NIGHTLY_RECALC_SECONDS, pipeline.nightly_cycle),
        job("vulndata_refresh", VULNDATA_SECONDS, pipeline.refresh_cycle),
    ]
    if settings.scan_interval_hours:
        jobs.append(job("scheduled_scan", settings.scan_interval_hours * 3600.0, pipeline.scan_cycle))
    if settings.itop_url is not None and settings.itop_token is not None:
        jobs.append(
            job(
                "inventory_refresh",
                INVENTORY_SECONDS,
                inventory_refresh(session_factory, reader_from_settings(settings)),
            )
        )
    return jobs
