"""The pipeline cycles (docs/03 §2 triggers, COR-05, docs/15 F-04 to F-13, F-17).

* News (hourly, and once after each scan): ingestion → keyword filter → the news analyst on new relevant stories
  → `correlate_stories` → each group the news crossed is evaluated (trigger `news`), with the judge → tickets.
  Dismissal candidates go to the judge's mode 2.
* Scan (scheduled or requested): the vulnerability refresh first when a CPE mapping changed since the last one
  (F15.12, rehearsal 2 P2-B) → the simulated scan → `correlate_new_groups` on the groups it created or reopened
  → the CVE analyst on pending CVEs (F3.3, injected) → every group it changed is evaluated (trigger
  `new_finding`) → tickets; then an extra news cycle (`after_scan`).
* Nightly: recalculation of every open group **without the judge** (COR-05).

The cycles never overlap: each takes the pipeline lock and is skipped when another cycle holds it (the scan also
keeps its own lock). Every group is evaluated in its own session, so one failing group never stops the rest; no
transaction is open while a model answers (the analysts and the judge commit their read step first, F12.2 #105).
Events are written by the ticket lifecycle; the dispatcher delivers them on its own.

Scoring (`evaluate`, `recalculate`) and the package scorer of mode 2 (`dismissal_package`) come from F4.3: they are
injected seams, and without them the cycles still ingest, analyze and correlate and say that scoring is off.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Protocol

from sqlalchemy import exists, select
from sqlalchemy.orm import Session, sessionmaker

from core.correlation.engine import StoryOutcome, correlate_new_groups, correlate_stories
from core.db import models as m
from core.ingestion.embeddings import EmbeddingError
from core.judge.session import ToolCaller
from core.pipeline.judging import PipelineJudge, dismiss_story, judge_for
from core.pipeline.locks import cycle_lock
from core.scoring.queue import (
    claim_recalculation,
    has_running_recalculation,
    next_queued_recalculation,
    requeue_abandoned_recalculations,
)
from core.shutdown import ShutdownRequested

log = logging.getLogger("core.pipeline")

SCAN_EVALUATED_STATUSES: Final = ("new", "reopened", "fixed", "persistent")
SCAN_CORRELATED_STATUSES: Final = ("new", "reopened")
CATCH_UP: Final = timedelta(hours=72)  # how far back analysed stories with no trace of correlation are retried
# The scheduled refresh is skipped when a scan's refresh ended this recently (a scan queued at worker start runs first).
REFRESH_FRESH: Final = timedelta(hours=1)

# (session, group_id, run_id, trigger, judge or None) -> the stored assessment id, None when nothing changed.
Evaluator = Callable[[Session, uuid.UUID, uuid.UUID, str, PipelineJudge | None], uuid.UUID | None]
# (session, story_id) -> the dismissal package of that story (F4.3 scorer).
DismissalPackager = Callable[[Session, uuid.UUID], dict[str, Any]]


class TicketApplier(Protocol):
    """F5.2 `TicketLifecycle`."""

    def apply(self, session: Session, assessment_id: uuid.UUID) -> object: ...


@dataclass(frozen=True)
class NewsCycleOutput:
    """What the news step produced: the stories the analyst analyzed and the news run they belong to."""

    run_id: uuid.UUID | None
    analyzed: list[uuid.UUID]


@dataclass(frozen=True)
class ScanCycleOutput:
    run_id: uuid.UUID


@dataclass
class Steps:
    """The services the cycles chain; every one is injectable (tests use doubles, never real tokens)."""

    news: Callable[[Session, str], NewsCycleOutput] | None
    scan: Callable[[uuid.UUID | None, str], ScanCycleOutput] | None = None
    evaluate: Evaluator | None = None
    recalculate: Callable[[Session], object] | None = None
    recalculate_queued: Callable[[Session, uuid.UUID], object] | None = None
    dismissal_package: DismissalPackager | None = None
    judge_caller: ToolCaller | None = None
    tickets: TicketApplier | None = None
    # Vulnerability catalogue before scanning (NVD, KEV, EPSS); opens its own short transactions around downloads.
    refresh: Callable[[], object] | None = None
    analyze_cves: Callable[[Session], object] | None = None  # F3.3 CVE analyst on the CVEs of active groups
    correlate_news: Callable[[Session, list[uuid.UUID], datetime], list[StoryOutcome]] = correlate_stories
    correlate_groups: Callable[[Session, set[uuid.UUID], datetime], list[StoryOutcome]] = correlate_new_groups


# The worker wires the CVE analyst only with an LLM client, i.e. when DEEPSEEK_API_KEY is set.
CVE_ANALYST_OFF: Final = "CVE analyst is off (DEEPSEEK_API_KEY is not configured)"


@dataclass
class CycleReport:
    """What one cycle did (logged; also handy for tests and the admin CLI)."""

    cycle: str
    ran: bool = True
    run_id: uuid.UUID | None = None
    stories: int = 0
    groups: int = 0
    assessments: int = 0
    dismissals: int = 0
    failures: int = 0
    notes: list[str] = field(default_factory=list)


def _count_recalculation(report: CycleReport, result: object) -> None:
    """Copy the counts of a recalculation pass (F4.3 `RecalculationReport`: groups, assessments stored) into the log."""
    groups, changed = getattr(result, "groups", None), getattr(result, "changed", None)
    if isinstance(groups, int):
        report.groups = groups
    if isinstance(changed, int):
        report.assessments = changed


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class Pipeline:
    session_factory: sessionmaker[Session]
    steps: Steps
    clock: Callable[[], datetime] = utcnow
    # When the last vulnerability refresh this process completed started: a mapping saved after it is not in the
    # catalogue yet (CVE.org discovery reads the mappings), so the next scan refreshes first (P2-B).
    refreshed_at: datetime | None = None
    refresh_ended_at: datetime | None = None  # when that refresh ended: how recent the data is (`REFRESH_FRESH`)

    # --- cycles ---------------------------------------------------------------------------------------------
    def news_cycle(self, trigger_reason: str = "schedule") -> CycleReport:
        report = CycleReport("news")
        with cycle_lock(self.session_factory) as acquired:
            if not acquired:
                return self._skipped(report)
            self._news(report, trigger_reason)
        return report

    def scan_cycle(self, run_id: uuid.UUID | None = None, reason: str = "schedule") -> CycleReport:
        """Run a scan (a queued request when `run_id` is given), then correlate and evaluate what it changed."""
        report = CycleReport("scan")
        if self.steps.scan is None:
            report.ran = False
            report.notes.append("scan is not configured")
            return report
        with cycle_lock(self.session_factory) as acquired:
            if not acquired:
                return self._skipped(report)  # nothing ran: a queued request stays queued for the next tick
            self._refresh_for_mappings(report)
            output = self.steps.scan(run_id, reason)
            report.run_id = output.run_id
            changed, correlated = self._scan_groups(output.run_id)
            now = self.clock()
            with self.session_factory() as session:
                self.steps.correlate_groups(session, correlated, now)
            self._analyze_cves(report)
            report.groups = len(changed)
            self._evaluate(report, changed, output.run_id, "new_finding")
            self._news(CycleReport("news"), "after_scan")  # ING-02: an extra news run after each scan
        self._log(report)
        return report

    def refresh_cycle(self) -> CycleReport:
        """ESC-09: refresh the vulnerability catalogue the simulated scan crosses the inventory with."""
        report = CycleReport("refresh")
        if self.steps.refresh is None:
            report.ran = False
            report.notes.append("vulnerability refresh is not configured")
            return report
        ended = self.refresh_ended_at
        if ended is not None and self.clock() - ended < REFRESH_FRESH:
            report.ran = False
            report.notes.append(f"a scan refreshed the vulnerability data at {ended:%H:%M} UTC")
            self._log(report)
            return report
        with cycle_lock(self.session_factory) as acquired:
            if not acquired:
                return self._skipped(report)
            started = self.clock()
            self._mark_refresh(report, started, self.steps.refresh())
        self._log(report)
        return report

    def nightly_cycle(self) -> CycleReport:
        """F-17: recalculation of every open group with the formula and the clock; the judge is never called."""
        report = CycleReport("nightly")
        if self.steps.recalculate is None:
            report.ran = False
            report.notes.append("scoring is not wired yet (F4.3)")
            return report
        with cycle_lock(self.session_factory) as acquired:
            if not acquired:
                return self._skipped(report)
            with self.session_factory() as session:
                result = self.steps.recalculate(session)
                session.commit()
        _count_recalculation(report, result)
        self._log(report)
        return report

    def recalculation_requests_cycle(self) -> bool:
        """FRO-08: serve the oldest queued formula-change request (no judge, D-033). True when one ran."""
        if self.steps.recalculate_queued is None:
            return False
        with self.session_factory() as session:
            if next_queued_recalculation(session) is None and not has_running_recalculation(session):
                return False
        report = CycleReport("recalculation")
        with cycle_lock(self.session_factory) as acquired:
            if not acquired:
                self._skipped(report)  # the request stays queued for the next tick
                return False
            with self.session_factory() as session, session.begin():
                if requeue_abandoned_recalculations(session):
                    log.warning("requeued a recalculation left running by a stopped worker")
                run_id = next_queued_recalculation(session)
                if run_id is None:
                    return False
                report.run_id = run_id
                claimed = claim_recalculation(session, run_id, self.clock())
            if not claimed:
                return False
            with self.session_factory() as session:
                result = self.steps.recalculate_queued(session, run_id)  # commits per group; failure marks it failed
        _count_recalculation(report, result)
        self._log(report)
        return True

    # --- steps ----------------------------------------------------------------------------------------------
    def _refresh_for_mappings(self, report: CycleReport) -> None:
        """P2-B: the vulnerability refresh (NVD window, KEV, EPSS and CVE.org) runs before the scan when a CPE mapping
        (its CPE or its CNA names) was saved after the last refresh this process completed started, or when none has
        completed yet. At most once per change: a scan that follows sees the new mark and does not refresh again.
        A failed refresh leaves the scan with what is stored and the next scan tries again."""
        if self.steps.refresh is None:
            return
        with self.session_factory() as session:
            if not mapping_changed_since(session, self.refreshed_at):
                return
        started = self.clock()
        try:
            result = self.steps.refresh()
        except ShutdownRequested:
            raise
        except Exception:
            report.failures += 1
            report.notes.append("the vulnerability refresh before the scan failed; the scan uses the stored data")
            log.exception("the vulnerability refresh before the scan failed; the next scan tries again")
            return
        report.notes.append("vulnerability data refreshed first: a CPE mapping changed since the last refresh")
        self._mark_refresh(report, started, result)

    def _mark_refresh(self, report: CycleReport, started: datetime, result: object) -> None:
        """A complete refresh covers the mappings saved before it started. One that CVE.org could not finish (GitHub
        down, budget spent: `VulndataRefresh.complete`) leaves the mark where it was, so the next scan after a
        mapping change refreshes again."""
        if getattr(result, "complete", True):
            self.refreshed_at, self.refresh_ended_at = started, self.clock()
            return
        report.notes.append("CVE.org did not finish this refresh; the next scan refreshes again")

    def _news(self, report: CycleReport, trigger_reason: str) -> None:
        if self.steps.news is None:
            report.ran = False
            report.notes.append("news ingestion is not available (EMBEDDINGS_URL is not configured)")
            self._log(report)
            return
        try:
            with self.session_factory() as session:
                output = self.steps.news(session, trigger_reason)
                session.commit()
        except EmbeddingError as error:
            # Fail closed: the articles are already stored by the ingestion and wait ungrouped for the next cycle.
            report.failures += 1
            report.notes.append(f"news deduplication skipped: {error}")
            self._log(report)
            return
        report.run_id = output.run_id
        report.stories = len(output.analyzed)
        now = self.clock()
        with self.session_factory() as session:
            # Stories analysed in an earlier cycle that failed before correlating them are picked up here (F13.0 #73).
            stories = list(dict.fromkeys([*output.analyzed, *_uncorrelated_stories(session, now - CATCH_UP)]))
        if not stories:
            self._log(report)
            return
        with self.session_factory() as session:
            outcomes = self.steps.correlate_news(session, stories, now)
        groups = {placed.group_id for outcome in outcomes for placed in outcome.matches}
        report.groups = len(groups)
        if output.run_id is not None:
            self._evaluate(report, groups, output.run_id, "news")
        self._dismissals(report, [o.story_id for o in outcomes if o.dismissal_candidate])
        self._log(report)

    def _evaluate(self, report: CycleReport, groups: Iterable[uuid.UUID], run_id: uuid.UUID, trigger: str) -> None:
        evaluate = self.steps.evaluate
        if evaluate is None:
            report.notes.append("scoring is not wired yet (F4.3): groups were correlated but not evaluated")
            return
        for group_id in sorted(groups):
            try:
                with self.session_factory() as session:
                    judge = self._judge(session)
                    assessment_id = evaluate(session, group_id, run_id, trigger, judge)
                    if assessment_id is not None:
                        report.assessments += 1
                        if self.steps.tickets is not None:
                            self.steps.tickets.apply(session, assessment_id)
                    session.commit()
            except Exception:
                report.failures += 1
                log.exception("evaluating group %s failed; the next cycle retries it", group_id)

    def _analyze_cves(self, report: CycleReport) -> None:
        """F-04 step 8: the CVE analyst on pending CVEs (vector when CVSS is missing, conditions), before scoring."""
        if self.steps.analyze_cves is None:
            report.notes.append(CVE_ANALYST_OFF)
            return
        try:
            with self.session_factory() as session:
                self.steps.analyze_cves(session)
                session.commit()
        except Exception:
            report.failures += 1
            log.exception("the CVE analyst failed; groups are scored with what the CVE records hold")

    def _dismissals(self, report: CycleReport, story_ids: Sequence[uuid.UUID]) -> None:
        packager, caller = self.steps.dismissal_package, self.steps.judge_caller
        if not story_ids or packager is None or caller is None:
            return
        for story_id in story_ids:
            try:
                with self.session_factory() as session:
                    stored = dismiss_story(session, caller, packager(session, story_id), self.clock())
                    session.commit()
                report.dismissals += stored is not None
            except Exception:
                report.failures += 1
                log.exception("mode 2 on story %s failed; the next cycle retries it", story_id)

    def _judge(self, session: Session) -> PipelineJudge | None:
        caller = self.steps.judge_caller
        return judge_for(session, caller, self.clock()) if caller is not None else None

    def _scan_groups(self, run_id: uuid.UUID) -> tuple[set[uuid.UUID], set[uuid.UUID]]:
        """Groups the scan changed (to evaluate) and those it created or reopened (to correlate, COR-05)."""
        with self.session_factory() as session:
            rows = session.execute(
                select(m.Finding.finding_group_id, m.FindingStatusChange.status)
                .join(m.FindingStatusChange, m.FindingStatusChange.finding_id == m.Finding.id)
                .where(
                    m.FindingStatusChange.run_id == run_id,
                    m.FindingStatusChange.status.in_(SCAN_EVALUATED_STATUSES),
                )
            ).all()
        changed = {group_id for group_id, _ in rows}
        correlated = {group_id for group_id, status in rows if status in SCAN_CORRELATED_STATUSES}
        return changed, correlated

    @staticmethod
    def _skipped(report: CycleReport) -> CycleReport:
        report.ran = False
        report.notes.append("another pipeline cycle is running")
        log.info("%s cycle skipped: another pipeline cycle is running", report.cycle)
        return report

    @staticmethod
    def _log(report: CycleReport) -> None:
        log.info(
            "%s cycle: %d stories, %d groups, %d assessments, %d dismissals, %d failures%s",
            report.cycle,
            report.stories,
            report.groups,
            report.assessments,
            report.dismissals,
            report.failures,
            "".join(f"; {note}" for note in report.notes),
        )


def mapping_changed_since(session: Session, since: datetime | None) -> bool:
    """A CPE mapping saved after `since` (any mapping when `since` is None). Saving a mapping (`PUT /api/mappings`,
    `make itop-map-cpe`) stamps `mapped_at`, whether its CPE or its CNA names changed."""
    saved = select(m.CpeMapping.software_product_id)
    if since is not None:
        saved = saved.where(m.CpeMapping.mapped_at > since)
    return bool(session.scalar(select(exists(saved))))


def _uncorrelated_stories(session: Session, since: datetime) -> list[uuid.UUID]:
    """Stories analysed since `since` that left no trace of correlation: no correlation, no alert and no mode 2
    package. Correlation is idempotent, so a story that simply matched nothing is retried harmlessly until the window
    closes."""
    traces = (
        exists().where(m.Correlation.story_id == m.NewsAnalysis.story_id),
        exists().where(m.Alert.story_id == m.NewsAnalysis.story_id),
        exists().where(m.ReviewPackage.story_id == m.NewsAnalysis.story_id),
    )
    rows = session.scalars(
        select(m.NewsAnalysis.story_id)
        .where(m.NewsAnalysis.created_at >= since, *(~trace for trace in traces))
        .order_by(m.NewsAnalysis.created_at, m.NewsAnalysis.story_id)
    )
    return list(rows)
