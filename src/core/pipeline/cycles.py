"""The pipeline cycles (docs/03 §2 triggers, COR-05, docs/15 F-04 to F-13, F-17).

* News (hourly, and once after each scan): ingestion → keyword filter → the news analyst on new relevant stories
  → `correlate_stories` → each group the news crossed is evaluated (trigger `news`), with the judge → tickets.
  Dismissal candidates go to the judge's mode 2.
* Scan (scheduled or requested): the simulated scan → `correlate_new_groups` on the groups it created or reopened
  → the CVE analyst on pending CVEs (F3.3, injected) → every group it changed is evaluated (trigger
  `new_finding`) → tickets; then an extra news cycle (`after_scan`).
* Nightly: recalculation of every open group **without the judge** (COR-05).

The cycles never overlap: each takes the pipeline lock and is skipped when another cycle holds it (the scan also
keeps its own lock). Every group is evaluated in its own transaction, so one failing group never stops the rest.
Events are written by the ticket lifecycle; the dispatcher delivers them on its own.

Scoring (`evaluate`, `recalculate`) and the package scorer of mode 2 (`dismissal_package`) come from F4.3: they are
injected seams, and without them the cycles still ingest, analyze and correlate and say that scoring is off.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from core.correlation.engine import StoryOutcome, correlate_new_groups, correlate_stories
from core.db import models as m
from core.judge.session import ToolCaller
from core.pipeline.judging import JudgeFn, dismiss_story, judge_for
from core.pipeline.locks import cycle_lock

log = logging.getLogger("core.pipeline")

SCAN_EVALUATED_STATUSES: Final = ("new", "reopened", "fixed", "persistent")
SCAN_CORRELATED_STATUSES: Final = ("new", "reopened")

# (session, group_id, run_id, trigger, judge or None) -> the stored assessment id, None when nothing changed.
Evaluator = Callable[[Session, uuid.UUID, uuid.UUID, str, JudgeFn | None], uuid.UUID | None]
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
    dismissal_package: DismissalPackager | None = None
    judge_caller: ToolCaller | None = None
    tickets: TicketApplier | None = None
    # Vulnerability catalogue before scanning (NVD, KEV, EPSS); opens its own short transactions around downloads.
    refresh: Callable[[], object] | None = None
    analyze_cves: Callable[[Session], object] | None = None  # F3.3 CVE analyst on the CVEs of active groups
    correlate_news: Callable[[Session, list[uuid.UUID], datetime], list[StoryOutcome]] = correlate_stories
    correlate_groups: Callable[[Session, set[uuid.UUID], datetime], list[StoryOutcome]] = correlate_new_groups


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


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class Pipeline:
    session_factory: sessionmaker[Session]
    steps: Steps
    clock: Callable[[], datetime] = utcnow

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
        with cycle_lock(self.session_factory) as acquired:
            if not acquired:
                return self._skipped(report)
            self.steps.refresh()
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
                self.steps.recalculate(session)
                session.commit()
        self._log(report)
        return report

    # --- steps ----------------------------------------------------------------------------------------------
    def _news(self, report: CycleReport, trigger_reason: str) -> None:
        if self.steps.news is None:
            report.ran = False
            report.notes.append("news ingestion is not available (embeddings extra not installed)")
            self._log(report)
            return
        with self.session_factory() as session:
            output = self.steps.news(session, trigger_reason)
            session.commit()
        report.run_id = output.run_id
        report.stories = len(output.analyzed)
        if not output.analyzed:
            self._log(report)
            return
        now = self.clock()
        with self.session_factory() as session:
            outcomes = self.steps.correlate_news(session, output.analyzed, now)
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
            report.notes.append("CVE analyst is not wired yet (F3.3)")
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

    def _judge(self, session: Session) -> JudgeFn | None:
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
