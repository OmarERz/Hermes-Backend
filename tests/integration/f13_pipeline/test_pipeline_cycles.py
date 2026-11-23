"""Pipeline cycles chain the services, never overlap, and keep going when one group fails."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import pytest
from pipeline_support import NOW, judge_caller, make_story, one_reason_review
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from core.correlation.engine import Placed, StoryOutcome
from core.db import models as m
from core.pipeline.cycles import NewsCycleOutput, Pipeline, ScanCycleOutput, Steps
from core.pipeline.judging import JudgeFn
from core.pipeline.locks import cycle_lock
from doubles.llm import tool_call_completion
from harness.judge import dismissal_package, finding_package

pytestmark = pytest.mark.integration


@dataclass
class Recorder:
    """Fakes for the steps around the orchestration, recording how they were called."""

    run_id: uuid.UUID
    stories: list[uuid.UUID]
    outcomes: list[StoryOutcome] = field(default_factory=list)
    news_calls: list[str] = field(default_factory=list)
    evaluations: list[tuple[uuid.UUID, str, bool]] = field(default_factory=list)
    applied: list[uuid.UUID] = field(default_factory=list)
    correlated_groups: list[set[uuid.UUID]] = field(default_factory=list)
    verdicts: list[int | None] = field(default_factory=list)
    fail_group: uuid.UUID | None = None
    assessment_for: dict[uuid.UUID, uuid.UUID] = field(default_factory=dict)

    def news(self, _session: Session, reason: str) -> NewsCycleOutput:
        self.news_calls.append(reason)
        return NewsCycleOutput(self.run_id, list(self.stories) if reason == "schedule" else [])

    def correlate_news(self, _session: Session, story_ids: list[uuid.UUID], _now: datetime) -> list[StoryOutcome]:
        assert story_ids == self.stories
        return self.outcomes

    def correlate_groups(self, _session: Session, groups: set[uuid.UUID], _now: datetime) -> list[StoryOutcome]:
        self.correlated_groups.append(set(groups))
        return []

    def evaluate(
        self, _session: Session, group_id: uuid.UUID, run_id: uuid.UUID, trigger: str, judge: JudgeFn | None
    ) -> uuid.UUID | None:
        if group_id == self.fail_group:
            raise RuntimeError("broken group")
        self.evaluations.append((group_id, trigger, judge is not None))
        if judge is not None:
            self.verdicts.append(judge(finding_package(package_id=str(group_id))).adjustment)
        assert run_id == self.run_id
        return self.assessment_for.get(group_id)

    def apply(self, _session: Session, assessment_id: uuid.UUID) -> object:
        self.applied.append(assessment_id)
        return None


def groups(session: Session) -> list[uuid.UUID]:
    return list(session.scalars(select(m.FindingGroup.id).order_by(m.FindingGroup.id)))


def news_run(session: Session) -> uuid.UUID:
    run = m.Run(kind="news", status="succeeded", progress=100, trigger_reason="schedule", started_at=NOW)
    session.add(run)
    session.flush()
    return run.id


def test_a_news_cycle_analyzes_correlates_judges_and_applies_tickets(factory: sessionmaker[Session]) -> None:
    caller, double = judge_caller(*one_reason_review())
    with factory() as session, session.begin():
        group = groups(session)[0]
        run_id, story, candidate = news_run(session), make_story(session), make_story(session)
    assessment = uuid.uuid4()
    rec = Recorder(run_id, [story, candidate], assessment_for={group: assessment})
    rec.outcomes = [
        StoryOutcome(story, matches=[Placed(group, "cve_exact", "R1")]),
        StoryOutcome(candidate, dismissal_candidate=True),
    ]

    def packager(_session: Session, story_id: uuid.UUID) -> dict[str, Any]:
        content = dismissal_package(package_id=str(story_id))
        content["news"][0]["story_id"] = str(story_id)
        return content

    dismissal_caller, dismissal_double = judge_caller(
        tool_call_completion("dismiss_news", {"news_id": "N1", "reason": "No usamos OpenSSL 3."})
    )
    steps = Steps(news=rec.news, evaluate=rec.evaluate, judge_caller=caller, tickets=rec)
    steps.correlate_news = rec.correlate_news
    report = Pipeline(factory, steps, clock=lambda: NOW).news_cycle()
    assert (report.ran, report.stories, report.groups, report.assessments) == (True, 2, 1, 1)
    assert rec.evaluations == [(group, "news", True)]
    assert rec.verdicts == [10]
    assert rec.applied == [assessment]
    double.assert_calls(2)

    # mode 2 on the dismissal candidate, once the F4.3 packager is wired
    steps.judge_caller, steps.dismissal_package = dismissal_caller, packager
    rec.outcomes = [StoryOutcome(candidate, dismissal_candidate=True)]
    rec.evaluations.clear()
    report = Pipeline(factory, steps, clock=lambda: NOW).news_cycle()
    assert report.dismissals == 1
    dismissal_double.assert_calls(1)


def test_a_scan_cycle_correlates_new_groups_evaluates_changes_and_runs_news(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        scan_run = m.Run(kind="scan", status="succeeded", progress=100, trigger_reason="manual", started_at=NOW)
        session.add(scan_run)
        session.flush()
        findings = list(session.scalars(select(m.Finding).order_by(m.Finding.id)).all())
        session.add_all(
            [
                m.FindingStatusChange(
                    finding_id=findings[0].id, run_id=scan_run.id, status="new", observed_version="1", changed_at=NOW
                ),
                m.FindingStatusChange(
                    finding_id=findings[-1].id, run_id=scan_run.id, status="fixed", observed_version="2", changed_at=NOW
                ),
            ]
        )
        new_group, fixed_group = findings[0].finding_group_id, findings[-1].finding_group_id
    rec = Recorder(scan_run.id, [])
    scans: list[tuple[uuid.UUID | None, str]] = []

    def scan(run_id: uuid.UUID | None, reason: str) -> ScanCycleOutput:
        scans.append((run_id, reason))
        return ScanCycleOutput(scan_run.id)

    steps = Steps(news=rec.news, scan=scan, evaluate=rec.evaluate, tickets=rec)
    steps.correlate_groups = rec.correlate_groups
    queued = uuid.uuid4()
    report = Pipeline(factory, steps, clock=lambda: NOW).scan_cycle(queued, "manual")

    assert scans == [(queued, "manual")]
    assert rec.correlated_groups == [{new_group}]
    assert {(g, t) for g, t, _ in rec.evaluations} == {(new_group, "new_finding"), (fixed_group, "new_finding")}
    assert rec.news_calls == ["after_scan"]
    assert (report.run_id, report.groups) == (scan_run.id, len({new_group, fixed_group}))


def test_the_nightly_cycle_recalculates_without_the_judge(factory: sessionmaker[Session]) -> None:
    calls: list[Session] = []
    steps = Steps(news=lambda _s, _r: NewsCycleOutput(None, []), recalculate=calls.append)
    assert Pipeline(factory, steps).nightly_cycle().ran is True
    assert len(calls) == 1
    without = Pipeline(factory, Steps(news=lambda _s, _r: NewsCycleOutput(None, []))).nightly_cycle()
    assert (without.ran, without.notes) == (False, ["scoring is not wired yet (F4.3)"])


def test_cycles_never_overlap(factory: sessionmaker[Session]) -> None:
    calls: list[str] = []
    steps = Steps(news=lambda _s, reason: calls.append(reason) or NewsCycleOutput(None, []), recalculate=calls.append)
    pipeline = Pipeline(factory, steps)
    with cycle_lock(factory) as held:
        assert held
        assert pipeline.news_cycle().ran is False
        assert pipeline.nightly_cycle().ran is False
        scan = Steps(news=steps.news, scan=lambda _r, _q: calls.append("scan") or ScanCycleOutput(uuid.uuid4()))
        assert Pipeline(factory, scan).scan_cycle().ran is False  # the scan itself never starts
        refresh = Steps(news=steps.news, refresh=lambda: calls.append(None))
        assert Pipeline(factory, refresh).refresh_cycle().ran is False
    assert calls == []
    assert pipeline.news_cycle().ran is True


def test_without_scoring_the_cycle_still_correlates(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        group, run_id, story = groups(session)[0], news_run(session), make_story(session)
    rec = Recorder(run_id, [story], outcomes=[StoryOutcome(story, matches=[Placed(group, "cve_exact", "R1")])])
    steps = Steps(news=rec.news)
    steps.correlate_news = rec.correlate_news
    report = Pipeline(factory, steps).news_cycle()
    assert (report.groups, report.assessments) == (1, 0)
    assert report.notes == ["scoring is not wired yet (F4.3): groups were correlated but not evaluated"]
    assert Pipeline(factory, steps).scan_cycle().notes == ["scan is not configured"]


def test_a_failing_group_does_not_stop_the_others(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        first, second = groups(session)[0], uuid.uuid4()  # the evaluator is a fake: any id works
        run_id, story = news_run(session), make_story(session)
    rec = Recorder(run_id, [story], fail_group=first)
    rec.outcomes = [StoryOutcome(story, matches=[Placed(first, "cve_exact", "R1"), Placed(second, "cve_exact", "R1")])]
    steps = Steps(news=rec.news, evaluate=rec.evaluate)
    steps.correlate_news = rec.correlate_news
    report = Pipeline(factory, steps).news_cycle()
    assert report.failures == 1
    assert [g for g, _, _ in rec.evaluations] == [second]  # sorted order: whichever comes first, both are tried


def test_the_refresh_cycle_and_a_missing_news_step(factory: sessionmaker[Session]) -> None:
    refreshed: list[None] = []
    assert Pipeline(factory, Steps(news=None, refresh=lambda: refreshed.append(None))).refresh_cycle().ran is True
    assert len(refreshed) == 1
    assert Pipeline(factory, Steps(news=None)).refresh_cycle().notes == ["vulnerability refresh is not configured"]
    report = Pipeline(factory, Steps(news=None)).news_cycle()
    assert (report.ran, report.notes) == (False, ["news ingestion is not available (EMBEDDINGS_URL is not configured)"])


def test_the_scan_cycle_runs_the_cve_analyst_before_scoring(factory: sessionmaker[Session]) -> None:
    order: list[str] = []
    run_id = uuid.uuid4()
    steps = Steps(
        news=lambda _s, _r: NewsCycleOutput(None, []),
        scan=lambda _q, _r: ScanCycleOutput(run_id),
        analyze_cves=lambda _s: order.append("cves"),
    )
    steps.correlate_groups = lambda _s, _g, _n: order.append("correlate") or []
    report = Pipeline(factory, steps).scan_cycle()
    assert order == ["correlate", "cves"]
    assert "CVE analyst is not wired yet (F3.3)" not in report.notes

    def broken(_session: Session) -> None:
        raise RuntimeError("analyst down")

    steps.analyze_cves = broken
    assert Pipeline(factory, steps).scan_cycle().failures == 1
    steps.analyze_cves = None
    assert "CVE analyst is not wired yet (F3.3)" in Pipeline(factory, steps).scan_cycle().notes


def test_a_story_analysed_in_a_failed_cycle_is_correlated_by_the_next_one(factory: sessionmaker[Session]) -> None:
    """The analysis committed but correlation never ran; the next news cycle catches it up (pending F13.0 #73)."""
    with factory() as session, session.begin():
        run_id, missed, correlated = news_run(session), make_story(session), make_story(session)
        fields: dict[str, Any] = {
            "agent": "news_analyst", "model": "m", "response_model": {}, "prompt_version": "1", "prompt_hash": "h",
            "schema_version": "1", "schema_hash": "h", "parameters": {}, "input_ref": "r", "calls": [],
            "status": "applied", "attempts": 1, "tokens_input": 1, "tokens_cached": 0, "tokens_output": 1,
            "tokens_reasoning": 0, "cost_usd": 0, "latency_ms": 1, "ladder_level": 0, "created_at": NOW,
        }  # fmt: skip
        review, other = m.LlmReview(**fields), m.LlmReview(**fields)
        session.add_all([review, other])
        session.flush()
        for story, rid in ((missed, review.id), (correlated, other.id)):
            session.add(
                m.NewsAnalysis(
                    story_id=story, llm_review_id=rid, summary="s", event_type="other", output={}, created_at=NOW
                )
            )
        session.add(m.Alert(story_id=correlated, relevance="R2", status="open", created_at=NOW))  # already handled
    seen: list[list[uuid.UUID]] = []

    def correlate(_session: Session, story_ids: list[uuid.UUID], _now: datetime) -> list[StoryOutcome]:
        seen.append(list(story_ids))
        return []

    steps = Steps(news=lambda _s, _r: NewsCycleOutput(run_id, []))
    steps.correlate_news = correlate
    Pipeline(factory, steps, clock=lambda: NOW).news_cycle()
    assert seen == [[missed]]
