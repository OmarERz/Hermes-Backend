"""The pipeline with the real scoring (F4.3), judge service on the LLM double and ticket lifecycle (F5.2)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from pipeline_support import NOW, judge_caller
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from core.pipeline.cycles import NewsCycleOutput, Pipeline, ScanCycleOutput, Steps
from core.pipeline.wiring import engine_dismissal_package, engine_evaluate, engine_recalculate
from core.scoring import evaluate
from core.tickets.content import ItopIdentity
from core.tickets.lifecycle import TicketLifecycle
from doubles.llm import tool_call_completion

pytestmark = pytest.mark.integration


def finalize_only() -> dict[str, object]:
    return tool_call_completion("finalize_review", {"summary": "Sin motivos.", "mitigation_steps": []}, call_id="f")


def demo_group(session: Session) -> uuid.UUID:
    return session.scalars(select(m.FindingGroup.id).order_by(m.FindingGroup.created_at, m.FindingGroup.id)).first()


def scan_run(session: Session, statuses: str) -> uuid.UUID:
    """A finished scan that observed every finding of the demo group with the given status."""
    run = m.Run(kind="scan", status="succeeded", progress=100, trigger_reason="manual", started_at=NOW)
    session.add(run)
    session.flush()
    for finding in session.scalars(select(m.Finding).where(m.Finding.finding_group_id == demo_group(session))):
        session.add(
            m.FindingStatusChange(
                finding_id=finding.id, run_id=run.id, status=statuses, observed_version="3.0.2", changed_at=NOW
            )
        )
    session.flush()
    return run.id


def test_a_scan_cycle_scores_with_the_judge_and_opens_tickets(factory: sessionmaker[Session]) -> None:
    caller, double = judge_caller(finalize_only())
    with factory() as session, session.begin():
        run_id = scan_run(session, "new")
    news_calls: list[str] = []
    steps = Steps(
        news=lambda _s, reason: news_calls.append(reason) or NewsCycleOutput(None, []),
        scan=lambda _queued, _reason: ScanCycleOutput(run_id),
        evaluate=engine_evaluate,
        judge_caller=caller,
        tickets=TicketLifecycle(ItopIdentity("1", "5")),
    )
    steps.correlate_groups = lambda _s, _g, _n: []

    report = Pipeline(factory, steps, clock=lambda: NOW).scan_cycle()

    assert (report.groups, report.assessments, report.failures) == (1, 1, 0)
    assert news_calls == ["after_scan"]
    double.assert_calls(1)
    with factory() as session:
        group = demo_group(session)
        assessment = session.scalars(
            select(m.Assessment).where(m.Assessment.finding_group_id == group).order_by(m.Assessment.assessed_at.desc())
        ).first()
        assert assessment is not None
        assert assessment.llm_review_id is not None  # the judge's review stands behind the score
        tickets = session.scalars(select(m.Ticket).where(m.Ticket.finding_group_id == group)).all()
        assert tickets
        events = session.scalars(
            select(m.NotificationEvent).where(m.NotificationEvent.ticket_id.in_([t.id for t in tickets]))
        )
        assert {e.event_type for e in events} == {"new_ticket"}

    # the same scan again: no new assessment and no second judge call; the standing one reaches the ticket rules
    with factory() as session:
        before = session.scalar(select(func.count()).select_from(m.Assessment))
    report = Pipeline(factory, steps, clock=lambda: NOW).scan_cycle()
    assert (report.assessments, report.failures) == (1, 0)
    double.assert_calls(1)
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(m.Assessment)) == before


def test_a_fully_fixed_group_still_reaches_the_ticket_lifecycle(factory: sessionmaker[Session]) -> None:
    with factory() as session:
        session.begin()
        group = demo_group(session)
        latest = session.scalars(
            select(m.Assessment.id)
            .where(m.Assessment.finding_group_id == group)
            .order_by(m.Assessment.assessed_at.desc())
        ).first()
        run_id = scan_run(session, "fixed")
        assert engine_evaluate(session, group, run_id, "new_finding", None) == latest
        session.rollback()


def test_the_nightly_recalculation_and_the_dismissal_packager(factory: sessionmaker[Session]) -> None:
    with factory() as session:
        session.begin()
        report = engine_recalculate(None)(session)
        assert getattr(report, "groups", 0) >= 1
        with pytest.raises(LookupError):
            engine_dismissal_package(session, uuid.uuid4())  # a story without analysis has no package
        session.rollback()


def test_a_failed_nightly_recalculation_keeps_finished_groups_and_marks_the_run_failed(
    factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Per-group transactions (real commits): the group before the failure stays, the failing one is undone."""
    real = evaluate.evaluate_group
    marks = [datetime(2001, 1, 1, tzinfo=UTC), datetime(2001, 1, 2, tzinfo=UTC)]
    calls: list[uuid.UUID] = []

    def flaky(session: Session, group_id: uuid.UUID, *args: Any) -> Any:
        mark = marks[len(calls)]
        calls.append(group_id)
        session.add(m.Run(kind="nightly", status="succeeded", progress=100, trigger_reason="schedule", started_at=mark))
        session.flush()
        if len(calls) == len(marks):
            raise RuntimeError("boom")
        return real(session, group_id, *args)

    load = evaluate.load_active_groups

    def twice(session: Session, only: Any = None) -> Any:  # the seed has one open group: visit it twice
        return load(session, only=only) if only is not None else load(session) * 2

    monkeypatch.setattr("core.scoring.evaluate.load_active_groups", twice)
    monkeypatch.setattr("core.scoring.evaluate.evaluate_group", flaky)
    with factory() as session, pytest.raises(RuntimeError, match="boom"):
        engine_recalculate(None)(session)
    with factory() as other:
        stored = set(other.scalars(select(m.Run.started_at).where(m.Run.started_at.in_(marks))))
        failed = other.scalars(select(m.Run).where(m.Run.kind == "nightly", m.Run.status == "failed")).one()
    assert stored == {marks[0]}
    assert (failed.progress, failed.finished_at is not None) == (0, True)
