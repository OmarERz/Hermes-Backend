"""End-to-end smoke scenario (F5.3): assessment → tickets in iTop → events delivered → feedback → silence."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

import pytest
from f05data import T0
from f05scenario import Scenario
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from core.feedback.service import FeedbackRejectedError, SqlFeedbackService
from core.itop.outbox import ItopOutboxWorker, build_writer
from core.notifications.dispatcher import NotificationDispatcher
from core.tickets.content import ItopIdentity
from core.tickets.lifecycle import TicketLifecycle
from doubles.itop import ItopDouble
from notifications_api import FeedbackInput, NotificationEvent

pytestmark = pytest.mark.integration
ITOP = "https://itop.example.test"


@dataclass
class Clock:
    now: datetime = T0

    def __call__(self) -> datetime:
        return self.now


@dataclass
class FlakyConsumer:
    failures: int = 1
    received: list[NotificationEvent] = field(default_factory=list)

    def process(self, event: NotificationEvent) -> None:
        if self.failures:
            self.failures -= 1
            raise ConnectionError("slack unavailable")
        self.received.append(event)


def feedback(assessment_id: str, email: str, verdict: str) -> FeedbackInput:
    return FeedbackInput(
        assessment_id=assessment_id,
        user_email=email,
        channel="slack",
        verdict=verdict,
        proposed_level=None,
        proposed_score=None,
        comment=None,
    )


def test_tickets_events_and_feedback_end_to_end(factory: sessionmaker[Session]) -> None:
    clock, double, consumer = Clock(), ItopDouble(), FlakyConsumer()
    lifecycle = TicketLifecycle(ItopIdentity("1", "5", "7"), itop_base_url=ITOP, clock=clock)
    with factory() as session, session.begin():
        session.execute(text("UPDATE team SET is_default = false WHERE is_default"))
        sc = Scenario(session)
        ops, data = sc.team("Platform Ops"), sc.team("Data Custody")
        sc.ci("web-01", ops, sc.person("Ana Rivera"))
        sc.ci("db-01", data, sc.person("Luis Soto"))
        first = sc.assess({"web-01": 92, "db-01": 55}, sc.scan({"web-01": "new", "db-01": "new"}))
        lifecycle.apply(session, first.id)
        analyst = m.AppUser(
            firebase_uid=f"a-{sc.product}",
            email=f"a-{sc.product}@example.test",
            role="analyst",
            active=True,
            created_at=T0,
        )
        session.add(analyst)
        group_id, first_id, email = sc.group.id, str(first.id), analyst.email
        formula_id, factors = first.formula_version_id, (first.factor_s, first.factor_p, first.factor_t)
        first_assessment_id = first.id

    # 1. The outbox creates both tickets in iTop; the dispatcher delivers both events (immediate first) after a retry.
    writer = build_writer("http://localhost", str(double.token), http=double.client())
    assert ItopOutboxWorker(factory, writer, clock=clock).drain() == 2
    dispatcher = NotificationDispatcher(factory, consumer, itop_base_url=ITOP, clock=clock)
    dispatcher.drain()
    clock.now += timedelta(minutes=1)
    dispatcher.drain()
    # The immediate one went first, failed, and was delivered on its retry a minute later.
    assert [(e.type, e.priority) for e in consumer.received] == [("new_ticket", "normal"), ("new_ticket", "immediate")]
    assert all(e.ticket and e.ticket.itop_id and e.ticket.url.startswith(ITOP) for e in consumer.received)
    assert {r["team_id"] for r in double.data["UserRequest"].values()} == {ops.itop_team_id, data.itop_team_id}

    # 2. Feedback from an unauthorized address is rejected; a false positive from an analyst is accepted.
    service = SqlFeedbackService(factory, clock=clock)
    with pytest.raises(FeedbackRejectedError):
        service.record(feedback(first_id, "intruder@example.test", "false_positive"))
    assert service.record(feedback(first_id, email, "false_positive")).replaced_previous is False

    # 3. The suppressed fingerprint emits no new event, even when its score rises.
    with factory() as session, session.begin():
        for ticket in session.scalars(select(m.Ticket).where(m.Ticket.finding_group_id == group_id)):
            ticket.current_urgency = 1 if ticket.custodian_team_id == ops.id else 3
        later = m.Run(kind="news", status="succeeded", progress=100, trigger_reason="schedule")
        session.add(later)
        session.flush()
        assets = session.scalars(
            select(m.AssetScore.asset_id).where(m.AssetScore.assessment_id == first_assessment_id)
        ).all()
        raised = m.Assessment(
            finding_group_id=group_id,
            run_id=later.id,
            formula_version_id=formula_id,
            trigger="news",
            factor_s=factors[0],
            factor_p=factors[1],
            factor_t=factors[2],
            judge_adjustment=0,
            assessed_at=clock.now,
        )
        session.add(raised)
        session.flush()
        for asset_id in assets:
            snap = session.get_one(m.Asset, asset_id)
            session.add(
                m.AssetScore(
                    assessment_id=raised.id,
                    asset_id=asset_id,
                    factor_a=1,
                    factor_d=1,
                    version_factor=1,
                    base=95,
                    ci_adjustment=0,
                    final=95,
                    snap_criticality=snap.criticality,
                    snap_confidentiality=snap.confidentiality,
                )
            )
        session.flush()
        events_before = session.scalar(select(func.count()).select_from(m.NotificationEvent))
        lifecycle.apply(session, raised.id)
        assert session.scalar(select(func.count()).select_from(m.NotificationEvent)) == events_before
