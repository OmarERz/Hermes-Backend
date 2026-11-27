"""The Slack service end to end against PostgreSQL (F11 acceptance): real backend events reach the right channel, an
immediate one within a minute (simulated clock), and a click ends in the real `SqlFeedbackService`."""

from __future__ import annotations

import sys
import uuid
from collections.abc import Callable, Iterator
from concurrent.futures import Executor, Future
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from slack_bolt.request import BoltRequest
from sqlalchemy import Engine, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from core.db.session import make_engine
from core.feedback.service import SqlFeedbackService
from core.notifications.dispatcher import waiting_immediate_events
from core.tickets.content import ItopIdentity
from core.tickets.lifecycle import TicketLifecycle
from doubles.slack_web import FakeWebClient
from notifications_slack import render
from notifications_slack.module import build_module
from notifications_slack.settings import SlackSettings
from notifications_slack.sql_store import SqlSlackStore
from slack_app.service import DISPATCH_SECONDS, SlackDispatchJob

# The ticket scenario helpers of F5 (they import each other by bare name).
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "f05_tickets"))
from f05data import T0
from f05scenario import Scenario, formula_version

pytestmark = pytest.mark.integration
TEAM, DEFAULT, URGENT = "C0OPSTEAM1", "C0DEFAULT1", "C0URGENT01"
ANALYST, READER = "U0ANALYST1", "U0READER01"


class Immediate(Executor):
    def submit(self, fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Future[Any]:
        future: Future[Any] = Future()
        try:
            future.set_result(fn(*args, **kwargs))
        except BaseException as exc:  # noqa: BLE001 - handed to the future, like a thread pool
            future.set_exception(exc)
        return future


@pytest.fixture
def admin(slack_db: Any) -> Iterator[sessionmaker[Session]]:
    """Superuser sessions to build the scenario (the service itself connects as app and slack_module)."""
    engine = make_engine(slack_db.superuser_url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE notification_event SET status = 'delivered', delivered_at = now(), next_attempt_at = NULL"
                " WHERE status = 'pending'"  # each test starts with an empty outbox
            )
        )
    try:
        yield sessionmaker(engine, expire_on_commit=False)
    finally:
        engine.dispose()


@pytest.fixture
def app_factory(slack_db: Any) -> Iterator[sessionmaker[Session]]:
    engine = make_engine(slack_db.app_url)
    try:
        yield sessionmaker(engine, expire_on_commit=False)
    finally:
        engine.dispose()


def set_consumer(admin: sessionmaker[Session], name: str) -> None:
    with admin() as session, session.begin():
        formula_version(session)  # seeds the parameter catalog once per database
        version = session.scalar(
            select(func.coalesce(func.max(m.SettingValue.version), 0)).where(
                m.SettingValue.setting_key == "notifications.consumer"
            )
        )
        session.add(
            m.SettingValue(
                setting_key="notifications.consumer", version=version + 1, value=name, origin="frontend", changed_at=T0
            )
        )


def ticket_event(admin: sessionmaker[Session], score: int) -> dict[str, Any]:
    """A real new_ticket event: an assessment applied by the ticket lifecycle, as the pipeline does."""
    with admin() as session, session.begin():
        session.execute(text("UPDATE team SET is_default = false WHERE is_default"))
        sc = Scenario(session)
        ops = sc.team(f"Ops {uuid.uuid4().hex[:4]}")
        sc.ci("web-01", ops)
        assessment = sc.assess({"web-01": score}, sc.scan({"web-01": "new"}))
        TicketLifecycle(ItopIdentity("1", "5"), clock=lambda: T0).apply(session, assessment.id)
        users = {}
        for role in ("analyst", "reader"):
            user = m.AppUser(
                firebase_uid=f"{role}-{sc.product}",
                email=f"{role}-{sc.product}@example.test",
                role=role,
                active=True,
                created_at=T0,
            )
            session.add(user)
            users[role] = user.email
        event = session.scalars(
            select(m.NotificationEvent).where(m.NotificationEvent.assessment_id == assessment.id)
        ).one()
        return {"event_id": event.id, "assessment_id": str(assessment.id), "team": ops.name, "emails": users}


class Service:
    def __init__(self, app_factory: sessionmaker[Session], slack_engine: Engine, case: dict[str, Any]) -> None:
        self.client = FakeWebClient(emails={ANALYST: case["emails"]["analyst"], READER: case["emails"]["reader"]})
        settings = SlackSettings(  # type: ignore[call-arg]
            _env_file=None,
            _secrets_dir=None,
            channel_map={case["team"]: TEAM},
            default_channel=DEFAULT,
            urgent_channel=URGENT,
        )
        feedback = SqlFeedbackService(app_factory, clock=lambda: T0)
        self.now = T0
        self.module = build_module(
            settings,
            feedback,
            SqlSlackStore(slack_engine),
            client=self.client,
            clock=lambda: self.now,
            listener_executor=Immediate(),
        )
        self.job = SlackDispatchJob(
            app_factory, self.module.consumer, "https://itop.example.test", clock=lambda: self.now
        )

    def click(self, user: str, value: str, verdict: str = "relevant") -> None:
        body = {
            "type": "block_actions",
            "user": {"id": user, "team_id": "T00000001"},
            "team": {"id": "T00000001"},
            "api_app_id": "A00000001",
            "trigger_id": "1111.2222.abcd",
            "channel": {"id": URGENT},
            "actions": [{"type": "button", "action_id": render.ACTION_PREFIX + verdict, "value": value}],
        }
        self.module.app.dispatch(BoltRequest(body=body, mode="socket_mode"))


def event_row(admin: sessionmaker[Session], event_id: uuid.UUID) -> m.NotificationEvent:
    with admin() as session:
        return session.get_one(m.NotificationEvent, event_id)


def test_an_immediate_event_reaches_the_urgent_channel_within_a_minute(
    admin: sessionmaker[Session], app_factory: sessionmaker[Session], slack_engine: Engine
) -> None:
    set_consumer(admin, "slack")
    case = ticket_event(admin, score=95)  # final >= 90: immediate (NOT-03)
    service = Service(app_factory, slack_engine, case)
    service.now = T0 + timedelta(seconds=DISPATCH_SECONDS)  # the first dispatch round after the event
    assert service.job() == 1
    (post,) = service.client.posts()
    assert post["channel"] == URGENT
    row = event_row(admin, case["event_id"])
    assert row.status == "delivered"
    assert row.delivered_at is not None
    assert row.delivered_at - row.created_at < timedelta(minutes=1)
    assert service.job() == 0  # nothing left; redelivery would be ignored by event_id anyway


def test_a_normal_event_goes_to_the_team_digest(
    admin: sessionmaker[Session], app_factory: sessionmaker[Session], slack_engine: Engine
) -> None:
    set_consumer(admin, "slack")
    case = ticket_event(admin, score=70)
    service = Service(app_factory, slack_engine, case)
    # A normal event waits for iTop's ticket id up to 30 minutes (the create is still in the iTop outbox).
    service.now = T0 + timedelta(minutes=31)
    assert service.job() == 1
    assert service.client.posts() == []  # waiting for the team's digest
    service.now = T0 + timedelta(minutes=40)  # past the digest window
    assert service.module.digests.publish_due() == 1
    assert [p["channel"] for p in service.client.posts()] == [TEAM]


def test_with_the_log_consumer_the_slack_service_leaves_events_to_the_worker(
    admin: sessionmaker[Session], app_factory: sessionmaker[Session], slack_engine: Engine
) -> None:
    set_consumer(admin, "log")
    case = ticket_event(admin, score=95)
    service = Service(app_factory, slack_engine, case)
    assert service.job() == 0
    assert event_row(admin, case["event_id"]).status == "pending"


def test_a_click_ends_in_the_feedback_service(
    admin: sessionmaker[Session], app_factory: sessionmaker[Session], slack_engine: Engine
) -> None:
    set_consumer(admin, "slack")
    case = ticket_event(admin, score=95)
    service = Service(app_factory, slack_engine, case)
    service.job()
    (post,) = service.client.posts()
    value = post["blocks"][-1]["elements"][0]["value"]  # the "Relevante" button of the delivered message
    service.click(ANALYST, value)
    service.click(READER, value)  # a reader may not give feedback (D-030)
    with admin() as session:
        stored = session.scalars(
            select(m.Feedback).where(m.Feedback.assessment_id == uuid.UUID(case["assessment_id"]))
        ).all()
    assert [(f.channel, f.verdict) for f in stored] == [("slack", "relevant")]
    answers = [c["text"] for c in service.client.calls_of("chat.postEphemeral")]
    assert answers[0].startswith("Gracias")
    assert "no corresponde a un analista" in answers[1]


def test_waiting_counts_only_due_immediate_events_nobody_took(admin: sessionmaker[Session]) -> None:
    set_consumer(admin, "slack")
    ticket_event(admin, score=95)  # immediate
    ticket_event(admin, score=70)  # normal: it may wait for iTop's ticket id, never counted
    with admin() as session:
        assert waiting_immediate_events(session, T0) == 1
        assert waiting_immediate_events(session, T0 - timedelta(seconds=1)) == 0
        # A claim leases the event (next_attempt_at moves 5 minutes ahead): an event being delivered is not counted.
        session.execute(
            text(
                "UPDATE notification_event SET attempts = 1, next_attempt_at = :lease"
                " WHERE status = 'pending' AND priority = 'immediate'"
            ),
            {"lease": T0 + timedelta(minutes=5)},
        )
        session.commit()
        assert waiting_immediate_events(session, T0 + timedelta(minutes=1)) == 0
