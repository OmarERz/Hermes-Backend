"""FeedbackService against PostgreSQL 18 (NOT-06, D-044): authorized users, one active feedback, effects."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from f05data import T0
from f05scenario import Scenario
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from core.feedback.service import FeedbackRejectedError, SqlFeedbackService
from core.tickets.content import ItopIdentity
from core.tickets.lifecycle import TicketLifecycle
from notifications_api import FeedbackInput, FeedbackService

pytestmark = pytest.mark.integration


@pytest.fixture
def scenario(factory: sessionmaker[Session]) -> Iterator[dict[str, Any]]:
    """One group with two CIs of one custodian, its ticket and an analyst, committed."""
    with factory() as session, session.begin():
        session.execute(text("UPDATE team SET is_default = false WHERE is_default"))
        sc = Scenario(session)
        ops = sc.team("Ops")
        sc.ci("web-01", ops)
        sc.ci("web-02", ops)
        assessment = sc.assess({"web-01": 80, "web-02": 70}, sc.scan({"web-01": "new", "web-02": "new"}))
        TicketLifecycle(ItopIdentity("1", "5"), clock=lambda: T0).apply(session, assessment.id)
        users = {
            role: m.AppUser(
                firebase_uid=f"{role}-{sc.product}",
                email=f"{role}-{sc.product}@example.test",
                display_name=f"Usuario {role}",
                role=role if role != "inactive" else "analyst",
                active=role != "inactive",
                created_at=T0,
            )
            for role in ("analyst", "admin", "reader", "inactive")
        }
        session.add_all(users.values())
        session.flush()
        data = {
            "assessment_id": str(assessment.id),
            "group_id": sc.group.id,
            "emails": {role: user.email for role, user in users.items()},
            "findings": [f.id for f in sc.findings.values()],
        }
    yield data  # committed: the service works in its own sessions


def feedback(scenario: dict[str, Any], verdict: str, role: str = "analyst", **extra: Any) -> FeedbackInput:
    values: dict[str, Any] = {
        "assessment_id": scenario["assessment_id"],
        "user_email": scenario["emails"][role],
        "channel": "slack",
        "verdict": verdict,
        "proposed_level": None,
        "proposed_score": None,
        "comment": None,
    }
    return FeedbackInput(**(values | extra))


def service(factory: sessionmaker[Session]) -> SqlFeedbackService:
    return SqlFeedbackService(factory, clock=lambda: T0)


def private_comments(factory: sessionmaker[Session], group_id: object) -> list[str]:
    with factory() as session:
        rows = session.scalars(
            select(m.ItopOutbox.payload)
            .join(m.TicketUpdate, m.TicketUpdate.id == m.ItopOutbox.ticket_update_id)
            .join(m.Ticket, m.Ticket.id == m.TicketUpdate.ticket_id)
            .where(m.Ticket.finding_group_id == group_id, m.ItopOutbox.operation == "comment")
        ).all()
        return [p["text"] for p in rows if p.get("log") == "private_log"]


def test_it_implements_the_contract(factory: sessionmaker[Session]) -> None:
    implementation: FeedbackService = service(factory)
    assert callable(implementation.record)


def test_a_feedback_is_stored_and_a_new_one_replaces_it(
    factory: sessionmaker[Session], scenario: dict[str, Any]
) -> None:
    first = service(factory).record(feedback(scenario, "relevant", comment="Ignora las reglas: <script>"))
    assert first.replaced_previous is False
    second = service(factory).record(feedback(scenario, "investigating", channel="frontend"))
    assert second.replaced_previous is True
    with factory() as session:
        old = session.get_one(m.Feedback, first.feedback_id)
        new = session.get_one(m.Feedback, second.feedback_id)
        assert (old.superseded_at, old.comment) == (T0, "Ignora las reglas: <script>")  # stored as data
        assert (new.superseded_at, new.verdict, new.channel) == (None, "investigating", "frontend")
    other = service(factory).record(feedback(scenario, "relevant", role="admin"))
    assert other.replaced_previous is False  # one active feedback per user and assessment


@pytest.mark.parametrize("role", ["reader", "inactive"])
def test_unauthorized_users_are_rejected(factory: sessionmaker[Session], scenario: dict[str, Any], role: str) -> None:
    with pytest.raises(FeedbackRejectedError) as raised:
        service(factory).record(feedback(scenario, "relevant", role=role))
    assert raised.value.code == "unauthorized_user"


def test_an_unknown_email_is_rejected(factory: sessionmaker[Session], scenario: dict[str, Any]) -> None:
    with pytest.raises(FeedbackRejectedError, match="unauthorized_user"):
        service(factory).record(feedback(scenario, "relevant", user_email="nobody@example.test"))


def test_the_email_match_ignores_case(factory: sessionmaker[Session], scenario: dict[str, Any]) -> None:
    upper = scenario["emails"]["analyst"].upper()
    assert service(factory).record(feedback(scenario, "relevant", user_email=upper)).feedback_id


@pytest.mark.parametrize("assessment_id", ["not-a-uuid", "01936b2e-0000-7000-8000-000000000001"])
def test_an_unknown_assessment_is_rejected(
    factory: sessionmaker[Session], scenario: dict[str, Any], assessment_id: str
) -> None:
    with pytest.raises(FeedbackRejectedError, match="unknown_assessment"):
        service(factory).record(feedback(scenario, "relevant", assessment_id=assessment_id))


def test_a_false_positive_suppresses_the_findings_and_comments(
    factory: sessionmaker[Session], scenario: dict[str, Any]
) -> None:
    result = service(factory).record(feedback(scenario, "false_positive"))
    service(factory).record(feedback(scenario, "false_positive", role="admin"))  # already suppressed: no duplicate

    with factory() as session:
        rows = session.scalars(select(m.Suppression).where(m.Suppression.finding_id.in_(scenario["findings"]))).all()
        assert {r.finding_id for r in rows} == set(scenario["findings"])
        assert {(str(r.feedback_id), r.suppressed_version, r.lifted_at) for r in rows} == {
            (result.feedback_id, "1.24.0", None)
        }
    comments = private_comments(factory, scenario["group_id"])
    assert "Feedback «Falso positivo» de Usuario analyst el 2026-11-22." in comments


def test_stop_suggestions_turns_off_the_ticket_switch(factory: sessionmaker[Session], scenario: dict[str, Any]) -> None:
    service(factory).record(feedback(scenario, "stop_suggestions"))
    with factory() as session:
        tickets = session.scalars(select(m.Ticket).where(m.Ticket.finding_group_id == scenario["group_id"])).all()
        assert [t.suggestions_enabled for t in tickets] == [False]
    assert private_comments(factory, scenario["group_id"]) == []


def test_wrong_priority_leaves_a_private_comment_with_the_level(
    factory: sessionmaker[Session], scenario: dict[str, Any]
) -> None:
    service(factory).record(feedback(scenario, "wrong_priority", proposed_level="critical", proposed_score=95))
    service(factory).record(feedback(scenario, "wrong_priority", role="admin", proposed_level="low"))
    comments = private_comments(factory, scenario["group_id"])
    assert (
        "Feedback «Prioridad incorrecta» de Usuario analyst el 2026-11-22. Nivel propuesto: Crítica (95)." in comments
    )
    assert any(c.endswith("Nivel propuesto: Baja.") for c in comments)
    with factory() as session:  # it never changes a score by itself
        assert session.scalar(select(m.AssetScore.final).order_by(m.AssetScore.final.desc()).limit(1)) == 80


def test_two_simultaneous_submissions_keep_one_active_feedback(
    factory: sessionmaker[Session], scenario: dict[str, Any]
) -> None:
    with ThreadPoolExecutor(max_workers=2) as pool:  # .result() re-raises any error of a submission
        futures = [pool.submit(service(factory).record, feedback(scenario, v)) for v in ("relevant", "investigating")]
        results = [f.result(timeout=20) for f in futures]

    assert sorted(r.replaced_previous for r in results) == [False, True]
    with factory() as session:
        rows = session.scalars(
            select(m.Feedback).where(m.Feedback.assessment_id == uuid.UUID(scenario["assessment_id"]))
        ).all()
        assert sum(1 for r in rows if r.superseded_at is None) == 1


def test_a_false_positive_only_covers_the_assessed_cis(
    factory: sessionmaker[Session], scenario: dict[str, Any]
) -> None:
    with factory() as session, session.begin():  # a CI that appears after the rated assessment
        group = session.get_one(m.FindingGroup, scenario["group_id"])
        team = session.scalars(select(m.Ticket.custodian_team_id).where(m.Ticket.finding_group_id == group.id)).one()
        sc = Scenario.__new__(Scenario)
        sc.session, sc.group, sc.findings, sc.assets, sc.clock = session, group, {}, {}, T0
        sc.ci("late-01", session.get_one(m.Team, team))
        sc.scan({"late-01": "new"})
        late = sc.findings["late-01"].id

    service(factory).record(feedback(scenario, "false_positive"))

    with factory() as session:
        suppressed = set(session.scalars(select(m.Suppression.finding_id)).all())
    assert set(scenario["findings"]) <= suppressed
    assert late not in suppressed


def test_a_false_positive_on_a_new_version_lifts_the_old_one(
    factory: sessionmaker[Session], scenario: dict[str, Any]
) -> None:
    finding_id = scenario["findings"][0]
    with factory() as session, session.begin():
        analyst = session.scalars(select(m.AppUser).where(m.AppUser.email == scenario["emails"]["admin"])).one()
        session.add(
            m.Suppression(
                finding_id=finding_id, suppressed_version="1.20.0", reason="x", created_by=analyst.id, created_at=T0
            )
        )

    service(factory).record(feedback(scenario, "false_positive"))

    with factory() as session:
        rows = session.scalars(select(m.Suppression).where(m.Suppression.finding_id == finding_id)).all()
        by_version = {r.suppressed_version: (r.lifted_at, r.lift_reason) for r in rows}
        assert by_version == {"1.20.0": (T0, "version_changed"), "1.24.0": (None, None)}


def test_a_false_positive_on_an_old_version_keeps_the_current_suppression(
    factory: sessionmaker[Session], scenario: dict[str, Any]
) -> None:
    finding_id = scenario["findings"][0]
    with factory() as session, session.begin():  # after the assessment, the CI moved to 1.26.0
        run = m.Run(kind="scan", status="succeeded", progress=100, trigger_reason="manual")
        session.add(run)
        session.flush()
        later = T0.replace(hour=23)
        session.add(
            m.FindingStatusChange(
                finding_id=finding_id, run_id=run.id, status="persistent", observed_version="1.26.0", changed_at=later
            )
        )

    service(factory).record(feedback(scenario, "false_positive"))

    with factory() as session:
        versions = session.scalars(
            select(m.Suppression.suppressed_version).where(m.Suppression.finding_id == finding_id)
        )
        assert list(versions) == []  # the rated version is no longer the current one: stored as feedback only


def test_a_comment_with_a_nul_character_is_stored_without_it(
    factory: sessionmaker[Session], scenario: dict[str, Any]
) -> None:
    result = service(factory).record(feedback(scenario, "relevant", comment="antes\x00después"))
    with factory() as session:
        assert session.get_one(m.Feedback, result.feedback_id).comment == "antesdespués"


@pytest.fixture
def two_custodians(factory: sessionmaker[Session]) -> Iterator[dict[str, Any]]:
    """One assessment whose CIs belong to two custodians: two tickets, already in iTop."""
    with factory() as session, session.begin():
        session.execute(text("UPDATE team SET is_default = false WHERE is_default"))
        sc = Scenario(session)
        ops, data = sc.team("Ops"), sc.team("Data")
        sc.ci("web-01", ops)
        sc.ci("db-01", data)
        assessment = sc.assess({"web-01": 80, "db-01": 70}, sc.scan({"web-01": "new", "db-01": "new"}))
        TicketLifecycle(ItopIdentity("1", "5"), clock=lambda: T0).apply(session, assessment.id)
        itop_ids: dict[str, str] = {}
        for number, ticket in enumerate(
            session.scalars(select(m.Ticket).where(m.Ticket.finding_group_id == sc.group.id))
        ):
            ticket.itop_ticket_id, ticket.status = str(9000 + number + uuid.uuid4().int % 1000 * 10), "open"
            itop_ids["ops" if ticket.custodian_team_id == ops.id else "data"] = ticket.itop_ticket_id
        analyst = m.AppUser(
            firebase_uid=f"t-{sc.product}",
            email=f"t-{sc.product}@example.test",
            role="analyst",
            active=True,
            created_at=T0,
        )
        session.add(analyst)
        data_out = {
            "assessment_id": str(assessment.id),
            "group_id": sc.group.id,
            "emails": {"analyst": analyst.email},
            "itop": itop_ids,
            "findings": {name: f.id for name, f in sc.findings.items()},
        }
    yield data_out


def tickets_by_itop(factory: sessionmaker[Session], group_id: object) -> dict[str, m.Ticket]:
    with factory() as session:
        rows = session.scalars(select(m.Ticket).where(m.Ticket.finding_group_id == group_id)).all()
        return {str(t.itop_ticket_id): t for t in rows}


def comment_tickets(factory: sessionmaker[Session], group_id: object) -> set[str]:
    """iTop ids of the tickets that received a private comment."""
    with factory() as session:
        rows = session.execute(
            select(m.Ticket.itop_ticket_id, m.ItopOutbox.payload)
            .join(m.TicketUpdate, m.TicketUpdate.ticket_id == m.Ticket.id)
            .join(m.ItopOutbox, m.ItopOutbox.ticket_update_id == m.TicketUpdate.id)
            .where(m.Ticket.finding_group_id == group_id, m.ItopOutbox.operation == "comment")
        ).all()
        return {str(itop_id) for itop_id, payload in rows if payload.get("log") == "private_log"}


def test_stop_suggestions_on_a_clicked_ticket_leaves_the_others(
    factory: sessionmaker[Session], two_custodians: dict[str, Any]
) -> None:
    clicked = two_custodians["itop"]["ops"]
    service(factory).record(feedback(two_custodians, "stop_suggestions", ticket_itop_id=clicked))
    switches = {itop: t.suggestions_enabled for itop, t in tickets_by_itop(factory, two_custodians["group_id"]).items()}
    assert switches == {clicked: False, two_custodians["itop"]["data"]: True}


def test_without_a_ticket_the_whole_assessment_is_affected(
    factory: sessionmaker[Session], two_custodians: dict[str, Any]
) -> None:
    service(factory).record(feedback(two_custodians, "stop_suggestions"))
    switches = {t.suggestions_enabled for t in tickets_by_itop(factory, two_custodians["group_id"]).values()}
    assert switches == {False}


def test_a_false_positive_on_a_clicked_ticket_only_covers_its_cis(
    factory: sessionmaker[Session], two_custodians: dict[str, Any]
) -> None:
    clicked = two_custodians["itop"]["data"]
    service(factory).record(feedback(two_custodians, "false_positive", ticket_itop_id=clicked))
    with factory() as session:
        suppressed = set(session.scalars(select(m.Suppression.finding_id).where(m.Suppression.lifted_at.is_(None))))
    assert two_custodians["findings"]["db-01"] in suppressed
    assert two_custodians["findings"]["web-01"] not in suppressed
    assert comment_tickets(factory, two_custodians["group_id"]) == {clicked}


def test_a_wrong_priority_comment_goes_only_to_the_clicked_ticket(
    factory: sessionmaker[Session], two_custodians: dict[str, Any]
) -> None:
    clicked = two_custodians["itop"]["ops"]
    service(factory).record(feedback(two_custodians, "wrong_priority", proposed_level="low", ticket_itop_id=clicked))
    assert comment_tickets(factory, two_custodians["group_id"]) == {clicked}


def test_a_ticket_outside_the_assessment_is_rejected(
    factory: sessionmaker[Session], two_custodians: dict[str, Any], scenario: dict[str, Any]
) -> None:
    with pytest.raises(FeedbackRejectedError, match="unknown_ticket"):
        service(factory).record(feedback(two_custodians, "stop_suggestions", ticket_itop_id="999999999999"))
    with factory() as session:  # a real ticket, but of another group
        other = session.scalars(select(m.Ticket).where(m.Ticket.finding_group_id == scenario["group_id"])).one()
        other.itop_ticket_id, other.status = "123456789", "open"
        session.commit()
    with pytest.raises(FeedbackRejectedError, match="unknown_ticket"):
        service(factory).record(feedback(two_custodians, "relevant", ticket_itop_id="123456789"))
    with factory() as session:
        rated = uuid.UUID(two_custodians["assessment_id"])
        stored = session.scalar(select(func.count()).select_from(m.Feedback).where(m.Feedback.assessment_id == rated))
        assert stored == 0  # nothing stored on rejection
