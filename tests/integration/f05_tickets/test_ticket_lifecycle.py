"""Ticket lifecycle per custodian against PostgreSQL 18 (docs/08 §5 acceptance criteria)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from f05data import T0
from f05scenario import Scenario
from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from core.itop.outbox import ItopOutboxWorker, build_writer
from core.tickets.content import ItopIdentity
from core.tickets.lifecycle import TicketLifecycle
from doubles.itop import ItopDouble

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]
EVENT_SCHEMA = json.loads((ROOT / "schemas" / "notification_event.schema.json").read_text(encoding="utf-8"))
IDENTITY = ItopIdentity(org_id="1", caller_id="5", service_id="7")


@pytest.fixture
def session(factory: sessionmaker[Session]) -> Iterator[Session]:
    with factory() as session:
        session.begin()
        session.execute(text("UPDATE team SET is_default = false WHERE is_default"))
        yield session
        session.rollback()


def lifecycle(scenario: Scenario) -> TicketLifecycle:
    return TicketLifecycle(IDENTITY, itop_base_url="https://itop.example.test", clock=lambda: scenario.clock)


def tickets(session: Session, scenario: Scenario) -> list[m.Ticket]:
    query = select(m.Ticket).where(m.Ticket.finding_group_id == scenario.group.id).order_by(m.Ticket.created_at)
    return list(session.scalars(query).all())


def writes(session: Session, ticket: m.Ticket) -> list[tuple[str, dict[str, Any]]]:
    rows = session.execute(
        select(m.TicketUpdate.action, m.ItopOutbox.payload)
        .join(m.ItopOutbox, m.ItopOutbox.ticket_update_id == m.TicketUpdate.id, isouter=True)
        .where(m.TicketUpdate.ticket_id == ticket.id)
        .order_by(m.TicketUpdate.created_at, m.TicketUpdate.id)
    ).all()
    return [(row.action, row.payload) for row in rows]


def events(session: Session, ticket: m.Ticket | None = None) -> list[m.NotificationEvent]:
    query = select(m.NotificationEvent).order_by(m.NotificationEvent.created_at, m.NotificationEvent.id)
    if ticket is not None:
        query = query.where(m.NotificationEvent.ticket_id == ticket.id)
    return list(session.scalars(query).all())


def created_in_itop(ticket: m.Ticket, itop_id: str, urgency: int, status: str = "open") -> None:
    """What the outbox does once iTop answers the create."""
    ticket.itop_ticket_id, ticket.itop_ref, ticket.status = itop_id, f"R-{itop_id}", status
    ticket.current_urgency, ticket.current_impact = urgency, "service"
    if status == "resolved":
        ticket.resolved_at = T0
    if status == "closed":
        ticket.closed_at = T0


def test_two_custodians_get_two_tickets_with_their_team_and_owners(session: Session) -> None:
    sc = Scenario(session)
    ops, data = sc.team("Platform Ops"), sc.team("Data Custody")
    ana, luis = sc.person("Ana Rivera"), sc.person("Luis Soto")
    sc.ci("web-01", ops, ana)
    sc.ci("db-01", data, luis)
    run = sc.scan({"web-01": "new", "db-01": "new"})

    report = lifecycle(sc).apply(session, sc.assess({"web-01": 80, "db-01": 60}, run).id)

    assert (report.created, report.events) == (2, 2)
    by_team = {t.custodian_team_id: t for t in tickets(session, sc)}
    create_ops = writes(session, by_team[ops.id])[0]
    assert create_ops[0] == "create"
    fields = create_ops[1]["fields"]
    assert fields["team_id"] == ops.itop_team_id
    assert fields["title"] == f"{sc.group.cve_id} · {sc.product} · Platform Ops"
    assert fields["contacts_list"] == [{"contact_id": ana.itop_person_id}]
    assert fields["functionalcis_list"] == [
        {"functionalci_id": sc.assets["web-01"].itop_ci_id, "impact_code": "manual"}
    ]
    assert (fields["urgency"], fields["impact"], fields["caller_id"], fields["service_id"]) == ("2", "2", "5", "7")
    assert "agent_id" not in fields
    assert writes(session, by_team[data.id])[0][1]["fields"]["team_id"] == data.itop_team_id
    assert [e.event_type for e in events(session)] == ["new_ticket", "new_ticket"]
    for event in events(session):
        jsonschema.validate(event.payload, EVENT_SCHEMA)


def test_a_low_score_still_opens_a_ticket_with_a_digest_event(session: Session) -> None:
    sc = Scenario(session)
    sc.ci("web-01", sc.team("Ops"))
    run = sc.scan({"web-01": "new"})

    lifecycle(sc).apply(session, sc.assess({"web-01": 30}, run).id)

    (event,) = events(session)
    assert (event.event_type, event.priority) == ("new_ticket", "digest")
    assert event.payload["ticket"]["itop_id"] == ""  # completed by the dispatcher once iTop answers
    assert event.payload["score"]["final"] == 30


def test_a_ci_without_custodian_goes_to_the_default_team(session: Session) -> None:
    sc = Scenario(session)
    default = sc.default_team()
    sc.ci("orphan-01", None)
    run = sc.scan({"orphan-01": "new"})

    lifecycle(sc).apply(session, sc.assess({"orphan-01": 55}, run).id)

    assert [t.custodian_team_id for t in tickets(session, sc)] == [default.id]


def test_without_custodian_nor_default_team_no_ticket_is_opened(session: Session) -> None:
    sc = Scenario(session)
    sc.ci("orphan-01", None)
    run = sc.scan({"orphan-01": "new"})

    assert lifecycle(sc).apply(session, sc.assess({"orphan-01": 55}, run).id).created == 0


def test_the_same_assessment_twice_writes_nothing_new(session: Session) -> None:
    sc = Scenario(session)
    sc.ci("web-01", sc.team("Ops"))
    assessment = sc.assess({"web-01": 80}, sc.scan({"web-01": "new"}))
    lifecycle(sc).apply(session, assessment.id)
    ticket = tickets(session, sc)[0]
    created_in_itop(ticket, "100", 2)

    report = lifecycle(sc).apply(session, assessment.id)

    assert (report.writes, report.events) == (0, 0)


def test_a_new_ci_of_the_same_custodian_is_added_to_the_ticket(session: Session) -> None:
    sc = Scenario(session)
    ops = sc.team("Ops")
    ana, luis = sc.person("Ana"), sc.person("Luis")
    sc.ci("web-01", ops, ana)
    lifecycle(sc).apply(session, sc.assess({"web-01": 60}, sc.scan({"web-01": "new"})).id)
    ticket = tickets(session, sc)[0]
    created_in_itop(ticket, "100", 3)
    sc.later(days=1)
    sc.ci("web-02", ops, luis)

    lifecycle(sc).apply(session, sc.assess({"web-01": 60, "web-02": 62}, sc.scan({"web-02": "new"})).id)

    assert len(tickets(session, sc)) == 1
    actions = writes(session, ticket)
    assert [a for a, _ in actions] == ["create", "add_ci", "comment"]
    update = actions[1][1]["fields"]
    assert [c["functionalci_id"] for c in update["functionalcis_list"]] == [
        sc.assets["web-02"].itop_ci_id,
        sc.assets["web-01"].itop_ci_id,
    ]
    assert update["contacts_list"] == [{"contact_id": luis.itop_person_id}, {"contact_id": ana.itop_person_id}]
    assert "Se agregó el CI web-02." in actions[2][1]["text"]
    assert [e.event_type for e in events(session)] == ["new_ticket"]


def test_a_ci_that_changes_custodian_moves_with_a_comment_on_both(session: Session) -> None:
    sc = Scenario(session)
    ops, data = sc.team("Ops"), sc.team("Data")
    sc.ci("web-01", ops)
    sc.ci("web-02", ops)
    lifecycle(sc).apply(
        session, sc.assess({"web-01": 60, "web-02": 70}, sc.scan({"web-01": "new", "web-02": "new"})).id
    )
    old = tickets(session, sc)[0]
    created_in_itop(old, "100", 3)
    sc.assets["web-02"].custodian_team_id = data.id
    sc.later(days=1)

    run = sc.scan({"web-01": "persistent", "web-02": "persistent"})
    lifecycle(sc).apply(session, sc.assess({"web-01": 60, "web-02": 70}, run).id)

    new = next(t for t in tickets(session, sc) if t.custodian_team_id == data.id)
    old_writes = writes(session, old)
    assert [a for a, _ in old_writes] == ["create", "comment", "comment"]
    assert [c["functionalci_id"] for c in old_writes[1][1]["fields"]["functionalcis_list"]] == [
        sc.assets["web-01"].itop_ci_id
    ]
    assert "El CI web-02 pasó al equipo Data." in old_writes[2][1]["text"]
    new_create = writes(session, new)[0][1]["fields"]
    assert new_create["functionalcis_list"][0]["functionalci_id"] == sc.assets["web-02"].itop_ci_id
    assert [e.event_type for e in events(session, new)] == ["new_ticket"]


def test_fixing_one_of_three_cis_comments_and_emits_partially_fixed(session: Session) -> None:
    sc = Scenario(session)
    ops = sc.team("Ops")
    for name in ("web-01", "web-02", "web-03"):
        sc.ci(name, ops)
    run = sc.scan({"web-01": "new", "web-02": "new", "web-03": "new"})
    lifecycle(sc).apply(session, sc.assess({"web-01": 80, "web-02": 70, "web-03": 60}, run).id)
    ticket = tickets(session, sc)[0]
    created_in_itop(ticket, "100", 2)
    sc.later(days=1)

    run = sc.scan({"web-01": "fixed", "web-02": "persistent", "web-03": "persistent"})
    lifecycle(sc).apply(session, sc.assess({"web-02": 70, "web-03": 60}, run).id)

    actions = writes(session, ticket)
    assert (
        "partial_fix",
        {"kind": "comment", "log": "public_log", "text": "Corregido en web-01; 1 de 3 corregidos."},
    ) in actions
    partial = events(session, ticket)[-1]
    assert partial.event_type == "partially_fixed"
    assert (partial.payload["ticket"]["fixed_cis"], partial.payload["ticket"]["total_cis"]) == (1, 3)
    assert partial.payload["ticket"]["itop_id"] == "100"
    assert partial.payload["ticket"]["url"].endswith("&id=100")
    jsonschema.validate(partial.payload, EVENT_SCHEMA)


def test_fixing_every_ci_comments_and_emits_fixed(session: Session) -> None:
    sc = Scenario(session)
    sc.ci("web-01", sc.team("Ops"))
    lifecycle(sc).apply(session, sc.assess({"web-01": 80}, sc.scan({"web-01": "new"})).id)
    ticket = tickets(session, sc)[0]
    created_in_itop(ticket, "100", 2)
    sc.later(days=1)

    lifecycle(sc).apply(session, sc.assess({}, sc.scan({"web-01": "fixed"})).id)

    assert writes(session, ticket)[-1][0] == "fix_comment"
    fixed = events(session, ticket)[-1]
    assert (fixed.event_type, fixed.priority, fixed.payload["score"]) == ("fixed", "normal", None)
    jsonschema.validate(fixed.payload, EVENT_SCHEMA)
    assert ticket.status == "open"  # a person closes it


def test_a_higher_score_raises_the_urgency_and_emits_level_up(session: Session) -> None:
    sc = Scenario(session)
    sc.ci("web-01", sc.team("Ops"), critical=True)
    lifecycle(sc).apply(session, sc.assess({"web-01": 60}, sc.scan({"web-01": "new"})).id)
    ticket = tickets(session, sc)[0]
    created_in_itop(ticket, "100", 3)
    sc.later(days=1)

    lifecycle(sc).apply(session, sc.assess({"web-01": 92}, sc.run("news")).id)

    actions = writes(session, ticket)
    assert ("raise_urgency", {"kind": "update", "fields": {"urgency": "1", "impact": "1"}}) in actions
    assert "Urgencia subida a 1 (Crítica)" in actions[-1][1]["text"]
    level_up = events(session, ticket)[-1]
    assert (level_up.event_type, level_up.priority) == ("level_up", "immediate")
    assert (level_up.payload["score"]["final"], level_up.payload["score"]["previous"]) == (92, 60)


def test_a_human_urgency_change_is_respected_with_a_private_suggestion(session: Session) -> None:
    sc = Scenario(session)
    sc.ci("web-01", sc.team("Ops"))
    lifecycle(sc).apply(session, sc.assess({"web-01": 60}, sc.scan({"web-01": "new"})).id)
    ticket = tickets(session, sc)[0]
    created_in_itop(ticket, "100", 4)
    ticket.last_human_change_at, ticket.last_human_change_by = T0, "Ana Rivera"
    sc.later(days=1)

    lifecycle(sc).apply(session, sc.assess({"web-01": 92}, sc.run("news")).id)

    action, payload = writes(session, ticket)[-1]
    assert (action, payload["log"]) == ("suggest", "private_log")
    assert "No se cambió porque Ana Rivera modificó la urgencia." in payload["text"]
    assert [e.event_type for e in events(session, ticket)] == ["new_ticket"]

    ticket.suggestions_enabled = False  # "No sugerir más": recorded, not written to iTop (TIC-07)
    sc.later(days=1)
    lifecycle(sc).apply(session, sc.assess({"web-01": 93}, sc.run("news")).id)
    assert writes(session, ticket)[-1] == ("suggest", None)


def test_the_urgency_falls_only_after_the_hysteresis(session: Session) -> None:
    sc = Scenario(session)
    sc.ci("web-01", sc.team("Ops"))
    lifecycle(sc).apply(session, sc.assess({"web-01": 80}, sc.scan({"web-01": "new"})).id)
    ticket = tickets(session, sc)[0]
    created_in_itop(ticket, "100", 2)

    sc.later(days=1)
    lifecycle(sc).apply(session, sc.assess({"web-01": 60}, sc.run("news")).id)
    assert writes(session, ticket)[-1][0] == "comment"
    assert "cuando se cumpla la histéresis" in writes(session, ticket)[-1][1]["text"]

    sc.later(days=1)
    lifecycle(sc).apply(session, sc.assess({"web-01": 61}, sc.run("news")).id)
    assert ("lower_urgency", {"kind": "update", "fields": {"urgency": "3", "impact": "2"}}) in writes(session, ticket)
    assert [e.event_type for e in events(session, ticket)] == ["new_ticket"]  # lowering emits no event


def test_a_scan_that_finds_it_again_comments_that_it_persists(session: Session) -> None:
    sc = Scenario(session)
    sc.ci("web-01", sc.team("Ops"))
    lifecycle(sc).apply(session, sc.assess({"web-01": 60}, sc.scan({"web-01": "new"})).id)
    ticket = tickets(session, sc)[0]
    created_in_itop(ticket, "100", 3)
    sc.later(days=1)

    lifecycle(sc).apply(session, sc.assess({"web-01": 60}, sc.scan({"web-01": "persistent"})).id)

    assert writes(session, ticket)[-1][1]["text"] == "Sigue presente en el escaneo del 2026-11-23."


def test_a_resolved_ticket_whose_finding_persists_is_reopened(session: Session) -> None:
    sc = Scenario(session)
    sc.ci("web-01", sc.team("Ops"))
    lifecycle(sc).apply(session, sc.assess({"web-01": 60}, sc.scan({"web-01": "new"})).id)
    ticket = tickets(session, sc)[0]
    created_in_itop(ticket, "100", 3, status="resolved")
    sc.later(days=1)

    lifecycle(sc).apply(session, sc.assess({"web-01": 60}, sc.scan({"web-01": "persistent"})).id)

    assert ("reopen", {"kind": "stimulus", "stimulus": "ev_reopen"}) in writes(session, ticket)
    assert ticket.status == "open"
    assert events(session, ticket)[-1].event_type == "reopened"


def test_a_closed_ticket_is_replaced_by_a_new_request_when_the_finding_returns(session: Session) -> None:
    sc = Scenario(session)
    sc.ci("web-01", sc.team("Ops"))
    lifecycle(sc).apply(session, sc.assess({"web-01": 60}, sc.scan({"web-01": "new"})).id)
    ticket = tickets(session, sc)[0]
    created_in_itop(ticket, "100", 3, status="closed")
    sc.later(days=1)
    lifecycle(sc).apply(session, sc.assess({}, sc.scan({"web-01": "fixed"})).id)
    sc.later(days=1)

    lifecycle(sc).apply(session, sc.assess({"web-01": 65}, sc.scan({"web-01": "reopened"})).id)

    assert (ticket.status, ticket.itop_ticket_id, ticket.closed_at) == ("pending_creation", None, None)
    assert [a for a, _ in writes(session, ticket)].count("create") == 2
    assert events(session, ticket)[-1].event_type == "reopened"


def test_a_false_positive_neither_opens_a_ticket_nor_emits_events(session: Session) -> None:
    sc = Scenario(session)
    sc.ci("web-01", sc.team("Ops"))
    analyst = m.AppUser(
        firebase_uid=f"uid-{sc.product}", email=f"{sc.product}@example.test", role="analyst", active=True, created_at=T0
    )
    session.add(analyst)
    session.flush()
    session.add(
        m.Suppression(
            finding_id=sc.findings["web-01"].id,
            suppressed_version="1.24.0",
            reason="Falso positivo",
            created_by=analyst.id,
            created_at=T0,
        )
    )
    session.flush()

    report = lifecycle(sc).apply(session, sc.assess({"web-01": 95}, sc.scan({"web-01": "new"})).id)

    assert (report.created, report.events) == (0, 0)


def test_an_alert_assessment_is_refused(session: Session) -> None:
    sc = Scenario(session)
    assessment = sc.assess({}, sc.run())
    assessment.finding_group_id = None
    with pytest.raises(ValueError, match="group assessments"):
        lifecycle(sc).apply(session, assessment.id)


def test_the_created_ticket_reaches_itop_through_the_outbox(factory: sessionmaker[Session]) -> None:
    double = ItopDouble()
    with factory() as session, session.begin():
        sc = Scenario(session)
        sc.ci("web-01", sc.team("Ops"), sc.person("Ana"))
        lifecycle(sc).apply(session, sc.assess({"web-01": 80}, sc.scan({"web-01": "new"})).id)
        group_id = sc.group.id

    writer = build_writer("http://localhost", str(double.token), http=double.client())
    assert ItopOutboxWorker(factory, writer, clock=lambda: T0).drain() == 1

    created = next(iter(double.data["UserRequest"].values()))
    assert "Puntuación del ticket: 80 (Alta), impulsada por web-01." in created["description"]
    with factory() as session:
        ticket = session.scalars(select(m.Ticket).where(m.Ticket.finding_group_id == group_id)).one()
        assert (ticket.status, ticket.current_urgency, ticket.itop_ticket_id) == ("open", 2, created["id"])


def test_a_decommissioned_ci_leaves_the_ticket(session: Session) -> None:
    sc = Scenario(session)
    ops = sc.team("Ops")
    sc.ci("web-01", ops)
    sc.ci("web-02", ops)
    lifecycle(sc).apply(
        session, sc.assess({"web-01": 60, "web-02": 60}, sc.scan({"web-01": "new", "web-02": "new"})).id
    )
    ticket = tickets(session, sc)[0]
    created_in_itop(ticket, "100", 3)
    sc.assets["web-02"].decommissioned_at = sc.clock
    sc.later(days=1)

    lifecycle(sc).apply(session, sc.assess({"web-01": 60}, sc.run("inventory_sync")).id)

    actions = writes(session, ticket)
    assert [c["functionalci_id"] for c in actions[1][1]["fields"]["functionalcis_list"]] == [
        sc.assets["web-01"].itop_ci_id
    ]
    assert "El CI web-02 se dio de baja en iTop." in actions[2][1]["text"]


def test_ci_changes_before_itop_created_the_ticket_are_queued_behind_the_create(session: Session) -> None:
    sc = Scenario(session)
    ops, data = sc.team("Ops"), sc.team("Data")
    sc.ci("web-01", ops)
    sc.ci("web-02", ops)
    run = sc.scan({"web-01": "new", "web-02": "new"})
    lifecycle(sc).apply(session, sc.assess({"web-01": 60, "web-02": 70}, run).id)
    old = tickets(session, sc)[0]  # still pending_creation: iTop has not answered the create yet
    sc.assets["web-02"].custodian_team_id = data.id
    sc.later(days=1)

    run = sc.scan({"web-01": "persistent", "web-02": "persistent"})
    lifecycle(sc).apply(session, sc.assess({"web-01": 60, "web-02": 70}, run).id)

    old_writes = writes(session, old)
    assert [a for a, _ in old_writes] == ["create", "comment", "comment"]
    assert [c["functionalci_id"] for c in old_writes[1][1]["fields"]["functionalcis_list"]] == [
        sc.assets["web-01"].itop_ci_id
    ]
    assert "El CI web-02 pasó al equipo Data." in old_writes[2][1]["text"]


def test_a_suppression_of_an_older_version_no_longer_silences(session: Session) -> None:
    sc = Scenario(session)
    sc.ci("web-01", sc.team("Ops"))
    analyst = m.AppUser(
        firebase_uid=f"v-{sc.product}", email=f"v-{sc.product}@example.test", role="analyst", active=True, created_at=T0
    )
    session.add(analyst)
    session.flush()
    session.add(
        m.Suppression(
            finding_id=sc.findings["web-01"].id,
            suppressed_version="1.23.0",  # the false positive was about another version
            reason="Falso positivo",
            created_by=analyst.id,
            created_at=T0,
        )
    )
    session.flush()

    report = lifecycle(sc).apply(session, sc.assess({"web-01": 95}, sc.scan({"web-01": "new"})).id)

    assert (report.created, report.events) == (1, 1)
    suppression = session.scalars(
        select(m.Suppression).where(m.Suppression.finding_id == sc.findings["web-01"].id)
    ).one()
    assert (suppression.lifted_at, suppression.lift_reason) == (sc.clock, "version_changed")
