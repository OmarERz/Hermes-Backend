"""F10.5: the routes that used sample answers now run the real services (feedback, simulation)."""

from __future__ import annotations

import logging
import uuid
from decimal import Decimal

import pytest
from f10data import Scenario
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from api.auth import CurrentUser, Role, get_current_user

pytestmark = pytest.mark.integration


def as_user(client: TestClient, email: str, role: Role = Role.ANALYST) -> None:
    app = client.app
    assert hasattr(app, "dependency_overrides")
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(uid="x", email=email, display_name=None, role=role)


def test_feedback_is_stored_for_the_token_user_and_replaced_on_the_second_one(
    client: TestClient, scenario: Scenario, database: tuple[str, Engine]
) -> None:
    as_user(client, "ana@example.test")
    body = {"assessment_id": str(scenario.assessments["A1"]), "verdict": "relevant", "comment": "ok"}
    first = client.post("/api/feedback", json=body)
    assert first.status_code == 201, first.text
    assert first.json()["replaced_previous"] is True  # the scenario already holds an active feedback of Ana
    second = client.post("/api/feedback", json={**body, "verdict": "investigating"})
    assert second.status_code == 201
    assert second.json()["replaced_previous"] is True
    with database[1].connect() as conn:
        rows = conn.execute(
            text(
                "SELECT u.email, f.channel, f.verdict FROM feedback f JOIN app_user u ON u.id = f.app_user_id "
                "WHERE f.assessment_id = :a AND f.superseded_at IS NULL AND u.email = 'ana@example.test'"
            ),
            {"a": scenario.assessments["A1"]},
        ).all()
    assert [tuple(r) for r in rows] == [("ana@example.test", "frontend", "investigating")]


def test_feedback_errors(client: TestClient, scenario: Scenario) -> None:
    as_user(client, "ana@example.test")
    unknown = client.post("/api/feedback", json={"assessment_id": str(uuid.UUID(int=9)), "verdict": "relevant"})
    assert unknown.status_code == 404
    not_an_id = client.post("/api/feedback", json={"assessment_id": "nope", "verdict": "relevant"})
    assert not_an_id.status_code == 404
    as_user(client, "stranger@example.test")  # an analyst of the token with no app_user row
    unauthorized = client.post(
        "/api/feedback", json={"assessment_id": str(scenario.assessments["A1"]), "verdict": "relevant"}
    )
    assert unauthorized.status_code == 403
    as_user(client, "ana@example.test")
    forged = client.post(
        "/api/feedback",
        json={
            "assessment_id": str(scenario.assessments["A1"]),
            "verdict": "relevant",
            "user_email": "luis@example.test",
        },
    )
    assert forged.status_code == 422


def test_simulate_compares_the_open_findings_with_the_proposed_formula(client: TestClient, scenario: Scenario) -> None:
    assert scenario.groups
    as_user(client, "admin@example.test", Role.ADMIN)
    values = client.get("/api/config").json()["values"]
    weight_s, weight_p = Decimal(values["weights.S"]), Decimal(values["weights.P"])
    shifted = {"weights.S": str(weight_s + Decimal("0.05")), "weights.P": str(weight_p - Decimal("0.05"))}
    reply = client.post("/api/formula/simulate", json={"changes": shifted})
    assert reply.status_code == 200, reply.text
    body = reply.json()
    assert set(body) == {"changed_findings", "level_matrix", "last_30_days_effect", "top_movers", "not_simulable"}
    assert body["not_simulable"] == []  # only formula keys: everything was simulated (FRO-04)
    matrix = body["level_matrix"]
    off_diagonal = sum(n for before, row in matrix.items() for after, n in row.items() if before != after)
    assert body["changed_findings"] == off_diagonal
    # known scenario: three scored CIs, one falls from high to low (75 to 42), none rises
    assert matrix == {"critical": {"critical": 1}, "medium": {"medium": 1}, "high": {"low": 1}}
    assert body["changed_findings"] == 1
    assert body["top_movers"][0] == "CVE-2026-10002 en srv-sin-custodio: 75 a 42"
    assert len(body["top_movers"]) <= 5
    # the preview writes nothing: the formula is still the active one
    assert client.get("/api/config").json()["values"] == values
    invalid = client.post("/api/formula/simulate", json={"changes": {"weights.S": "0.9"}})
    assert invalid.status_code == 422


def test_rejected_feedback_is_a_logged_security_event(
    client: TestClient, scenario: Scenario, caplog: pytest.LogCaptureFixture
) -> None:
    """docs/14 §10.4 (F12.3): the rejection code is logged, never the input or the e-mail."""
    as_user(client, "stranger@example.test")
    with caplog.at_level(logging.WARNING, logger="api.routes.findings"):
        answer = client.post(
            "/api/feedback",
            json={"assessment_id": str(scenario.assessments["A1"]), "verdict": "relevant", "comment": "texto"},
        )
    assert answer.status_code == 403
    assert "feedback rejected: unauthorized_user" in caplog.text
    assert "stranger@example.test" not in caplog.text and "texto" not in caplog.text
