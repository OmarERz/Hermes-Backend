"""Recommendation history and feedback received against PostgreSQL (FRO-12 to FRO-15)."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from decimal import Decimal
from typing import Any

import pytest
from f10data import Scenario
from fastapi.testclient import TestClient
from sqlalchemy import Engine, update
from sqlalchemy.orm import Session

from core.db import models as m

pytestmark = pytest.mark.integration
Get = Callable[..., Any]


def names(scenario: Scenario, items: list[dict[str, Any]]) -> list[str]:
    by_id = {str(v): k for k, v in scenario.assessments.items()}
    return [by_id[item["assessment_id"]] for item in items]


def test_feed_is_newest_first_and_pages(get: Get, scenario: Scenario) -> None:
    assert names(scenario, get("/api/recommendations")["items"]) == ["A3", "A2", "A4", "A1"]
    first = get("/api/recommendations", limit=3)
    second = get("/api/recommendations", limit=3, cursor=first["next_cursor"])
    assert names(scenario, first["items"] + second["items"]) == ["A3", "A2", "A4", "A1"]
    assert second["next_cursor"] is None


def test_timelines_by_vulnerability_or_by_ci(get: Get, scenario: Scenario) -> None:
    assert names(scenario, get("/api/recommendations", group_id=str(scenario.groups["G1"]))["items"]) == ["A2", "A1"]
    assert names(scenario, get("/api/recommendations", ci_id="CI-3")["items"]) == ["A3"]
    assert get("/api/recommendations", group_id="nope")["items"] == []
    assert get("/api/recommendations", ci_id="CI-404")["items"] == []


def test_recommendation_shows_score_ci_snapshot_mitigation_and_ticket(get: Get, scenario: Scenario) -> None:
    rec = get(f"/api/recommendations/{scenario.assessments['A2']}")
    assert (rec["cve"], rec["product"], rec["created_at"]) == ("CVE-2026-10001", "OpenSSL", "2026-11-21T12:00:00Z")
    # CI-4 (99) is decommissioned: CI-1 drives the score.
    assert (rec["base"], rec["judge_adjustment"], rec["final"], rec["level"], rec["previous_final"]) == (
        82,
        8,
        90,
        "critical",
        80,
    )
    assert rec["justification"].startswith("**Base 82 → Final 90 · impulsada por srv-pagos-01.**")
    assert "**Juez +8:** Explotación masiva con evidencia de los últimos 30 días (+8)." in rec["justification"]
    assert "Prueba de concepto" not in rec["justification"]  # the rejected reason is not shown
    assert "CISA KEV exige: Aplicar la actualización" in rec["mitigation"]
    assert rec["mitigation_draft"] == ["Aislar srv-pagos-01.", "Actualizar OpenSSL a 3.0.8."]
    assert rec["ticket_url"] == "https://itop.example.test/pages/UI.php?operation=details&class=UserRequest&id=777"
    assert rec["asset"] == {
        "ci_id": "CI-1",
        "name": "srv-pagos-01",
        "itop_url": "https://itop.example.test/pages/UI.php?operation=details&class=Server&id=CI-1",
        "owner": "Dueña de Pagos",
        "custodian": "Infraestructura Linux",
        "criticality": "high",
        "exposed": True,
        "classification": "highly_classified",
        "classification_at_evaluation": "highly_classified",
        "finding_status": "new",
        "score": 90,
        "finding_id": None,  # only the vulnerability detail carries it (F13.8)
    }
    assert rec["feedback_count"] == 1


def test_recommendation_without_judge_shows_the_most_restrictive_ci(get: Get, scenario: Scenario) -> None:
    rec = get(f"/api/recommendations/{scenario.assessments['A3']}")
    assert (rec["final"], rec["judge_adjustment"], rec["previous_final"]) == (75, 0, None)
    # G2's only ticket belongs to another custodian than the CI shown: it is still the group's ticket.
    assert rec["ticket_url"] == "https://itop.example.test/pages/UI.php?operation=details&class=UserRequest&id=778"
    assert "impulsada por srv-sin-custodio" in rec["justification"]
    assert "Sin revisión del juez" in rec["justification"]
    # Rehearsal 2, P2-D: G2 has no CVSS; docs/06 §S scores it with S = 0.8 and the `unrated` mark
    assert "Sin CVSS publicado: severidad estimada 8.0 (valor conservador, `unrated`)" in rec["justification"]
    assert rec["mitigation_draft"] is None
    # CI-3 drives the score, but CI-1 is the most restrictive CI (FRO-13).
    assert (rec["asset"]["ci_id"], rec["asset"]["score"]) == ("CI-1", 70)


def test_an_s_from_the_inferred_vector_is_called_estimated(
    get: Get, scenario: Scenario, database: tuple[str, Engine]
) -> None:
    """docs/06 §S: without CVSS, an S other than the formula's default (0.8) came from the CVE analyst's inferred
    vector (here 0.91, a 9.1 vector), and the text says so with that value (F15.12 review, P1)."""
    a3 = scenario.assessments["A3"]
    with Session(database[1]) as session, session.begin():
        session.execute(update(m.Assessment).where(m.Assessment.id == a3).values(factor_s=Decimal("0.91")))
    try:
        text = get(f"/api/recommendations/{a3}")["justification"]
        assert "Sin CVSS publicado: severidad estimada 9.1 con el vector que infirió el Analista de CVE" in text
        assert "unrated" not in text
    finally:
        with Session(database[1]) as session, session.begin():
            session.execute(update(m.Assessment).where(m.Assessment.id == a3).values(factor_s=Decimal("0.8")))


@pytest.mark.parametrize("assessment", [str(uuid.UUID(int=3))])  # malformed: 422 since F12.3 (test_path_params)
def test_unknown_recommendation_is_404(client: TestClient, assessment: str) -> None:
    for url in (f"/api/recommendations/{assessment}", f"/api/recommendations/{assessment}/feedback"):
        response = client.get(url)
        assert (response.status_code, response.json()["error"]["code"]) == (404, "not_found")


def test_feedback_received_with_history_and_version(get: Get, scenario: Scenario) -> None:
    older = get(f"/api/recommendations/{scenario.assessments['A1']}/feedback")
    assert [(f["user"], f["channel"], f["verdict"], f["active"]) for f in older] == [
        ("Usuario sin nombre", "slack", "false_positive", True),  # never a piece of the e-mail (#91)
        ("Ana Analista", "frontend", "relevant", True),
        ("Ana Analista", "frontend", "wrong_priority", False),
    ]
    assert older[2]["proposed_level"] == "high"
    assert {f["on_older_version"] for f in older} == {True}  # A2 changed the score after A1
    latest = get(f"/api/recommendations/{scenario.assessments['A2']}/feedback")
    assert [(f["verdict"], f["on_older_version"]) for f in latest] == [("investigating", False)]
    assert get(f"/api/recommendations/{scenario.assessments['A4']}/feedback") == []
    assert get(f"/api/recommendations/{scenario.assessments['A1']}")["feedback_count"] == 2


def test_a_ticket_still_waiting_for_itop_gives_no_link(get: Get, scenario: Scenario) -> None:
    rec = get(f"/api/recommendations/{scenario.assessments['A4']}")
    assert (rec["cve"], rec["ticket_url"], rec["asset"]["finding_status"]) == ("CVE-2026-10003", None, "fixed")
