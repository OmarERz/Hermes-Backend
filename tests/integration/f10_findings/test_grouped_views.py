"""Grouped views, group detail and CI detail against PostgreSQL (FRO-09 to FRO-11, D-035)."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

import pytest
from f10data import T2, Scenario, Spec, add_assessment
from fastapi.testclient import TestClient
from sqlalchemy import delete
from sqlalchemy.orm import Session

from core.db import models as m

pytestmark = pytest.mark.integration
Get = Callable[..., Any]
F = ("0.8", "1.0", "0.0")  # S, P, T of an assessment without CVSS


def ids(scenario: Scenario, groups: list[dict[str, Any]]) -> list[str]:
    names = {str(v): k for k, v in scenario.groups.items()}
    return [names[g["group_id"]] for g in groups]


def test_vulnerability_view_orders_groups_by_their_current_final(get: Get, scenario: Scenario) -> None:
    body = get("/api/vulnerabilities")
    assert body["view"] == "vulnerability" and body["next_cursor"] is None
    g1, g2, g3 = body["groups"]
    assert ids(scenario, body["groups"]) == ["G1", "G2", "G3"]
    # G1: CI-2 is fixed and CI-4 decommissioned, so CI-1 (90) speaks for the group.
    assert g1 | {"group_id": "-", "last_seen": "-"} == {
        "group_id": "-",
        "cve": "CVE-2026-10001",
        "product": "OpenSSL",
        "ci_count": 1,
        "custodians": ["Infraestructura Linux"],
        "tickets": ["R-000777"],
        "final": 90,
        "level": "critical",
        "in_kev": True,
        "owners": ["Dueña de Pagos"],
        "classification": "highly_classified",
        "exposed": True,
        "status": "new",
        "last_seen": "-",
        "cvss": "9.8",
        "severity": "critical",
        "match_sources": ["nvd_cpe"],
    }
    assert g1["last_seen"] == "2026-11-22T12:00:00Z"
    assert (g2["final"], g2["level"], g2["ci_count"], g2["in_kev"]) == (75, "high", 2, False)
    # Rehearsal 2, P2-D: a group scored without CVSS says so (docs/06 §S, ESC-14)
    assert (g2["cvss"], g2["severity"]) == (None, "unrated")
    assert (g3["cvss"], g3["severity"]) == ("5.0", "medium")
    # Every finding of G3 is fixed: its last scores still show.
    assert (g3["final"], g3["level"], g3["status"], g3["ci_count"], g3["exposed"]) == (30, "low", "fixed", 0, False)
    assert g3["classification"] == "classified"


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"band": "critical"}, ["G1"]),
        ({"band": "high"}, ["G2"]),
        ({"custodian": "Infraestructura Linux"}, ["G1", "G2", "G3"]),
        ({"custodian": "Seguridad"}, []),
        ({"owner": "Dueña de Pagos"}, ["G1", "G2", "G3"]),
        ({"classification": "classified"}, ["G3"]),
        ({"exposed": "false"}, ["G3"]),
        ({"in_kev": "true"}, ["G1"]),
        ({"status": "fixed"}, ["G3"]),
        ({"status": "new"}, ["G1", "G2"]),
        ({"date_to": "2026-11-21T12:00:00Z"}, ["G3"]),
        ({"date_from": "2026-11-22T00:00:00Z", "date_to": "2026-11-22T12:00:00Z"}, ["G1", "G2"]),
    ],
)
def test_filters_apply_to_the_vulnerability_view(
    get: Get, scenario: Scenario, params: dict[str, str], expected: list[str]
) -> None:
    assert ids(scenario, get("/api/vulnerabilities", **params)["groups"]) == expected


def test_criticality_view_counts_the_whole_result_and_pages_over_the_finals(get: Get, scenario: Scenario) -> None:
    first = get("/api/vulnerabilities", view="criticality", limit=2)
    counts = [(b["level"], b["count"]) for b in first["bands"]]
    assert counts == [("critical", 1), ("high", 1), ("medium", 0), ("low", 1)]
    assert [ids(scenario, b["groups"]) for b in first["bands"]] == [["G1"], ["G2"], [], []]
    second = get("/api/vulnerabilities", view="criticality", limit=2, cursor=first["next_cursor"])
    assert [ids(scenario, b["groups"]) for b in second["bands"]] == [[], [], [], ["G3"]]
    assert second["next_cursor"] is None


def test_asset_view_shows_the_risk_of_each_ci_never_a_sum(get: Get) -> None:
    assets = get("/api/vulnerabilities", view="asset")["assets"]
    assert [(a["ci_id"], a["risk"], a["status"]) for a in assets] == [
        ("CI-1", 90, "new"),
        ("CI-3", 75, "new"),
        ("CI-2", 62, "fixed"),
    ]
    ci1 = assets[0]
    assert ci1["findings_by_level"] == {"critical": 1, "high": 0, "medium": 1, "low": 0}
    assert (ci1["in_kev"], ci1["classification"], ci1["owner"], ci1["custodian"], ci1["exposed"]) == (
        1,
        "highly_classified",
        "Dueña de Pagos",
        "Infraestructura Linux",
        True,
    )
    orphan = assets[1]
    assert (orphan["owner"], orphan["custodian"], orphan["exposed"], orphan["classification"]) == (
        None,
        None,
        False,
        "unclassified",
    )


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"exposed": "false"}, ["CI-3", "CI-2"]),
        ({"band": "critical"}, ["CI-1"]),
        ({"custodian": "Infraestructura Linux"}, ["CI-1", "CI-2"]),
        ({"in_kev": "false"}, ["CI-3"]),
        ({"status": "fixed"}, ["CI-2"]),
        ({"classification": "unclassified"}, ["CI-3"]),
    ],
)
def test_filters_apply_to_the_asset_view(get: Get, params: dict[str, str], expected: list[str]) -> None:
    assert [a["ci_id"] for a in get("/api/vulnerabilities", view="asset", **params)["assets"]] == expected


def test_same_cve_scores_differently_per_ci(get: Get, scenario: Scenario) -> None:
    detail = get(f"/api/vulnerabilities/{scenario.groups['G2']}")
    assert [(a["ci_id"], a["score"]) for a in detail["assets"]] == [("CI-3", 75), ("CI-1", 70)]


def test_pages_chain_with_signed_cursors(get: Get, client: TestClient, scenario: Scenario) -> None:
    seen: list[str] = []
    cursor = None
    while True:
        body = get("/api/vulnerabilities", limit=1, **({"cursor": cursor} if cursor else {}))
        seen += ids(scenario, body["groups"])
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert seen == ["G1", "G2", "G3"]
    asset_cursor = get("/api/vulnerabilities", view="asset", limit=1)["next_cursor"]
    wrong_list = client.get("/api/vulnerabilities", params={"cursor": asset_cursor})
    assert (wrong_list.status_code, wrong_list.json()["error"]["code"]) == (400, "invalid_cursor")


def test_group_detail_lists_each_scored_ci_with_its_snapshot(get: Get, scenario: Scenario) -> None:
    detail = get(f"/api/vulnerabilities/{scenario.groups['G1']}")
    assert detail["description"] == "Desbordamiento sintético para la demo"
    assert (detail["final"], detail["cvss"], detail["severity"]) == (90, "9.8", "critical")
    unrated = get(f"/api/vulnerabilities/{scenario.groups['G2']}")
    assert (unrated["cvss"], unrated["severity"]) == (None, "unrated")
    ci1, ci2 = detail["assets"]
    assert ci1 == {
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
        "finding_id": str(scenario.findings[("G1", "CI-1")]),
        "match_source": "nvd_cpe",
        "certainty": "1.0",
    }
    assert (ci2["ci_id"], ci2["finding_status"], ci2["score"]) == ("CI-2", "fixed", 62)
    assert ci2["finding_id"] == str(scenario.findings[("G1", "CI-2")])
    assert (ci2["classification"], ci2["classification_at_evaluation"]) == ("classified", "public")


def test_a_ci_row_shows_the_cvss_of_its_own_assessment(get: Get, scenario: Scenario, database: Any) -> None:
    """F15.12 review (P2-D): the CI detail shows each finding with that CI's score; its CVSS and severity come from the
    same assessment. A later assessment of G1 without CVSS that scores only CI-1 leaves CI-2 on A2 (CVSS 9.8)."""
    with Session(database[1]) as session, session.begin():
        later = add_assessment(session, scenario, Spec("G1", T2, {"CI-1": (80, 0, 80)}, cvss=None, factors=F))
    try:
        g1 = next(g for g in get("/api/vulnerabilities")["groups"] if g["cve"] == "CVE-2026-10001")
        assert (g1["cvss"], g1["severity"]) == (None, "unrated")  # CI-1 speaks for the group, from the later one
        row = next(f for f in get("/api/assets/CI-2")["findings"] if f["cve"] == "CVE-2026-10001")
        assert (row["final"], row["cvss"], row["severity"]) == (62, "9.8", "critical")
    finally:
        with Session(database[1]) as session, session.begin():
            session.execute(delete(m.AssetScore).where(m.AssetScore.assessment_id == later))
            session.execute(delete(m.Assessment).where(m.Assessment.id == later))


def test_the_finding_id_of_an_asset_opens_its_history(get: Get, scenario: Scenario) -> None:
    """F13.8: a client reaches GET /api/findings/{id}/history from the vulnerability detail alone."""
    detail = get(f"/api/vulnerabilities/{scenario.groups['G1']}")
    points = get(f"/api/findings/{detail['assets'][0]['finding_id']}/history")
    assert points
    assert points[-1]["final"] == detail["assets"][0]["score"]


def test_asset_detail_carries_the_score_of_that_ci(get: Get, scenario: Scenario) -> None:
    detail = get("/api/assets/CI-1")
    assert (detail["ci_id"], detail["name"], detail["risk"], detail["classification"]) == (
        "CI-1",
        "srv-pagos-01",
        90,
        "highly_classified",
    )
    assert [(ids(scenario, [f])[0], f["final"], f["level"]) for f in detail["findings"]] == [
        ("G1", 90, "critical"),
        ("G2", 70, "medium"),  # the group says 75 (CI-3); this CI's own score is 70
    ]
    fixed_only = get("/api/assets/CI-2")
    assert fixed_only["risk"] == 62 and {f["status"] for f in fixed_only["findings"]} == {"fixed"}


@pytest.mark.parametrize(
    "url",
    [
        f"/api/vulnerabilities/{uuid.UUID(int=1)}",
        "/api/assets/CI-404",
        "/api/assets/CI-4",  # decommissioned
    ],
)
def test_unknown_or_retired_resources_answer_404(client: TestClient, url: str) -> None:
    response = client.get(url)
    assert (response.status_code, response.json()["error"]["code"]) == (404, "not_found")
