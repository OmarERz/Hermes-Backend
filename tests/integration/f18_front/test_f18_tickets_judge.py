"""F18.1: ticket summary and log, the judge detail and the FRO-13 reasons of the recommendations."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from f18data import Front
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

pytestmark = pytest.mark.integration
Get = Callable[..., Any]
TICKET = "https://itop.example.test/pages/UI.php?operation=details&class=UserRequest&id="


def test_ticket_summary_counts_statuses_urgency_and_resolution(get: Get) -> None:
    summary = get("/api/tickets/summary")
    assert summary["total"] == 3
    assert summary["by_status"] == {"pending_creation": 1, "open": 1, "resolved": 1, "closed": 0}
    # 777 holds urgency 1 in iTop; 778 was never synced: the band of its score (75, urgency 2).
    assert summary["by_urgency"] == {"1": 1, "2": 1, "3": 0, "4": 0}
    assert summary["changed_by_person"] == 1
    assert summary["resolved"] == 1 and summary["resolved_percent"] == "50.0"
    assert summary["avg_resolution_hours"] == "6.0"


def test_ticket_log_lists_actions_with_their_itop_write(get: Get, front: Front) -> None:
    items = get("/api/tickets/updates", ticket_itop_id="777")["items"]
    assert [i["id"] for i in items] == [str(front.updates["raise"]), str(front.updates["create"])]
    raised, created = items
    assert raised["action"] == "raise_urgency" and raised["label"] == "Urgencia subida"
    assert raised["itop_status"] == "failed" and created["itop_status"] == "done"
    assert created["assessment_id"] == str(front.scenario.assessments["A2"])
    assert created["ticket_ref"] == "R-000777" and created["ticket_url"] == f"{TICKET}777"
    assert created["cve"] == "CVE-2026-10001" and created["custodian"] == "Infraestructura Linux"
    assert [i["action"] for i in get("/api/tickets/updates", action="create")["items"]] == ["create"]
    first = get("/api/tickets/updates", limit=1)
    assert first["next_cursor"] and get("/api/tickets/updates", cursor=first["next_cursor"])["items"]
    assert get("/api/tickets/updates", ticket_itop_id="999")["items"] == []


def test_ticket_log_refuses_a_malformed_ticket_id(client: TestClient) -> None:
    for params in ({"ticket_itop_id": "R-1"}, {"action": "delete"}):
        assert client.get("/api/tickets/updates", params=params).status_code == 422


def test_ticket_list_gives_the_numeric_id_the_filters_take(get: Get, front: Front) -> None:
    """`itop_id` shows the iTop reference once it exists; `ticket_itop_id` (F18.4) is the numeric id the
    `ticket_itop_id` filters take, so a ticket picked from the list filters its log and its recommendations."""
    tickets = {t["itop_id"]: t for t in get("/api/tickets")["items"]}
    assert {shown: t["ticket_itop_id"] for shown, t in tickets.items()} == {"R-000777": "777", "778": "778"}
    picked = tickets["R-000777"]["ticket_itop_id"]
    log = get("/api/tickets/updates", ticket_itop_id=picked)["items"]
    assert [u["id"] for u in log] == [str(front.updates["raise"]), str(front.updates["create"])]
    assert {u["ticket_ref"] for u in log} == {"R-000777"}
    a = front.scenario.assessments
    by_ticket = {r["assessment_id"] for r in get("/api/recommendations", ticket_itop_id=picked)["items"]}
    assert by_ticket == {str(a["A1"]), str(a["A2"])}


def test_a_ticket_without_a_numeric_itop_id_lists_no_filter_id(get: Get, database: tuple[str, Engine]) -> None:
    """A demo ticket (`make demo` stores DEMO-n) is shown by `itop_id`, but its `ticket_itop_id` is null: the
    filters only take a numeric id, so the list never offers one they would refuse."""
    with database[1].begin() as conn:
        conn.execute(text("UPDATE ticket SET itop_ticket_id = 'DEMO-7' WHERE itop_ticket_id = '778'"))
    try:
        tickets = {t["itop_id"]: t["ticket_itop_id"] for t in get("/api/tickets")["items"]}
        assert tickets == {"R-000777": "777", "DEMO-7": None}
    finally:
        with database[1].begin() as conn:
            conn.execute(text("UPDATE ticket SET itop_ticket_id = '778' WHERE itop_ticket_id = 'DEMO-7'"))


def test_judge_detail_shows_reasons_quotes_and_the_double_review(get: Get, front: Front) -> None:
    detail = get(f"/api/recommendations/{front.scenario.assessments['A2']}/judge")
    assert detail["review_id"] == str(front.reviews["first"])
    assert detail["status"] == "applied" and detail["summary"] == "Explotación masiva reportada."
    assert detail["proposed_adjustment"] == 8 and detail["applied_adjustment"] == 8
    assert detail["dead_zone_applied"] is False
    assert [(r["code"], r["points"], r["quote"]) for r in detail["accepted_reasons"]] == [
        ("mass_exploitation", 8, "explotación masiva")
    ]
    rejected = detail["rejected_reasons"]
    assert [(r["code"], r["status"], r["rejection_rule"]) for r in rejected] == [("unverified_poc", "rejected", "L6")]
    assert detail["double_review"] == {
        "agreed": True,
        "first_adjustment": 8,
        "second_adjustment": 10,
        "second_status": "applied",
    }
    assert detail["mitigation_status"] == "accepted"
    assert not any(key in detail for key in ("calls", "parameters", "prompt_hash"))


def test_a_stale_double_review_has_no_agreement(get: Get, front: Front, database: tuple[str, Engine]) -> None:
    """A review that went stale is stored as `no_judge_review` without its comparison (RE-3): agreement unknown."""
    with database[1].begin() as conn:
        conn.execute(
            text("UPDATE llm_review SET status = 'no_judge_review' WHERE id = :i"), {"i": front.reviews["first"]}
        )
    try:
        detail = get(f"/api/recommendations/{front.scenario.assessments['A2']}/judge")
        assert detail["double_review"]["agreed"] is None and detail["double_review"]["second_adjustment"] == 10
    finally:
        with database[1].begin() as conn:
            conn.execute(text("UPDATE llm_review SET status = 'applied' WHERE id = :i"), {"i": front.reviews["first"]})


def test_judge_detail_without_a_review_keeps_the_base(get: Get, client: TestClient, front: Front) -> None:
    detail = get(f"/api/recommendations/{front.scenario.assessments['A1']}/judge")
    assert detail["review_id"] is None and detail["status"] is None and detail["applied_adjustment"] == 0
    assert detail["accepted_reasons"] == [] and detail["double_review"] is None
    missing = client.get("/api/recommendations/0196a6f0-0000-7000-8000-000000000999/judge")
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "not_found"
    assert client.get("/api/recommendations/not-a-uuid/judge").status_code == 422


def test_recommendations_carry_the_accepted_reasons_with_quotes(get: Get, front: Front) -> None:
    detail = get(f"/api/recommendations/{front.scenario.assessments['A2']}")
    assert detail["accepted_reasons"] == [
        {
            "code": "mass_exploitation",
            "label": detail["accepted_reasons"][0]["label"],
            "points": 8,
            "quote": "explotación masiva",
            "ci_id": None,
        }
    ]
    assert detail["judge_status"] == "applied" and detail["judge_summary"] == "Explotación masiva reportada."
    assert detail["ticket_itop_id"] == "777"
    plain = get(f"/api/recommendations/{front.scenario.assessments['A3']}")
    assert plain["accepted_reasons"] == [] and plain["judge_status"] is None


def test_recommendations_filter_by_ticket_level_verdict_and_feedback(get: Get, front: Front) -> None:
    a = front.scenario.assessments
    by_ticket = {r["assessment_id"] for r in get("/api/recommendations", ticket_itop_id="777")["items"]}
    assert by_ticket == {str(a["A1"]), str(a["A2"])}
    critical = {r["assessment_id"] for r in get("/api/recommendations", level="critical")["items"]}
    assert str(a["A2"]) in critical and str(a["A1"]) not in critical
    assert all(r["level"] == "critical" for r in get("/api/recommendations", level="critical")["items"])
    investigating = [r["assessment_id"] for r in get("/api/recommendations", verdict="investigating")["items"]]
    assert investigating == [str(a["A2"])]
    without = {r["assessment_id"] for r in get("/api/recommendations", without_feedback=True)["items"]}
    assert str(a["A3"]) in without and str(a["A1"]) not in without and str(a["A2"]) not in without
    with_feedback = {r["assessment_id"] for r in get("/api/recommendations", without_feedback=False)["items"]}
    assert with_feedback == {str(a["A1"]), str(a["A2"])}
