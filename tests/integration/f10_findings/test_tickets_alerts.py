"""Tickets and threat alerts against PostgreSQL (D-036, TIC-03, mode 2)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration
Get = Callable[..., Any]


def test_tickets_in_itop_most_urgent_first(get: Get) -> None:
    body = get("/api/tickets")
    assert body["next_cursor"] is None
    assert body["items"] == [
        {
            "itop_id": "R-000777",
            "url": "https://itop.example.test/pages/UI.php?operation=details&class=UserRequest&id=777",
            "cve": "CVE-2026-10001",
            "custodian": "Infraestructura Linux",
            "urgency": 1,
            "status": "Abierto",
            "fixed_cis": 1,
            "total_cis": 2,
            "ticket_itop_id": "777",  # F18.4: the numeric id the filters take, next to the reference shown
        },
        {
            "itop_id": "778",
            "url": "https://itop.example.test/pages/UI.php?operation=details&class=UserRequest&id=778",
            "cve": "CVE-2026-10002",
            "custodian": "Seguridad",
            "urgency": 2,  # not synced yet: the band of its score (75)
            "status": "Resuelto",
            "fixed_cis": 0,
            "total_cis": 1,
            "ticket_itop_id": "778",
        },
    ]  # the ticket still waiting for iTop is not listed


def test_tickets_filter_by_urgency_and_page(get: Get, client: TestClient) -> None:
    assert [t["itop_id"] for t in get("/api/tickets", urgency=2)["items"]] == ["778"]
    assert get("/api/tickets", urgency=4)["items"] == []
    first = get("/api/tickets", limit=1)
    second = get("/api/tickets", limit=1, cursor=first["next_cursor"])
    assert [t["itop_id"] for t in first["items"] + second["items"]] == ["R-000777", "778"]
    assert second["next_cursor"] is None
    assert client.get("/api/tickets", params={"urgency": 5}).status_code == 422


def test_alerts_newest_first_without_r4(get: Get) -> None:
    body = get("/api/alerts")
    assert [(a["relevance"], a["inferred"]) for a in body["items"]] == [("inferred", True), ("R3", False)]
    inferred, r3 = body["items"]
    assert (inferred["ci_id"], inferred["summary"], inferred["actor"]) == (
        "CI-1",
        "Componente probable en srv-pagos-01.",
        None,
    )
    assert (r3["actor"], r3["victim"], r3["vector"], r3["ci_id"]) == ("Actor Uno", "Empresa Par", "phishing", None)
    assert r3["summary"] == "Campaña contra el sector financiero."
    assert r3["created_at"] == "2026-11-21T12:00:00Z"


def test_alerts_page_with_their_own_cursor(get: Get, client: TestClient) -> None:
    first = get("/api/alerts", limit=1)
    second = get("/api/alerts", limit=1, cursor=first["next_cursor"])
    assert [a["relevance"] for a in first["items"] + second["items"]] == ["inferred", "R3"]
    assert second["next_cursor"] is None
    tickets_cursor = get("/api/tickets", limit=1)["next_cursor"]
    assert client.get("/api/alerts", params={"cursor": tickets_cursor}).status_code == 400
