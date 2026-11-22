"""Ticket event payloads follow schemas/notification_event.schema.json (NOT-03)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from core.notifications.events import (
    TicketEvent,
    complete_ticket_link,
    justification,
    ticket_event_payload,
    ticket_url,
)
from core.tickets.content import CiLine, NewsLine, ReasonLine, TicketContext

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "schemas" / "notification_event.schema.json").read_text(encoding="utf-8"))
NOW = datetime(2026, 11, 22, 12, tzinfo=UTC)
EVENT_ID = uuid.UUID("01936b2e-0000-7000-8000-000000000001")


def line(name: str, score: int | None, *, fixed: bool = False, owner: str | None = "Ana") -> CiLine:
    return CiLine(f"id-{name}", name, score, "unknown", None, "unclassified", None, owner, "p1", None, fixed)


CONTEXT = TicketContext(
    cve="CVE-2026-1000",
    product="nginx",
    custodian="Ops",
    custodian_itop_id="10",
    cis=[line("web-01", 91), line("web-02", 40, owner="Ana"), line("old", None, fixed=True, owner=None)],
    score=91,
    driving_ci="web-01",
    base=85,
    judge_adjustment=6,
    reasons=[ReasonLine("mass_exploitation", 6)],
    news=[NewsLine("<b>t</b>", "https://n.example.test", "THN", "2026-11-20")],
    cvss=None,
    in_kev=False,
)


def test_a_new_ticket_payload_is_valid_and_complete() -> None:
    event = TicketEvent("new_ticket", "immediate", 1, None, uuid.uuid4())
    payload = ticket_event_payload(EVENT_ID, event, CONTEXT, ("", ""), NOW)
    jsonschema.validate(payload, SCHEMA)
    assert payload["date"] == "2026-11-22T12:00:00Z"
    assert payload["ticket"]["owners"] == [{"name": "Ana", "email": None}]
    assert (payload["ticket"]["fixed_cis"], payload["ticket"]["total_cis"]) == (1, 3)
    assert payload["score"] == {
        "base": 85,
        "judge_adjustment": 6,
        "final": 91,
        "level": "critical",
        "previous": None,
        "driving_ci": "web-01",
    }
    assert payload["assets"][0]["exposed"] is False  # unknown exposure (P-013)
    assert payload["assets"][2]["status"] == "fixed"
    assert payload["justification"].startswith("Puntuación 91 (Crítica) impulsada por web-01")
    assert "mass_exploitation (+6)" in payload["justification"]


def test_a_fixed_payload_without_score_is_valid() -> None:
    fixed = TicketContext(
        cve="CVE-2026-1", product="p", custodian="c", custodian_itop_id="1", cis=[line("a", None, fixed=True)]
    )
    payload = ticket_event_payload(EVENT_ID, TicketEvent("fixed", "digest", None, 55, None), fixed, ("7", "u"), NOW)
    jsonschema.validate(payload, SCHEMA)
    assert (payload["score"], payload["ticket"]["urgency"], payload["assessment_id"]) == (None, 4, None)
    assert justification(fixed, None) == "No quedan CIs vigentes en este ticket."


def test_ticket_links() -> None:
    assert ticket_url(None, "5") == ""
    assert ticket_url("https://itop.example.test/", None) == ""
    assert ticket_url("https://itop.example.test/", "5") == (
        "https://itop.example.test/pages/UI.php?operation=details&class=UserRequest&id=5"
    )
    payload = ticket_event_payload(EVENT_ID, TicketEvent("new_ticket", "normal", 2, None, None), CONTEXT, ("", ""), NOW)
    completed = complete_ticket_link(payload, "42", "https://itop.example.test")
    assert completed["ticket"]["itop_id"] == "42"
    assert completed["ticket"]["url"].endswith("&id=42")
    assert payload["ticket"]["itop_id"] == ""  # the original is not modified
    moved = complete_ticket_link(completed, "43", "https://itop.example.test")
    assert moved["ticket"]["url"].endswith("&id=43")  # a new id never keeps the old link
    assert complete_ticket_link(completed, "42", None)["ticket"]["url"].endswith("&id=42")


def test_owners_follow_the_contacts_order_and_identity() -> None:
    twins = TicketContext(
        cve="CVE-2026-1",
        product="p",
        custodian="c",
        custodian_itop_id="1",
        cis=[
            CiLine("a", "a", 50, "low", None, "public", None, "Ana", "p1", "a1@example.test"),
            CiLine("b", "b", 90, "low", None, "public", None, "Ana", "p2", "a2@example.test"),
        ],
        score=90,
        driving_ci="b",
        judge_adjustment=5,
    )
    payload = ticket_event_payload(
        EVENT_ID, TicketEvent("new_ticket", "immediate", 1, None, None), twins, ("", ""), NOW
    )
    assert payload["ticket"]["owners"] == [
        {"name": "Ana", "email": "a2@example.test"},
        {"name": "Ana", "email": "a1@example.test"},
    ]
    assert payload["score"]["base"] == 85  # unknown base: final minus the adjustment


def test_naive_dates_are_refused() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        ticket_event_payload(
            EVENT_ID,
            TicketEvent("fixed", "digest", None, None, None),
            CONTEXT,
            ("", ""),
            datetime.fromisoformat("2026-11-22T12:00:00"),
        )
