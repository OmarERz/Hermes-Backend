from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jsonschema
import pytest

from doubles.slack import SimulatedSlack, SlackDeliveryError

SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "schemas" / "notification_event.schema.json").read_text())

VALID_EVENT: dict[str, Any] = {
    "event_id": "evt-0001",
    "contract_version": "1.0",
    "type": "new_ticket",
    "priority": "immediate",
    "date": "2026-01-15T10:00:00Z",
    "ticket": {
        "itop_id": "R-000123",
        "url": "http://itop.test/pages/UI.php?operation=details&class=UserRequest&id=123",
        "custodian": "Platform Ops",
        "owners": [{"name": "Ana Rivera", "email": "ana.rivera@example.test"}],
        "urgency": 1,
        "fixed_cis": 0,
        "total_cis": 1,
    },
    "vulnerability": {"cve": "CVE-2026-0001", "product": "nginx 1.24.0", "cvss": 9.8, "in_kev": True},
    "alert": None,
    "score": {
        "base": 80,
        "judge_adjustment": 10,
        "final": 90,
        "level": "critical",
        "previous": None,
        "driving_ci": "web-frontend-01",
    },
    "assets": [
        {
            "ci_id": "100",
            "name": "web-frontend-01",
            "score": 90,
            "criticality": "medium",
            "exposed": True,
            "confidentiality": "public",
            "personal_data": False,
            "owner": "Ana Rivera",
            "status": "active",
        }
    ],
    "justification": "Exposed web server with a KEV vulnerability.",
    "mitigation": "Upgrade nginx to 1.25.",
    "mitigation_draft": None,
    "news": [],
    "assessment_id": "asm-1",
    "frontend_url": None,
}


def event(**changes: Any) -> dict[str, Any]:
    result = copy.deepcopy(VALID_EVENT)
    result.update(changes)
    jsonschema.validate(result, SCHEMA)
    return result


def test_sample_event_is_schema_valid() -> None:
    jsonschema.validate(VALID_EVENT, SCHEMA)


def test_stores_messages_from_mappings_and_objects() -> None:
    slack = SimulatedSlack()
    slack.process(event(event_id="e1"))
    slack.process(SimpleNamespace(event_id="e2", type="fixed", priority="normal"))
    assert [m.event_id for m in slack.sent] == ["e1", "e2"]
    assert [m.event_type for m in slack.of_type("fixed")] == ["fixed"]
    assert slack.sent[0].event_type == "new_ticket"
    assert slack.sent[0].priority == "immediate"


def test_is_idempotent_by_event_id() -> None:
    slack = SimulatedSlack()
    slack.process(event())
    slack.process(event())
    assert len(slack.sent) == 1
    assert slack.duplicates == 1
    assert slack.attempts == 2


def test_fail_next_raises_then_recovers() -> None:
    slack = SimulatedSlack()
    slack.fail_next(2)
    for _ in range(2):
        with pytest.raises(SlackDeliveryError):
            slack.process(event())
    slack.process(event())
    assert len(slack.sent) == 1
    assert slack.attempts == 3


def test_event_without_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="event_id"):
        SimulatedSlack().process({"type": "fixed"})
