"""Contract events for the Slack module tests, built from the sample events in tests/fixtures/events/ (NOT-07)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from notifications_api import NotificationEvent

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "events"
EVENT_TYPES = ("new_ticket", "level_up", "reopened", "partially_fixed", "fixed", "threat_alert", "inferred_alert")


def raw(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    return data


def event(name: str, **changes: Any) -> NotificationEvent:
    """A sample event with top-level fields replaced; `ticket__custodian="X"` replaces a nested field."""
    data = copy.deepcopy(raw(name))
    for key, value in changes.items():
        target = data
        *path, last = key.split("__")
        for part in path:
            target = target[part]
        target[last] = value
    return NotificationEvent.model_validate(data)
