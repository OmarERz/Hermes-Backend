"""The least-privilege iTop profile of the backend (C16, F12.3): what it may read and write.

Read on the change history is what lets TicketStateSync tell our urgency changes from a person's (D-007); iTop keeps
the `*` group for business classes, so the History group needs its own grant (checked live on iTop 3.2.2).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

DATAMODEL = (
    Path(__file__).resolve().parents[2]
    / "docker/itop/extensions/hermes-ci-attributes/datamodel.hermes-ci-attributes.xml"
)


def grants() -> dict[str, set[str]]:
    """Group -> allowed actions of the "Hermes Backend" profile (a plain reading of its XML block)."""
    text = DATAMODEL.read_text(encoding="utf-8")
    profile = re.search(r"<name>Hermes Backend</name>(.*?)</profile>", text, re.S)
    assert profile, "the Hermes Backend profile is missing"
    body = re.sub(r"<!--.*?-->", "", profile.group(1), flags=re.S)
    return {
        group: set(re.findall(r'<action id="([^"]+)">allow</action>', actions))
        for group, actions in re.findall(r'<group id="([^"]+)">(.*?)</group>', body, re.S)
    }


def test_the_history_is_readable_and_never_writable() -> None:
    assert grants()["History"] == {"action:read", "action:bulk read"}


def test_writes_stay_on_tickets_only() -> None:
    writers = {group for group, actions in grants().items() if any("write" in action for action in actions)}
    assert writers == {"Ticketing", "UserRequest"}


def test_the_cmdb_stays_read_only() -> None:
    assert grants()["*"] == {"action:read", "action:bulk read"}
