from __future__ import annotations

from dataclasses import dataclass

import pytest

from doubles.slack import SimulatedSlack, SlackDeliveryError


@dataclass
class Event:
    event_id: str
    event_type: str
    priority: str


def test_stores_messages_from_mappings_and_objects() -> None:
    slack = SimulatedSlack()
    slack.process({"event_id": "e1", "event_type": "new_ticket", "priority": "immediate"})
    slack.process(Event("e2", "fixed", "normal"))
    assert [m.event_id for m in slack.sent] == ["e1", "e2"]
    assert [m.event_type for m in slack.of_type("fixed")] == ["fixed"]
    assert slack.sent[0].priority == "immediate"


def test_is_idempotent_by_event_id() -> None:
    slack = SimulatedSlack()
    event = {"event_id": "e1", "event_type": "new_ticket"}
    slack.process(event)
    slack.process(event)
    assert len(slack.sent) == 1
    assert slack.duplicates == 1
    assert slack.attempts == 2


def test_fail_next_raises_then_recovers() -> None:
    slack = SimulatedSlack()
    slack.fail_next(2)
    for _ in range(2):
        with pytest.raises(SlackDeliveryError):
            slack.process({"event_id": "e1"})
    slack.process({"event_id": "e1"})
    assert len(slack.sent) == 1
    assert slack.attempts == 3


def test_event_without_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="event_id"):
        SimulatedSlack().process({"event_type": "fixed"})
