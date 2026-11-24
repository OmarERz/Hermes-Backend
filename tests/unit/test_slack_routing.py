"""Channels, audiences and threads (NOT-01, NOT-03, NOT-08, SLK-02, SLK-03)."""

from __future__ import annotations

import pytest

from doubles.slack_events import event
from notifications_slack.routing import Route, Router, thread_key
from notifications_slack.settings import SlackSettings

pytestmark = pytest.mark.unit
ROUTER = Router(
    {"infrastructure team": "C0INFRA001"},
    default_channel="C0DEFAULT1",
    urgent_channel="C0URGENT01",
    restricted_channel="C0SECRET01",
)


def test_an_immediate_event_goes_alone_to_the_urgent_channel() -> None:
    (route,) = ROUTER.routes(event("new_ticket", priority="immediate"))
    assert route == Route("standard", "C0URGENT01", thread_key(event("new_ticket")), digestible=False)


def test_without_an_urgent_channel_immediate_events_go_to_the_team() -> None:
    router = Router({"infrastructure team": "C0INFRA001"}, "C0DEFAULT1")
    assert router.routes(event("new_ticket", priority="immediate"))[0].channel == "C0INFRA001"


def test_other_events_go_to_the_custodian_team_and_may_wait_for_a_digest() -> None:
    (route,) = ROUTER.routes(event("new_ticket", priority="normal", ticket__custodian="INFRASTRUCTURE  team"))
    assert (route.channel, route.digestible) == ("C0INFRA001", True)
    (route,) = ROUTER.routes(event("new_ticket", priority="digest", ticket__custodian="Unknown Team"))
    assert route.channel == "C0DEFAULT1"


def test_alerts_have_no_ticket_thread_and_use_the_default_channel() -> None:
    routes = ROUTER.routes(event("threat_alert", priority="normal"))
    assert (routes[0].channel, routes[0].thread_key) == ("C0DEFAULT1", None)


def test_highly_classified_assets_add_a_restricted_copy_that_never_waits() -> None:
    sample = event("new_ticket", priority="normal")
    assets = [a.model_dump() for a in sample.assets]
    assets[0]["confidentiality"] = "highly_classified"
    routes = ROUTER.routes(event("new_ticket", priority="normal", assets=assets))
    assert [(r.audience, r.channel, r.digestible) for r in routes] == [
        ("standard", "C0INFRA001", True),
        ("restricted", "C0SECRET01", False),
    ]
    assert Router({}, "C0DEFAULT1").routes(event("new_ticket", assets=assets))[0].audience == "standard"


def test_thread_key_is_the_ticket_natural_key() -> None:
    first = thread_key(event("new_ticket"))
    assert first is not None
    assert len(first) == 64
    assert thread_key(event("fixed", ticket__itop_id="")) == thread_key(event("fixed"))  # no iTop id needed
    assert thread_key(event("new_ticket", ticket__custodian=" infrastructure TEAM")) == first
    assert thread_key(event("new_ticket", ticket__custodian="Apps")) != first


def test_the_default_channel_is_required() -> None:
    with pytest.raises(ValueError, match="SLACK_DEFAULT_CHANNEL"):
        Router.from_settings(SlackSettings(_env_file=None, _secrets_dir=None))  # type: ignore[call-arg]
