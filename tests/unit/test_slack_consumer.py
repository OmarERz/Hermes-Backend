"""`SlackConsumer` with the sample events (NOT-07 acceptance): right channel, threads, idempotency, retries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from doubles.slack_events import EVENT_TYPES, event, raw
from doubles.slack_web import FakeWebClient
from notifications_api import NotificationConsumer
from notifications_slack.consumer import SlackConsumer
from notifications_slack.gateway import SlackError, SlackGateway
from notifications_slack.routing import Router, thread_key
from notifications_slack.store import InMemorySlackStore

pytestmark = pytest.mark.unit
T0 = datetime(2026, 11, 23, 10, 0, tzinfo=UTC)
TEAM, DEFAULT, URGENT, SECRET = "C0INFRA001", "C0DEFAULT1", "C0URGENT01", "C0SECRET01"


class Setup:
    def __init__(self) -> None:
        self.client = FakeWebClient()
        self.store = InMemorySlackStore()
        self.now = T0
        router = Router({"infrastructure team": TEAM}, DEFAULT, URGENT, SECRET)
        gateway = SlackGateway(self.client, max_wait=0, sleep=lambda _: None)
        self.consumer = SlackConsumer(self.store, gateway, router, timedelta(seconds=120), clock=lambda: self.now)


@pytest.fixture
def s() -> Setup:
    return Setup()


def test_it_is_a_notification_consumer(s: Setup) -> None:
    consumer: NotificationConsumer = s.consumer
    assert consumer is s.consumer


@pytest.mark.parametrize(
    ("name", "channel"),
    [("new_ticket", URGENT), ("level_up", URGENT), ("reopened", URGENT), ("threat_alert", URGENT)],
)
def test_immediate_samples_are_posted_at_once_in_the_urgent_channel(s: Setup, name: str, channel: str) -> None:
    s.consumer.process(event(name, priority="immediate"))
    (post,) = s.client.posts()
    assert post["channel"] == channel
    assert "thread_ts" not in post


@pytest.mark.parametrize("name", EVENT_TYPES)
def test_other_samples_wait_for_the_digest_of_their_channel(s: Setup, name: str) -> None:
    sample = event(name, priority="normal")
    s.consumer.process(sample)
    assert s.client.posts() == []
    expected = DEFAULT if sample.ticket is None else TEAM
    assert s.store.due_channels(T0 + timedelta(seconds=120)) == [expected]


def test_delivery_is_idempotent_by_event_id(s: Setup) -> None:
    sample = event("new_ticket")
    s.consumer.process(sample)
    s.consumer.process(sample)  # redelivered by the outbox (at least once)
    assert len(s.client.posts()) == 1
    queued = event("level_up")
    s.consumer.process(queued)
    s.consumer.process(queued)
    assert len(s.store.due_items(TEAM, T0 + timedelta(seconds=120))) == 1


def test_follow_ups_go_to_the_ticket_thread_and_level_up_moves_its_root(s: Setup) -> None:
    s.consumer.process(event("new_ticket"))  # immediate: the thread root in the urgent channel
    root = s.client.posts()[0]
    s.consumer.process(event("partially_fixed", priority="normal"))
    reply = s.client.posts()[1]
    assert reply["channel"] == URGENT
    assert reply["thread_ts"] == "1700000000.000001"
    assert root["channel"] == URGENT
    s.consumer.process(event("level_up", event_id="evt-up-2", priority="immediate"))
    s.consumer.process(event("fixed", event_id="evt-fixed-2", priority="digest"))
    assert s.client.posts()[-1]["thread_ts"] == "1700000000.000003"  # the new root
    key = thread_key(event("new_ticket"))
    assert key is not None
    thread = s.store.thread(key, "standard")
    assert thread is not None
    assert thread.root_ts == "1700000000.000003"


def test_a_follow_up_without_a_thread_is_its_own_message(s: Setup) -> None:
    s.consumer.process(event("fixed", priority="immediate"))
    (post,) = s.client.posts()
    assert "thread_ts" not in post


def highly_classified(**changes: Any) -> Any:
    assets = raw("new_ticket")["assets"]
    assets[0]["confidentiality"] = "highly_classified"
    return event("new_ticket", assets=assets, **changes)


def test_highly_classified_assets_get_a_full_restricted_copy(s: Setup) -> None:
    s.consumer.process(highly_classified())
    standard, restricted = s.client.posts()
    assert (standard["channel"], restricted["channel"]) == (URGENT, SECRET)
    assert "srv-example-01" not in str(standard["blocks"])
    assert "srv-example-01" in str(restricted["blocks"])


def test_a_failed_post_raises_for_the_outbox_and_is_retried_once(s: Setup) -> None:
    s.client.fail("chat.postMessage", "internal_error", status=500)
    with pytest.raises(SlackError):
        s.consumer.process(event("new_ticket"))
    s.consumer.process(event("new_ticket"))
    assert len(s.client.posts()) == 2  # the failed attempt and the retry
    assert s.store.is_known("evt-sample-new_ticket", "standard")


def test_a_partial_failure_only_retries_the_missing_copy(s: Setup) -> None:
    sample = highly_classified()
    original = s.client.api_call
    calls = {"n": 0}

    def flaky(method: str, **kwargs: Any) -> Any:
        if method == "chat.postMessage":
            calls["n"] += 1
            if calls["n"] == 2:  # the restricted copy fails once
                s.client.fail("chat.postMessage", "internal_error", status=503)
        return original(method, **kwargs)

    s.client.api_call = flaky  # type: ignore[method-assign]
    with pytest.raises(SlackError):
        s.consumer.process(sample)
    s.consumer.process(sample)
    channels = [p["channel"] for p in s.client.posts()]
    assert channels == [URGENT, SECRET, SECRET]  # the standard copy was not posted again


def test_a_missing_team_channel_falls_back_to_the_default_one(s: Setup) -> None:
    s.client.fail("chat.postMessage", "channel_not_found")
    s.consumer.process(event("new_ticket", priority="immediate"))
    assert [p["channel"] for p in s.client.posts()] == [URGENT, DEFAULT]


def test_the_restricted_copy_never_falls_back(s: Setup) -> None:
    sample = highly_classified()
    s.consumer.process(event("new_ticket", event_id="warm-up"))  # unrelated
    original = s.client.api_call

    def refuse_secret(method: str, **kwargs: Any) -> Any:
        if method == "chat.postMessage" and (kwargs.get("json") or {}).get("channel") == SECRET:
            s.client.fail("chat.postMessage", "not_in_channel")
        return original(method, **kwargs)

    s.client.api_call = refuse_secret  # type: ignore[method-assign]
    with pytest.raises(SlackError, match="not_in_channel"):
        s.consumer.process(sample)
    assert DEFAULT not in [p["channel"] for p in s.client.posts()]


def test_a_permanent_error_in_the_default_channel_is_raised(s: Setup) -> None:
    s.client.fail("chat.postMessage", "invalid_blocks")
    with pytest.raises(SlackError, match="invalid_blocks"):
        s.consumer.process(event("new_ticket"))
