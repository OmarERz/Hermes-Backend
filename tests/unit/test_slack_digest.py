"""Channel digests (SLK-07): top 10 + count, details in the thread, item by item, NOT-02 retries for queued events."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from doubles.slack_events import event
from doubles.slack_web import FakeWebClient
from notifications_slack.digest import DigestPublisher
from notifications_slack.gateway import SlackGateway
from notifications_slack.routing import thread_key
from notifications_slack.store import InMemorySlackStore

pytestmark = pytest.mark.unit
T0 = datetime(2026, 11, 23, 10, 0, tzinfo=UTC)
WINDOW = timedelta(seconds=120)
TEAM = "C0INFRA001"
DEFAULT = "C0DEFAULT1"


class Setup:
    def __init__(self) -> None:
        self.client = FakeWebClient()
        self.store = InMemorySlackStore()
        self.now = T0
        gateway = SlackGateway(self.client, max_wait=0, sleep=lambda _: None)
        self.publisher = DigestPublisher(self.store, gateway, clock=lambda: self.now, fallback_channel=DEFAULT)

    def queue(self, count: int, *, every: timedelta = timedelta(0), **changes: object) -> list[str]:
        ids = []
        for i in range(count):
            at = T0 + every * i
            sample = event(
                "new_ticket",
                event_id=f"evt-{i:02d}",
                priority="normal",
                score__final=40 + i,
                vulnerability__cve=f"CVE-2099-{i:04d}",
                **changes,
            )
            self.store.enqueue(sample.event_id, TEAM, sample.model_dump(mode="json"), at, due=at + WINDOW)
            ids.append(sample.event_id)
        return ids


@pytest.fixture
def s() -> Setup:
    return Setup()


def test_nothing_goes_out_before_the_window(s: Setup) -> None:
    s.queue(3)
    s.now = T0 + WINDOW - timedelta(seconds=1)
    assert s.publisher.publish_due() == 0
    assert s.client.posts() == []


def test_a_digest_lists_the_top_ten_and_details_every_event_in_its_thread(s: Setup) -> None:
    s.queue(12)
    s.now = T0 + WINDOW
    assert s.publisher.publish_due() == 12
    summary, *replies = s.client.posts()
    assert "thread_ts" not in summary
    assert "Resumen · 12 avisos" in str(summary["blocks"])
    assert "_y 2 más._" in str(summary["blocks"])
    assert len(replies) == 12
    assert {r["thread_ts"] for r in replies} == {"1700000000.000001"}
    assert "CVE-2099-0011" in str(replies[0]["blocks"])  # highest score first
    assert all(r["blocks"][-1]["type"] == "actions" for r in replies)  # every event keeps its buttons
    assert s.store.due_channels(s.now + timedelta(days=1)) == []
    record = s.store.deliveries[("evt-00", "standard")]
    assert (record.kind, record.channel_id) == ("digest", TEAM)
    key = thread_key(event("new_ticket", vulnerability__cve="CVE-2099-0000"))
    assert key is not None
    thread = s.store.thread(key, "standard")
    assert thread is not None
    assert thread.root_ts == "1700000000.000001"  # follow-ups of these tickets go to the digest's thread


def test_a_single_event_is_posted_on_its_own(s: Setup) -> None:
    s.queue(1)
    s.now = T0 + WINDOW
    assert s.publisher.publish_due() == 1
    (post,) = s.client.posts()
    assert "Resumen" not in str(post["blocks"])
    assert s.store.deliveries[("evt-00", "standard")].kind == "message"


def test_an_interrupted_digest_continues_in_the_same_thread(s: Setup) -> None:
    s.queue(4)
    s.now = T0 + WINDOW
    original = s.client.api_call
    posts = {"n": 0}

    def rate_limit_third_post(method: str, **kwargs: object) -> object:
        if method == "chat.postMessage":
            posts["n"] += 1
            if posts["n"] == 4:  # summary, reply 1, reply 2, then a rate limit
                s.client.fail("chat.postMessage", "ratelimited", status=429, retry_after=60)
        return original(method, **kwargs)

    s.client.api_call = rate_limit_third_post  # type: ignore[method-assign]
    assert s.publisher.publish_due() == 2
    left = s.store.due_items(TEAM, s.now)
    assert [i.digest_ts for i in left] == ["1700000000.000001"]  # the third waits 1 minute, the fourth is due
    s.now += timedelta(minutes=1)
    assert s.publisher.publish_due() == 2
    replies = [p for p in s.client.posts() if "thread_ts" in p]
    assert {r["thread_ts"] for r in replies} == {"1700000000.000001"}
    summaries = [p for p in s.client.posts() if "thread_ts" not in p]
    assert len(summaries) == 1  # no second summary
    assert len({(k, v.message_ts) for k, v in s.store.deliveries.items()}) == 4  # each event posted once


def test_a_permanent_error_fails_only_that_item(s: Setup) -> None:
    s.queue(3)
    s.now = T0 + WINDOW
    original = s.client.api_call
    posts = {"n": 0}

    def reject_second_reply(method: str, **kwargs: object) -> object:
        if method == "chat.postMessage":
            posts["n"] += 1
            if posts["n"] == 3:
                s.client.fail("chat.postMessage", "msg_too_long")
        return original(method, **kwargs)

    s.client.api_call = reject_second_reply  # type: ignore[method-assign]
    assert s.publisher.publish_due() == 2
    failed = [eid for eid in ("evt-00", "evt-01", "evt-02") if s.store.status_of(eid)]
    assert len(failed) == 1
    status = s.store.status_of(failed[0])
    assert status == ("failed", 1, "msg_too_long")


def test_a_failed_summary_retries_every_item_later(s: Setup) -> None:
    s.queue(2)
    s.now = T0 + WINDOW
    s.client.fail("chat.postMessage", "internal_error", status=500)
    assert s.publisher.publish_due() == 0
    assert s.store.status_of("evt-00") == ("queued", 1, "internal_error")
    assert s.store.due_items(TEAM, s.now) == []
    s.now += timedelta(minutes=1)
    assert s.publisher.publish_due() == 2


def test_a_single_event_with_a_permanent_error_fails(s: Setup) -> None:
    s.queue(1)
    s.now = T0 + WINDOW
    s.client.fail("chat.postMessage", "invalid_blocks")
    assert s.publisher.publish_due() == 0
    assert s.store.status_of("evt-00") == ("failed", 1, "invalid_blocks")


def test_an_unreadable_item_fails_without_blocking_the_queue(s: Setup) -> None:
    s.queue(2)
    s.store.enqueue("broken", TEAM, {"event_id": "broken"}, T0, due=T0 + WINDOW)
    s.now = T0 + WINDOW
    assert s.publisher.publish_due() == 2
    assert s.store.status_of("broken") == ("failed", 1, "invalid_payload")


def test_events_arriving_during_the_window_join_one_digest(s: Setup) -> None:
    """SLK-07: a window, not a per-event delay. Events 30 s apart over 90 s go out together when the first is due."""
    s.queue(4, every=timedelta(seconds=30))
    s.now = T0 + WINDOW
    assert s.publisher.publish_due() == 4
    summary, *replies = s.client.posts()
    assert "Resumen · 4 avisos" in str(summary["blocks"])
    assert len(replies) == 4


def test_a_missing_team_channel_moves_the_digest_to_the_default_channel(s: Setup) -> None:
    s.queue(3)
    s.now = T0 + WINDOW
    s.client.fail("chat.postMessage", "not_in_channel")  # the bot was never invited to the team channel
    assert s.publisher.publish_due() == 3
    channels = [p["channel"] for p in s.client.posts()]
    assert channels == [TEAM, DEFAULT, DEFAULT, DEFAULT, DEFAULT]  # the refused summary, then all in #general
    assert {r.channel_id for r in s.store.deliveries.values()} == {DEFAULT}


def test_an_interrupted_digest_in_the_default_channel_continues_there(s: Setup) -> None:
    s.queue(3)
    s.now = T0 + WINDOW
    original = s.client.api_call
    posts = {"n": 0}

    def refuse_team_then_rate_limit(method: str, **kwargs: object) -> object:
        if method == "chat.postMessage":
            posts["n"] += 1
            if posts["n"] == 1:
                s.client.fail("chat.postMessage", "channel_not_found")
            if posts["n"] == 4:  # summary refused, summary in #general, reply 1, then a rate limit
                s.client.fail("chat.postMessage", "ratelimited", status=429, retry_after=60)
        return original(method, **kwargs)

    s.client.api_call = refuse_team_then_rate_limit  # type: ignore[method-assign]
    assert s.publisher.publish_due() == 1
    s.now += timedelta(minutes=1)
    assert s.publisher.publish_due() == 2
    later = s.client.posts()[4:]
    assert {p["channel"] for p in later} == {DEFAULT}
    assert {p["thread_ts"] for p in later} == {"1700000000.000001"}


def test_a_single_event_falls_back_too(s: Setup) -> None:
    s.queue(1)
    s.now = T0 + WINDOW
    s.client.fail("chat.postMessage", "is_archived")
    assert s.publisher.publish_due() == 1
    assert [p["channel"] for p in s.client.posts()] == [TEAM, DEFAULT]


def test_without_a_default_channel_the_channel_error_fails_the_items() -> None:
    s = Setup()
    s.publisher.fallback_channel = None
    s.queue(2)
    s.now = T0 + WINDOW
    s.client.fail("chat.postMessage", "channel_not_found")
    assert s.publisher.publish_due() == 0
    assert s.store.status_of("evt-00") == ("failed", 1, "channel_not_found")
