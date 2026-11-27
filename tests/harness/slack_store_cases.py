"""The rules every `SlackStore` follows (idempotency, threads, the digest queue's NOT-02 duties), written once and run
against the in-memory store (unit) and the PostgreSQL store (integration)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from notifications_slack.store import MAX_ATTEMPTS, DeliveryRecord, SlackStore, ThreadRef

T0 = datetime(2026, 11, 23, 10, 0, tzinfo=UTC)
KEY = "b" * 64
CHANNEL = "C0TEAM0001"
OTHER = "C0OTHER001"


def idempotency_by_event_and_audience(store: SlackStore) -> None:
    assert not store.is_known("evt-1", "standard")
    store.record_delivery(DeliveryRecord("evt-1", "standard", CHANNEL, "message", "1700000000.000001", T0))
    store.record_delivery(DeliveryRecord("evt-1", "standard", OTHER, "message", "1700000000.000009", T0))  # ignored
    assert store.is_known("evt-1", "standard")
    assert not store.is_known("evt-1", "restricted")  # the restricted copy is separate


def queued_events_are_known_and_never_queued_twice(store: SlackStore) -> None:
    store.enqueue("evt-2", CHANNEL, {"event_id": "evt-2"}, T0, due=T0 + timedelta(seconds=120))
    store.enqueue("evt-2", OTHER, {"event_id": "evt-2"}, T0, due=T0)  # already queued: ignored
    assert store.is_known("evt-2", "standard")
    assert not store.is_known("evt-2", "restricted")
    assert store.due_channels(T0) == []  # the window has not passed
    assert store.due_channels(T0 + timedelta(seconds=120)) == [CHANNEL]
    store.record_delivery(DeliveryRecord("evt-3", "standard", CHANNEL, "message", "1700000000.000002", T0))
    store.enqueue("evt-3", CHANNEL, {"event_id": "evt-3"}, T0, due=T0)  # already delivered: ignored
    assert store.due_items(CHANNEL, T0 + timedelta(seconds=120))[0].event_id == "evt-2"
    assert [i.event_id for i in store.due_items(CHANNEL, T0 + timedelta(seconds=120))] == ["evt-2"]


def threads_move_and_keep_their_creation_date(store: SlackStore) -> None:
    assert store.thread(KEY, "standard") is None
    store.save_thread(KEY, "standard", ThreadRef(CHANNEL, "1700000000.000001"), T0)
    store.save_thread(KEY, "restricted", ThreadRef(OTHER, "1700000000.000002"), T0)
    store.save_thread(KEY, "standard", ThreadRef(OTHER, "1700000000.000003"), T0 + timedelta(hours=1))
    assert store.thread(KEY, "standard") == ThreadRef(OTHER, "1700000000.000003")
    assert store.thread(KEY, "restricted") == ThreadRef(OTHER, "1700000000.000002")
    store.save_thread(KEY, "standard", ThreadRef(OTHER, "1700000000.000004"), T0 - timedelta(days=1))  # clock skew
    assert store.thread(KEY, "standard") == ThreadRef(OTHER, "1700000000.000004")


def completing_an_item_records_it_and_empties_the_queue(store: SlackStore) -> None:
    store.enqueue("evt-4", CHANNEL, {"event_id": "evt-4", "nested": {"a": [1, 2]}}, T0, due=T0)
    store.enqueue("evt-5", CHANNEL, {"event_id": "evt-5"}, T0 + timedelta(seconds=1), due=T0)
    items = store.due_items(CHANNEL, T0)
    assert [i.event_id for i in items] == ["evt-4", "evt-5"]  # oldest first
    assert items[0].payload == {"event_id": "evt-4", "nested": {"a": [1, 2]}}
    store.set_digest_ts(["evt-4", "evt-5"], "1700000000.000100", OTHER)  # the summary landed in OTHER (fallback)
    assert store.due_items(CHANNEL, T0) == []
    assert {(i.digest_ts, i.channel_id) for i in store.due_items(OTHER, T0)} == {("1700000000.000100", OTHER)}
    store.complete_item(DeliveryRecord("evt-4", "standard", OTHER, "digest", "1700000000.000101", T0))
    assert [i.event_id for i in store.due_items(OTHER, T0)] == ["evt-5"]
    assert store.is_known("evt-4", "standard")


def failures_back_off_then_fail(store: SlackStore) -> None:
    store.enqueue("evt-6", CHANNEL, {"event_id": "evt-6"}, T0, due=T0)
    assert store.fail_item("evt-6", "ratelimited", T0, permanent=False) is False
    assert store.due_items(CHANNEL, T0) == []  # waits 1 minute (NOT-02)
    assert store.due_items(CHANNEL, T0 + timedelta(minutes=1))[0].attempts == 1
    now = T0
    for _ in range(MAX_ATTEMPTS - 2):
        assert store.fail_item("evt-6", "internal_error", now, permanent=False) is False
    assert store.fail_item("evt-6", "internal_error", now, permanent=False) is True  # the 10th attempt
    assert store.due_channels(now + timedelta(days=1)) == []
    assert store.is_known("evt-6", "standard")  # a failed item is never queued again
    store.enqueue("evt-7", CHANNEL, {"event_id": "evt-7"}, T0, due=T0)
    assert store.fail_item("evt-7", "invalid_blocks", T0, permanent=True) is True
    assert store.fail_item("missing", "x", T0, permanent=True) is False


def purge_removes_old_records_only(store: SlackStore) -> None:
    store.record_delivery(DeliveryRecord("old", "standard", CHANNEL, "message", "1700000000.000001", T0))
    store.record_delivery(
        DeliveryRecord("new", "standard", CHANNEL, "message", "1700000000.000002", T0 + timedelta(days=100))
    )
    store.save_thread(KEY, "standard", ThreadRef(CHANNEL, "1700000000.000001"), T0)
    store.enqueue("failed", CHANNEL, {"event_id": "failed"}, T0, due=T0)
    store.fail_item("failed", "invalid_blocks", T0, permanent=True)
    store.enqueue("waiting", CHANNEL, {"event_id": "waiting"}, T0, due=T0)
    assert store.purge(T0 + timedelta(days=1), T0 + timedelta(days=1)) == 3
    assert not store.is_known("old", "standard")
    assert store.is_known("new", "standard")
    assert store.thread(KEY, "standard") is None
    assert not store.is_known("failed", "standard")
    assert store.is_known("waiting", "standard")  # a queued item is never purged


def a_due_channel_takes_its_whole_window_but_not_items_backing_off(store: SlackStore) -> None:
    """SLK-07: the oldest item makes the channel due; everything queued after it joins the same digest."""
    store.enqueue("first", CHANNEL, {"event_id": "first"}, T0, due=T0 + timedelta(seconds=120))
    store.enqueue("later", CHANNEL, {"event_id": "later"}, T0 + timedelta(seconds=60), due=T0 + timedelta(seconds=180))
    store.enqueue("retry", CHANNEL, {"event_id": "retry"}, T0, due=T0)
    store.fail_item("retry", "ratelimited", T0, permanent=False)  # waits until T0 + 1 min
    store.enqueue("elsewhere", OTHER, {"event_id": "elsewhere"}, T0, due=T0 + timedelta(seconds=150))
    now = T0 + timedelta(seconds=120)
    assert store.due_channels(now) == [CHANNEL]
    assert [i.event_id for i in store.due_items(CHANNEL, now)] == ["first", "retry", "later"]
    assert [i.event_id for i in store.due_items(CHANNEL, T0 + timedelta(seconds=30))] == ["first", "later"]


CASES: list[Callable[[SlackStore], None]] = [
    a_due_channel_takes_its_whole_window_but_not_items_backing_off,
    idempotency_by_event_and_audience,
    queued_events_are_known_and_never_queued_twice,
    threads_move_and_keep_their_creation_date,
    completing_an_item_records_it_and_empties_the_queue,
    failures_back_off_then_fail,
    purge_removes_old_records_only,
]
