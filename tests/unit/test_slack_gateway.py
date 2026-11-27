"""The Slack Web API gateway: prioritized posts, Retry-After, fail fast on permanent errors (SLK-08), no network."""

from __future__ import annotations

import threading
import time

import pytest

from doubles.slack_web import FakeWebClient
from notifications_slack.gateway import PriorityLock, SlackError, SlackGateway, convert_error
from notifications_slack.render import Message

pytestmark = pytest.mark.unit
MSG = Message("fallback", [{"type": "section", "text": {"type": "mrkdwn", "text": "hi"}}])


class FakeTime:
    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def gateway(client: FakeWebClient, max_wait: float = 30.0) -> tuple[SlackGateway, FakeTime]:
    fake = FakeTime()
    return SlackGateway(client, max_wait=max_wait, sleep=fake.sleep, clock=fake.clock), fake


def test_post_sends_blocks_without_unfurling_and_returns_the_channel_and_ts() -> None:
    client = FakeWebClient()
    gw, _ = gateway(client)
    assert gw.post("C0TEAM0001", MSG, thread_ts="1700000000.000001") == ("C0TEAM0001", "1700000000.000001")
    (args,) = client.posts()
    assert args["blocks"] == MSG.blocks
    assert (args["unfurl_links"], args["unfurl_media"], args["thread_ts"]) == (False, False, "1700000000.000001")


def test_a_rate_limit_waits_for_retry_after_then_posts_once() -> None:
    client = FakeWebClient()
    client.fail("chat.postMessage", "ratelimited", status=429, retry_after=3)
    gw, fake = gateway(client)
    gw.post("C0TEAM0001", MSG)
    assert fake.slept == [3.0]
    assert len(client.posts()) == 2  # the refused call and the successful one


def test_a_retry_after_beyond_the_budget_is_raised_for_the_outbox_to_retry() -> None:
    client = FakeWebClient()
    client.fail("chat.postMessage", "ratelimited", status=429, retry_after=120)
    gw, fake = gateway(client, max_wait=30)
    with pytest.raises(SlackError) as error:
        gw.post("C0TEAM0001", MSG)
    assert (error.value.code, error.value.retryable, error.value.retry_after) == ("ratelimited", True, 120.0)
    assert fake.slept == []


def test_permanent_errors_fail_fast() -> None:
    client = FakeWebClient()
    client.fail("chat.postMessage", "channel_not_found")
    gw, fake = gateway(client)
    with pytest.raises(SlackError) as error:
        gw.post("C0TEAM0001", MSG)
    assert (error.value.code, error.value.retryable) == ("channel_not_found", False)
    assert fake.slept == []
    assert len(client.posts()) == 1


def test_server_errors_are_retried_with_backoff() -> None:
    client = FakeWebClient()
    client.fail("chat.postMessage", "internal_error", status=500, times=2)
    gw, fake = gateway(client)
    gw.post("C0TEAM0001", MSG)
    assert fake.slept == [1.0, 2.0]


def test_network_errors_are_retryable(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeWebClient()

    def broken(*_: object, **__: object) -> None:
        raise ConnectionResetError("reset")

    monkeypatch.setattr(client, "chat_postMessage", broken)
    gw, fake = gateway(client, max_wait=2.5)
    with pytest.raises(SlackError) as error:
        gw.post("C0TEAM0001", MSG)
    assert (error.value.code, error.value.retryable) == ("network_error", True)
    assert fake.slept == [1.0]  # then 2 s more would pass the 2.5 s budget


def test_error_codes_never_carry_response_content() -> None:
    client = FakeWebClient()
    client.fail("chat.postMessage", "secret text <with> spaces", status=400)
    gw, _ = gateway(client)
    with pytest.raises(SlackError) as error:
        gw.post("C0TEAM0001", MSG)
    assert str(error.value) == "unknown_error"
    assert convert_error(ValueError("x")).code == "network_error"


def test_a_429_without_code_or_header_counts_as_a_rate_limit() -> None:
    client = FakeWebClient()
    client.fail("chat.postMessage", "", status=429)
    gw, _ = gateway(client, max_wait=0)
    with pytest.raises(SlackError) as error:
        gw.post("C0TEAM0001", MSG)
    assert (error.value.code, error.value.retry_after) == ("ratelimited", None)


def test_a_malformed_retry_after_is_ignored() -> None:
    client = FakeWebClient()
    client.fail("chat.postMessage", "ratelimited", status=429)
    client._script["chat.postMessage"][0].headers["Retry-After"] = "soon"
    gw, fake = gateway(client)
    gw.post("C0TEAM0001", MSG)
    assert fake.slept == [1.0]


def test_user_email_reads_the_profile() -> None:
    client = FakeWebClient(emails={"U0ANALYST1": " ana@example.test "})
    gw, _ = gateway(client)
    assert gw.user_email("U0ANALYST1") == "ana@example.test"
    assert gw.user_email("U0NOEMAIL1") is None
    assert gw.user_email("not-a-user") is None  # never sent to Slack
    assert [c["user"] for c in client.calls_of("users.info")] == ["U0ANALYST1", "U0NOEMAIL1"]


def test_bots_and_deleted_users_have_no_email(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeWebClient(emails={"U0BOT00001": "bot@example.test"})
    original = client._answer

    def answer(method: str, args: dict[str, object]) -> dict[str, object]:
        data = original(method, args)
        if method == "users.info":
            data["user"]["is_bot"] = True  # type: ignore[index]
        return data

    monkeypatch.setattr(client, "_answer", answer)
    gw, _ = gateway(client)
    assert gw.user_email("U0BOT00001") is None


def test_interactive_calls_convert_errors() -> None:
    client = FakeWebClient()
    client.fail("views.open", "expired_trigger_id")
    client.fail("chat.postEphemeral", "user_not_in_channel")
    gw, _ = gateway(client)
    with pytest.raises(SlackError, match="expired_trigger_id"):
        gw.open_view("123.456", {"type": "modal"})
    with pytest.raises(SlackError, match="user_not_in_channel"):
        gw.ephemeral("C0TEAM0001", "U0ANALYST1", "hola")


def test_waiting_posts_are_served_lowest_rank_first() -> None:
    lock = PriorityLock()
    order: list[int] = []
    started = threading.Event()

    def wait(rank: int) -> None:
        with lock.turn(rank):
            order.append(rank)

    with lock.turn(1):
        started.set()
        threads = [threading.Thread(target=wait, args=(rank,)) for rank in (2, 2, 0)]
        for thread in threads:
            thread.start()
            time.sleep(0.05)  # all three are queued before the turn is released
    for thread in threads:
        thread.join(timeout=5)
    assert order == [0, 2, 2]
