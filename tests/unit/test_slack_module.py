"""Assembling the Slack module from its settings (fail closed) without touching the network."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from slack_bolt.adapter.socket_mode import SocketModeHandler

from doubles.slack_web import FakeWebClient
from notifications_api import FeedbackInput, FeedbackResult
from notifications_slack.module import build_module
from notifications_slack.settings import SlackSettings
from notifications_slack.store import InMemorySlackStore

pytestmark = pytest.mark.unit
NOW = datetime(2026, 11, 23, 10, 0, tzinfo=UTC)
BOT, APP = "xoxb-" + "1" * 12, "xapp-" + "2" * 12  # fake values for tests


class NoFeedback:
    def record(self, feedback: FeedbackInput) -> FeedbackResult:
        raise AssertionError("not used")


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_: object, **__: object) -> None:
        raise AssertionError("a test tried to reach the Slack API")

    monkeypatch.setattr("slack_sdk.web.base_client.BaseClient._perform_urllib_http_request", refuse)


def settings(**values: object) -> SlackSettings:
    return SlackSettings(_env_file=None, _secrets_dir=None, default_channel="C0DEFAULT1", **values)  # type: ignore[call-arg]


def test_without_a_bot_token_nothing_is_built() -> None:
    with pytest.raises(ValueError, match="SLACK_BOT_TOKEN"):
        build_module(settings(), NoFeedback(), InMemorySlackStore())


def test_the_real_client_uses_the_bot_token(monkeypatch: pytest.MonkeyPatch) -> None:
    made: list[dict[str, object]] = []

    def fake_client(**kwargs: object) -> FakeWebClient:
        made.append(kwargs)
        return FakeWebClient()

    monkeypatch.setattr("notifications_slack.module.WebClient", fake_client)
    build_module(settings(bot_token=BOT), NoFeedback(), InMemorySlackStore())
    assert made == [{"token": BOT, "timeout": 10}]


def test_purge_applies_both_retentions() -> None:
    store = InMemorySlackStore()
    calls: list[tuple[datetime, datetime]] = []
    store.purge = lambda deliveries, threads: calls.append((deliveries, threads)) or 0  # type: ignore[method-assign]
    module = build_module(
        settings(retention_days=90, thread_retention_days=365),
        NoFeedback(),
        store,
        client=FakeWebClient(),
        clock=lambda: NOW,
    )
    module.purge()
    assert calls == [(NOW - timedelta(days=90), NOW - timedelta(days=365))]


def test_socket_mode_needs_the_app_token() -> None:
    module = build_module(settings(), NoFeedback(), InMemorySlackStore(), client=FakeWebClient())
    with pytest.raises(ValueError, match="SLACK_APP_TOKEN"):
        module.socket_mode()
    with_token = build_module(settings(app_token=APP), NoFeedback(), InMemorySlackStore(), client=FakeWebClient())
    handler = with_token.socket_mode()  # built, not connected
    assert isinstance(handler, SocketModeHandler)
    assert handler.app_token == APP
