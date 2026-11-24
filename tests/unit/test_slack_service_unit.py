"""The Slack service process (python -m slack_app): fail closed, lanes, entry point. No network, no database."""

from __future__ import annotations

import logging
import threading
from unittest.mock import MagicMock

import pytest
from pydantic import SecretStr

from core.config import Settings
from notifications_slack.settings import SlackSettings
from slack_app import __main__ as entry
from slack_app import service

pytestmark = pytest.mark.unit
FAKE_PASSWORD = "pw"  # noqa: S105 - fake value for tests
SETTINGS = Settings(
    _env_file=None,
    database_url=SecretStr("postgresql://app:pw@db/hermes"),
    firebase_project_id="demo-hermes",
    cursor_signing_key=SecretStr("k" * 40),
)


def test_an_unconfigured_service_connects_to_nothing(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service, "configure_logging", lambda *_: None)
    monkeypatch.setattr(service, "build", MagicMock(side_effect=AssertionError("must not build")))
    slack = SlackSettings(_env_file=None, _secrets_dir=None)  # type: ignore[call-arg]
    with caplog.at_level(logging.ERROR, logger="slack_app"):
        assert service.run(threading.Event(), SETTINGS, slack) == 2
    assert "SLACK_BOT_TOKEN" in caplog.text
    assert "SLACK_DEFAULT_CHANNEL" in caplog.text
    with_url = SlackSettings(  # type: ignore[call-arg]
        _env_file=None, _secrets_dir=None, database_url="postgresql://slack_module@db/hermes"
    )
    caplog.clear()
    with caplog.at_level(logging.ERROR, logger="slack_app"):
        assert service.run(threading.Event(), SETTINGS, with_url) == 2
    assert "SLACK_DB_PASSWORD" in caplog.text  # without it the role cannot log in: never start


def test_a_database_that_refuses_the_role_stops_the_service(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service, "configure_logging", lambda *_: None)
    store = MagicMock()
    store.check.side_effect = ConnectionError("password authentication failed")
    monkeypatch.setattr(service, "SqlSlackStore", lambda _engine: store)
    monkeypatch.setattr(service, "make_engine", lambda _url: MagicMock())
    slack = SlackSettings(  # type: ignore[call-arg]
        _env_file=None,
        _secrets_dir=None,
        bot_token="xoxb-" + "1" * 12,
        app_token="xapp-" + "2" * 12,
        database_url="postgresql://slack_module@db/hermes",
        db_password=FAKE_PASSWORD,
        default_channel="C0DEFAULT1",
    )
    with caplog.at_level(logging.ERROR, logger="slack_app"):
        assert service.run(threading.Event(), SETTINGS, slack) == 2
    assert "cannot start: ConnectionError" in caplog.text
    assert "password authentication" not in caplog.text


def test_build_needs_the_slack_database() -> None:
    slack = SlackSettings(_env_file=None, _secrets_dir=None)  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="SLACK_DATABASE_URL"):
        service.build(SETTINGS, slack, threading.Event())


def test_a_configured_service_connects_socket_mode_runs_its_lanes_and_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "configure_logging", lambda *_: None)
    handler = MagicMock()
    module = MagicMock()
    module.socket_mode.return_value = handler
    ran = threading.Event()
    stop = threading.Event()

    def dispatch() -> int:
        ran.set()
        stop.set()  # one round is enough
        return 0

    monkeypatch.setattr(service, "build", lambda *_: (module, dispatch))
    slack = SlackSettings(  # type: ignore[call-arg]
        _env_file=None,
        _secrets_dir=None,
        bot_token="xoxb-" + "1" * 12,
        app_token="xapp-" + "2" * 12,
        database_url="postgresql://slack_module@db/hermes",
        db_password=FAKE_PASSWORD,
        default_channel="C0DEFAULT1",
    )
    assert service.run(stop, SETTINGS, slack) == 0
    assert ran.is_set()
    handler.connect.assert_called_once()
    handler.close.assert_called_once()


def test_a_failing_round_is_logged_by_type_and_retried(caplog: pytest.LogCaptureFixture) -> None:
    stop = threading.Event()
    rounds: list[int] = []

    def job() -> None:
        rounds.append(1)
        if len(rounds) == 2:
            stop.set()
        raise RuntimeError("secret detail")

    with caplog.at_level(logging.ERROR, logger="slack_app"):
        service.run_every(stop, 0.01, "slack_dispatch", job)
    assert len(rounds) == 2
    assert "slack_dispatch failed: RuntimeError" in caplog.text
    assert "secret detail" not in caplog.text


def test_an_immediate_event_is_claimed_within_seconds() -> None:
    module = MagicMock()
    names = [(interval, name) for interval, name, _ in service.lanes(module, MagicMock())]
    assert names[0] == (service.DISPATCH_SECONDS, "slack_dispatch")
    assert service.DISPATCH_SECONDS <= 5  # F11 acceptance: an immediate event in less than a minute
    for _, name, job in service.lanes(module, MagicMock()):
        if name == "slack_digests":
            job()
    module.digests.publish_due.assert_called_once()


def test_with_the_log_consumer_nothing_is_claimed(monkeypatch: pytest.MonkeyPatch) -> None:
    session = MagicMock()
    session.scalar.return_value = "log"
    factory = MagicMock()
    factory.return_value.__enter__.return_value = session
    built = MagicMock()
    monkeypatch.setattr(service, "NotificationDispatcher", built)
    assert service.SlackDispatchJob(factory, MagicMock())() == 0
    built.assert_not_called()
    session.scalar.return_value = "slack"
    built.return_value.drain.return_value = 3
    assert service.SlackDispatchJob(factory, MagicMock())() == 3


def test_entry_point_runs_the_service_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "run", lambda stop: 7)
    monkeypatch.setattr(entry.signal, "signal", lambda *_: None)
    assert entry.main([]) == 7
