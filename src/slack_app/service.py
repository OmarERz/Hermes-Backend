"""The Slack service (`python -m slack_app`, compose service `slack`): the composition root of `notifications_slack`.

* Bolt in Socket Mode receives the button clicks (SLK-01); they end in the backend's `SqlFeedbackService` (NOT-06).
* A dispatch lane delivers the `notification_event` outbox with `SlackConsumer` while `notifications.consumer` is
  `slack` (the worker leaves those events alone, `core.notifications.dispatcher.delivered_by`); every 2 seconds, so
  an immediate event reaches Slack well within a minute (F11 acceptance).
* A digest lane publishes the channel digests and purges old records once a day.

Two database connections (approved 23 Nov 2026): `app` (DATABASE_URL) for the outbox and FeedbackService, the backend's
own code; `slack_module` (SLACK_DATABASE_URL) for the module's `slack_*` tables. Missing settings stop the service
before anything connects (fail closed).
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final

from sqlalchemy.orm import Session, sessionmaker

from core.config import Settings
from core.db.session import make_engine, make_session_factory, with_password
from core.feedback.service import SqlFeedbackService
from core.logging import configure_logging
from core.notifications.dispatcher import NotificationDispatcher, configured_consumer_name, delivered_by
from notifications_api import NotificationConsumer
from notifications_slack.module import SlackModule, build_module
from notifications_slack.settings import SlackSettings
from notifications_slack.sql_store import SqlSlackStore

log = logging.getLogger("slack_app")

DISPATCH_SECONDS: Final = 2.0  # NOT-03: an immediate event is claimed within seconds, never waits for a digest
DIGEST_SECONDS: Final = 5.0
PURGE_SECONDS: Final = 24 * 3600.0
SERVICE: Final = "slack"


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class SlackDispatchJob:
    """Delivers the outbox with the Slack consumer, only while `notifications.consumer` selects this service."""

    session_factory: sessionmaker[Session]
    consumer: NotificationConsumer
    itop_base_url: str | None = None
    stop: threading.Event | None = None
    clock: Callable[[], datetime] = field(default=utcnow)

    def __call__(self) -> int:
        with self.session_factory() as session:
            name = configured_consumer_name(session)
        if delivered_by(name) != SERVICE:
            return 0  # `log`: the worker delivers
        dispatcher = NotificationDispatcher(
            self.session_factory, self.consumer, itop_base_url=self.itop_base_url, clock=self.clock
        )
        return dispatcher.drain(stop=self.stop)


def run_every(stop: threading.Event, interval: float, name: str, job: Callable[[], object]) -> None:
    """Run `job` until `stop`; a failure is logged (its type only, SEG-21) and retried at the next interval."""
    while not stop.is_set():
        try:
            job()
        except Exception as exc:  # noqa: BLE001 - one failing round must not stop the lane
            log.error("%s failed: %s; retrying in %.0fs", name, type(exc).__name__, interval)  # noqa: TRY400
        stop.wait(interval)


def lanes(module: SlackModule, dispatch: SlackDispatchJob) -> list[tuple[float, str, Callable[[], object]]]:
    return [
        (DISPATCH_SECONDS, "slack_dispatch", dispatch),
        (DIGEST_SECONDS, "slack_digests", module.digests.publish_due),
        (PURGE_SECONDS, "slack_purge", module.purge),
    ]


def build(settings: Settings, slack: SlackSettings, stop: threading.Event) -> tuple[SlackModule, SlackDispatchJob]:
    if slack.database_url is None:
        raise ValueError("SLACK_DATABASE_URL is required")
    password = slack.db_password.get_secret_value() if slack.db_password else None
    store = SqlSlackStore(make_engine(with_password(slack.database_url.get_secret_value(), password)))
    store.check()  # the slack_module role logs in and reaches its tables, before anything else connects
    session_factory = make_session_factory(settings)
    module = build_module(slack, SqlFeedbackService(session_factory), store)
    itop_url = str(settings.itop_url) if settings.itop_url is not None else None
    return module, SlackDispatchJob(session_factory, module.consumer, itop_url, stop)


def run(stop: threading.Event, settings: Settings | None = None, slack: SlackSettings | None = None) -> int:
    settings = settings or Settings()
    slack = slack or SlackSettings()
    configure_logging([*settings.secret_values(), *slack.secret_values()])
    missing = slack.problems()
    if missing:
        log.error("the Slack service is not configured; missing: %s", ", ".join(missing))
        return 2
    try:
        module, dispatch = build(settings, slack, stop)
    except Exception as exc:  # noqa: BLE001 - any start failure stops the service before Slack is reached
        log.error("the Slack service cannot start: %s", type(exc).__name__)  # noqa: TRY400 - no traceback (SEG-21)
        return 2
    handler = module.socket_mode()
    handler.connect()  # type: ignore[no-untyped-call]  # slack_bolt's Socket Mode adapter is untyped
    log.info("slack service started (socket mode)")
    threads = [
        threading.Thread(target=run_every, args=(stop, interval, name, job), name=name, daemon=True)
        for interval, name, job in lanes(module, dispatch)
    ]
    for thread in threads:
        thread.start()
    stop.wait()
    handler.close()  # type: ignore[no-untyped-call]
    for thread in threads:
        thread.join(timeout=10)
    log.info("slack service stopped")
    return 0
