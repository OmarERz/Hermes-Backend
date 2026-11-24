"""The Slack module assembled from its settings: consumer, digest publisher and the Bolt app (Socket Mode, SLK-01).

The composition root (`slack_app`) passes in what only the backend has: the `FeedbackService` and the store bound to
the `slack_module` database role. Tests pass a fake `WebClient` and an in-memory store.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import Executor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_sdk import WebClient

from notifications_api import FeedbackService
from notifications_slack.consumer import SlackConsumer
from notifications_slack.digest import DigestPublisher
from notifications_slack.gateway import SlackGateway
from notifications_slack.interactions import FeedbackHandlers
from notifications_slack.routing import Router
from notifications_slack.settings import SlackSettings
from notifications_slack.store import SlackStore

WEB_TIMEOUT_SECONDS = 10


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class SlackModule:
    settings: SlackSettings
    store: SlackStore
    gateway: SlackGateway
    consumer: SlackConsumer
    digests: DigestPublisher
    app: App
    clock: Callable[[], datetime] = utcnow

    def purge(self) -> int:
        """Daily: delivery records past SLACK_RETENTION_DAYS, idle threads past SLACK_THREAD_RETENTION_DAYS."""
        now = self.clock()
        return self.store.purge(
            now - timedelta(days=self.settings.retention_days),
            now - timedelta(days=self.settings.thread_retention_days),
        )

    def socket_mode(self) -> SocketModeHandler:
        """The Socket Mode connection (app-level token, `connections:write`); `connect()` it to start receiving."""
        if self.settings.app_token is None:
            raise ValueError("SLACK_APP_TOKEN is required")
        return SocketModeHandler(self.app, self.settings.app_token.get_secret_value())


def build_module(  # noqa: PLR0913 - keyword-only test seams after the three collaborators
    settings: SlackSettings,
    feedback: FeedbackService,
    store: SlackStore,
    *,
    client: WebClient | None = None,
    clock: Callable[[], datetime] = utcnow,
    listener_executor: Executor | None = None,
) -> SlackModule:
    """Fails closed: without a bot token (or a client) and a default channel nothing is built."""
    if client is None:
        if settings.bot_token is None:
            raise ValueError("SLACK_BOT_TOKEN is required")
        client = WebClient(token=settings.bot_token.get_secret_value(), timeout=WEB_TIMEOUT_SECONDS)
    gateway = SlackGateway(client, max_wait=settings.max_rate_wait_seconds)
    router = Router.from_settings(settings)
    window = timedelta(seconds=settings.digest_window_seconds)
    consumer = SlackConsumer(store, gateway, router, digest_window=window, clock=clock)
    digests = DigestPublisher(store, gateway, clock=clock)
    # The token is checked once, at start, through `client` (auth.test): a bad token stops the service (fail closed),
    # and Bolt keeps the answer, so it never calls auth.test again on the plain per-request client it builds.
    app = App(client=client, name="hermes-slack", token_verification_enabled=True, listener_executor=listener_executor)
    FeedbackHandlers(feedback, gateway).register(app)
    return SlackModule(settings, store, gateway, consumer, digests, app, clock)
