"""The only code that calls the Slack Web API (slack_sdk `WebClient`); tests pass a fake client.

* Prioritized send queue (SLK-08): message posts take turns through one `PriorityLock`, lowest rank first
  (`immediate` 0, `normal` 1, digests 2), so an immediate event never waits behind a digest being published.
* Rate limits: a 429 (or `ratelimited`) is retried after Slack's `Retry-After` while holding the turn, so every
  other post waits too; transient errors (5xx, network) are retried with a short backoff. All of it within
  `max_wait` seconds; past that the error is raised and the caller's own retry takes over (the outbox, NOT-02).
* Permanent errors (`channel_not_found`, `not_in_channel`, `invalid_blocks`, `invalid_auth` ...) are raised at once.
* Interactive calls (`users.info`, `views.open`, `chat.postEphemeral`) never queue behind posts: `views.open` must
  run within 3 seconds of the click, and each method has its own rate limit tier.
* Errors keep only Slack's error code: the SDK's message embeds the whole response (SEG-21).
"""

from __future__ import annotations

import heapq
import itertools
import logging
import re
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, Final

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError, SlackClientError

from notifications_slack.render import Message

log = logging.getLogger("notifications_slack.gateway")

RETRYABLE_CODES: Final = frozenset(
    {"ratelimited", "rate_limited", "internal_error", "service_unavailable", "fatal_error", "request_timeout"}
)
# Errors of the destination channel itself: a standard copy may fall back to the default channel.
CHANNEL_ERRORS: Final = frozenset({"channel_not_found", "not_in_channel", "is_archived"})
_CODE: Final = re.compile(r"^[a-z0-9_]{1,64}$")
_USER_ID: Final = re.compile(r"^[UW][A-Z0-9]{2,31}$")
MAX_TRANSIENT_DELAY: Final = 8.0


class SlackError(Exception):
    """A failed Slack call: `code` is Slack's error code (or `network_error`), never response content."""

    def __init__(self, code: str, *, retryable: bool, retry_after: float | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable
        self.retry_after = retry_after


def convert_error(exc: Exception) -> SlackError:
    """`SlackApiError` → its code, status and Retry-After; any other client or network error → retryable."""
    if isinstance(exc, SlackApiError):
        response = exc.response
        raw = response.get("error") if isinstance(response.data, dict) else None
        code = raw if isinstance(raw, str) and _CODE.fullmatch(raw) else "unknown_error"
        status = response.status_code
        retry_after: float | None = None
        header = (response.headers or {}).get("Retry-After") or (response.headers or {}).get("retry-after")
        if header is not None:
            try:
                retry_after = max(float(header), 0.0)
            except (TypeError, ValueError):
                retry_after = None
        if status == 429 and code == "unknown_error":  # noqa: PLR2004
            code = "ratelimited"
        retryable = code in RETRYABLE_CODES or status == 429 or status >= 500  # noqa: PLR2004
        return SlackError(code, retryable=retryable, retry_after=retry_after)
    return SlackError("network_error", retryable=True)


class PriorityLock:
    """A lock whose waiters are served lowest rank first (FIFO within a rank)."""

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._waiting: list[tuple[int, int]] = []
        self._busy = False
        self._seq = itertools.count()

    @contextmanager
    def turn(self, rank: int) -> Iterator[None]:
        with self._cond:
            ticket = (rank, next(self._seq))
            heapq.heappush(self._waiting, ticket)
            while self._busy or self._waiting[0] != ticket:
                self._cond.wait()
            heapq.heappop(self._waiting)
            self._busy = True
        try:
            yield
        finally:
            with self._cond:
                self._busy = False
                self._cond.notify_all()


class SlackGateway:
    def __init__(
        self,
        client: WebClient,
        *,
        max_wait: float = 30.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.client = client
        self.max_wait = max_wait
        self._sleep = sleep
        self._clock = clock
        self._queue = PriorityLock()

    # --- posts (queued by priority) -----------------------------------------------------------------------------
    def post(self, channel: str, msg: Message, *, thread_ts: str | None = None, rank: int = 1) -> tuple[str, str]:
        """Post a message (a thread reply with `thread_ts`); returns (channel id, ts)."""
        kwargs: dict[str, Any] = {
            "channel": channel,
            "text": msg.text,
            "blocks": msg.blocks,
            "unfurl_links": False,
            "unfurl_media": False,
        }
        if thread_ts is not None:
            kwargs["thread_ts"] = thread_ts
        with self._queue.turn(rank):
            response = self._with_retries(lambda: self.client.chat_postMessage(**kwargs))
        return str(response["channel"]), str(response["ts"])

    def _with_retries(self, call: Callable[[], Any]) -> Any:
        deadline = self._clock() + self.max_wait
        attempt = 0
        while True:
            try:
                return call()
            except (SlackClientError, OSError) as exc:
                error = convert_error(exc)
            if not error.retryable:
                raise error
            attempt += 1
            delay = (
                error.retry_after if error.retry_after is not None else min(2.0 ** (attempt - 1), MAX_TRANSIENT_DELAY)
            )
            if self._clock() + delay > deadline:
                raise error
            log.info("slack %s; retrying in %.1fs", error.code, delay)
            self._sleep(delay)

    # --- interactive calls (not queued) ---------------------------------------------------------------------
    def _direct(self, call: Callable[[], Any]) -> Any:
        try:
            return call()
        except (SlackClientError, OSError) as exc:
            raise convert_error(exc) from None

    def user_email(self, user_id: str) -> str | None:
        """The e-mail of a Slack user (users:read.email), or None for bots, deleted users or hidden addresses."""
        if not _USER_ID.fullmatch(user_id):
            return None
        info = self._direct(lambda: self.client.users_info(user=user_id))
        user = info.get("user") if isinstance(info.data, dict) else None
        if not isinstance(user, dict) or user.get("deleted") or user.get("is_bot"):
            return None
        email = (user.get("profile") or {}).get("email")
        return email.strip() if isinstance(email, str) and email.strip() else None

    def open_view(self, trigger_id: str, view: dict[str, Any]) -> None:
        self._direct(lambda: self.client.views_open(trigger_id=trigger_id, view=view))

    def ephemeral(self, channel: str, user: str, text: str) -> None:
        self._direct(lambda: self.client.chat_postEphemeral(channel=channel, user=user, text=text))
