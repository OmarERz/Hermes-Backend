"""Cooperative shutdown of the worker (#170): a long cycle stops at its next safe point when the process is asked to.

The worker's signal handler sets one `threading.Event`. The clients that wait on the network receive a `StopSignal`
built on it (the news fetcher, the embeddings client, the vulnerability sources and their rate limiter, the LLM
clients): they check it before each request and sleep on it instead of `time.sleep`, so a SIGTERM or SIGINT during a
download loop, a retry backoff or a rate-limit pause ends the cycle within a second instead of when the cycle ends.
A request already on the wire still runs to its own timeout; the worker bounds that wait (`workers.jobs`).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


class ShutdownRequested(BaseException):
    """The worker is stopping.

    A BaseException, like KeyboardInterrupt: the per-item `except Exception` guards that keep a cycle going (one
    failing source, story or group never stops the others) must not swallow it, while `with session` blocks still
    roll back and `finally` blocks still run on the way out.
    """


@dataclass(frozen=True)
class StopSignal:
    """The worker's stop event, as the clients use it. A default signal is never set (it only waits)."""

    event: threading.Event = field(default_factory=threading.Event)

    def check(self) -> None:
        """Raise ShutdownRequested when the worker was asked to stop."""
        if self.event.is_set():
            raise ShutdownRequested("the worker is stopping")

    def sleep(self, seconds: float) -> None:
        """`time.sleep` that wakes up and raises ShutdownRequested as soon as the worker is asked to stop."""
        if self.event.wait(max(seconds, 0.0)):
            raise ShutdownRequested("the worker is stopping")
