"""Connection status with a cache and a rate limit (SEG-23: admin only, without spending the NVD quota).

`status()` answers from results younger than `max_age` and checks only what is stale or never checked; `test()`
forces a new check, but a service checked less than `min_interval` ago keeps its last result. Checks are serialized,
so concurrent requests never call a service twice. The probes run in parallel and the batch is bounded by one
`deadline`; a probe still running after it is reported offline (its own transport timeout ends it). Results live
in memory: a restart checks again.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from core.connections.probes import MSG_OFFLINE, NAMES, Name, Probe, ProbeResult

log = logging.getLogger("core.connections")

MAX_AGE: Final = timedelta(minutes=5)
MIN_INTERVAL: Final = timedelta(seconds=30)
DEADLINE_SECONDS: Final = 10.0


@dataclass(frozen=True)
class ConnectionState:
    name: Name
    ok: bool
    latency_ms: int | None
    message: str
    missing_variable: str | None
    checked_at: datetime
    last_ok_at: datetime | None


class ConnectionChecker:
    def __init__(
        self,
        probe_of: Callable[[Name], Probe],
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        max_age: timedelta = MAX_AGE,
        min_interval: timedelta = MIN_INTERVAL,
        deadline: float = DEADLINE_SECONDS,
    ) -> None:
        self._probe_of = probe_of
        self._clock = clock
        self._max_age = max_age
        self._min_interval = min_interval
        self._deadline = deadline
        self._lock = threading.Lock()
        self._check_lock = threading.Lock()
        self._states: dict[Name, ConnectionState] = {}

    def cached(self) -> dict[Name, ConnectionState]:
        """What is known now, without checking anything (the setup wizard reads it)."""
        with self._lock:
            return dict(self._states)

    def status(self) -> list[ConnectionState]:
        with self._check_lock:  # one check at a time: concurrent requests reuse what the first one fetched
            now = self._clock()
            known = self.cached()
            stale = [n for n in NAMES if n not in known or now - known[n].checked_at >= self._max_age]
            return self._check(stale, now)

    def test(self, names: Iterable[Name] | None = None) -> list[ConnectionState]:
        wanted = list(dict.fromkeys(names)) if names is not None else list(NAMES)
        with self._check_lock:
            now = self._clock()
            known = self.cached()
            due = [n for n in wanted if n not in known or now - known[n].checked_at >= self._min_interval]
            states = {s.name: s for s in self._check(due, now)}
        return [states[n] for n in NAMES if n in wanted]

    def _check(self, names: list[Name], now: datetime) -> list[ConnectionState]:
        results: dict[Name, ProbeResult] = {}
        if names:
            # Not a `with` block: leaving it would wait for a hung probe; the deadline must bound the answer.
            pool = ThreadPoolExecutor(max_workers=len(names), thread_name_prefix="connection-check")
            try:
                futures = {name: pool.submit(self._probe_of(name)) for name in names}
                end = time.monotonic() + self._deadline  # one deadline for the whole batch
                for name, future in futures.items():
                    try:
                        results[name] = future.result(timeout=max(0.0, end - time.monotonic()))
                    except FutureTimeout:
                        log.warning("connection check of %s exceeded %s s", name, self._deadline)
                        results[name] = ProbeResult(ok=False, latency_ms=None, message=MSG_OFFLINE)
            finally:
                pool.shutdown(wait=False, cancel_futures=True)
        with self._lock:
            for name, result in results.items():
                previous = self._states.get(name)
                last_ok = now if result.ok else (previous.last_ok_at if previous else None)
                self._states[name] = ConnectionState(
                    name=name,
                    ok=result.ok,
                    latency_ms=result.latency_ms,
                    message=result.message,
                    missing_variable=result.missing_variable,
                    checked_at=now,
                    last_ok_at=last_ok,
                )
            return [self._states[n] for n in NAMES if n in self._states]
