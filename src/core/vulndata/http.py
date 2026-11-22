"""Shared HTTP plumbing for the vulnerability sources: explicit timeouts, retries with backoff, rate limiting.

Clocks and sleeps are injectable so tests never wait. Error messages never include URLs with query strings,
headers or bodies, so an API key cannot leak through an exception (SEG-21).
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

import httpx

DEFAULT_RETRYABLE: Final = frozenset({429, 500, 502, 503, 504})
HTTP_OK: Final = 200
MAX_BACKOFF_SECONDS: Final = 60.0
MAX_BODY_BYTES: Final = 64 * 1024 * 1024


class SourceUnavailableError(Exception):
    """The source gave no usable answer after the retries (network, timeout, 5xx, bad JSON)."""


class SourceRefusedError(Exception):
    """The source answered with a non-retryable error status (bad request, not found, unauthorized)."""

    def __init__(self, status: int) -> None:
        super().__init__(f"source answered HTTP {status}")
        self.status = status


@dataclass
class RateLimiter:
    """At most `max_calls` calls in any `period` seconds (a sliding window)."""

    max_calls: int
    period: float
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    _calls: deque[float] = field(default_factory=deque)

    def acquire(self) -> None:
        while True:
            now = self.clock()
            while self._calls and now - self._calls[0] >= self.period:
                self._calls.popleft()
            if len(self._calls) < self.max_calls:
                self._calls.append(now)
                return
            self.sleep(self.period - (now - self._calls[0]))


@dataclass
class JsonSource:
    """A JSON-over-HTTP source. `http` is injectable (`httpx.MockTransport` in tests)."""

    timeout: float = 30.0
    max_attempts: int = 3
    backoff_seconds: float = 1.0
    retryable: frozenset[int] = DEFAULT_RETRYABLE
    limiter: RateLimiter | None = None
    http: httpx.Client | None = None
    sleep: Callable[[float], None] = time.sleep

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, str | int] | None = None,
        headers: Mapping[str, str] | None = None,
        json: Any = None,
    ) -> Any:
        client = self.http or httpx.Client(timeout=httpx.Timeout(self.timeout))
        try:
            request = client.build_request(
                method, url, params=params, headers=headers, json=json, timeout=httpx.Timeout(self.timeout)
            )
            return self._with_retries(client, request)
        finally:
            if self.http is None:
                client.close()

    def get(
        self, url: str, *, params: Mapping[str, str | int] | None = None, headers: Mapping[str, str] | None = None
    ) -> Any:
        return self.request("GET", url, params=params, headers=headers)

    def post(self, url: str, body: Any, *, headers: Mapping[str, str] | None = None) -> Any:
        return self.request("POST", url, headers=headers, json=body)

    def _with_retries(self, client: httpx.Client, request: httpx.Request) -> Any:
        last = "no attempt made"
        for attempt in range(1, self.max_attempts + 1):
            delay: float | None = None
            if self.limiter:
                self.limiter.acquire()
            try:
                response = client.send(request)
            except httpx.TransportError as exc:
                last = f"no response ({type(exc).__name__})"
            else:
                if response.status_code == HTTP_OK:
                    return self._body(response)
                if response.status_code not in self.retryable:
                    raise SourceRefusedError(response.status_code)
                last = f"HTTP {response.status_code}"
                delay = _retry_after(response)
            if attempt < self.max_attempts:
                backoff = min(self.backoff_seconds * 2 ** (attempt - 1), MAX_BACKOFF_SECONDS)
                self.sleep(delay if delay is not None else backoff)
        raise SourceUnavailableError(f"{last} after {self.max_attempts} attempts")

    @staticmethod
    def _body(response: httpx.Response) -> Any:
        if len(response.content) > MAX_BODY_BYTES:
            raise SourceUnavailableError("answer too large")
        try:
            return response.json()
        except ValueError:
            raise SourceUnavailableError("the source did not answer JSON") from None


def _retry_after(response: httpx.Response) -> float | None:
    try:
        return min(max(float(response.headers.get("Retry-After", "")), 0.0), MAX_BACKOFF_SECONDS)
    except ValueError:
        return None
