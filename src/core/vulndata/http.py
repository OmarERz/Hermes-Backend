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

from core.textnum import retry_after_seconds

DEFAULT_RETRYABLE: Final = frozenset({429, 500, 502, 503, 504})
HTTP_OK: Final = 200
# A source may redirect within its own origin (the EPSS daily file points `current` to the dated file with a 302).
# Only same-origin GET redirects are followed, so a redirect can never take a request (or its API key) elsewhere.
REDIRECT_STATUSES: Final = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS: Final = 3
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
        return self._body(self._send(method, url, params, headers, json))

    def get_bytes(self, url: str) -> bytes:
        """A raw body (for example a compressed daily file), with the same retries and size cap."""
        response = self._send("GET", url, None, None, None)
        self._check_size(response)
        return response.content

    def _send(
        self,
        method: str,
        url: str,
        params: Mapping[str, str | int] | None,
        headers: Mapping[str, str] | None,
        json: Any,
    ) -> httpx.Response:
        client = self.http or httpx.Client(timeout=httpx.Timeout(self.timeout))
        try:
            request = client.build_request(
                method, url, params=params, headers=headers, json=json, timeout=httpx.Timeout(self.timeout)
            )
            for _hop in range(MAX_REDIRECTS + 1):
                response = self._with_retries(client, request)
                if response.status_code not in REDIRECT_STATUSES:
                    return response
                request = self._same_origin_redirect(client, request, response)
            raise SourceRefusedError(response.status_code)  # too many redirects
        finally:
            if self.http is None:
                client.close()

    def _same_origin_redirect(
        self, client: httpx.Client, request: httpx.Request, response: httpx.Response
    ) -> httpx.Request:
        location = response.headers.get("Location")
        if request.method != "GET" or not location:
            raise SourceRefusedError(response.status_code)
        target = request.url.join(location)
        same_origin = (target.scheme, target.host, target.port) == (
            request.url.scheme,
            request.url.host,
            request.url.port,
        )
        if not same_origin:
            raise SourceRefusedError(response.status_code)
        return client.build_request("GET", target, headers=request.headers, timeout=httpx.Timeout(self.timeout))

    def get(
        self, url: str, *, params: Mapping[str, str | int] | None = None, headers: Mapping[str, str] | None = None
    ) -> Any:
        return self.request("GET", url, params=params, headers=headers)

    def post(self, url: str, body: Any, *, headers: Mapping[str, str] | None = None) -> Any:
        return self.request("POST", url, headers=headers, json=body)

    def _with_retries(self, client: httpx.Client, request: httpx.Request) -> httpx.Response:
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
                if response.status_code == HTTP_OK or response.status_code in REDIRECT_STATUSES:
                    return response
                if response.status_code not in self.retryable:
                    raise SourceRefusedError(response.status_code)
                last = f"HTTP {response.status_code}"
                delay = _retry_after(response)
            if attempt < self.max_attempts:
                backoff = min(self.backoff_seconds * 2 ** (attempt - 1), MAX_BACKOFF_SECONDS)
                self.sleep(delay if delay is not None else backoff)
        raise SourceUnavailableError(f"{last} after {self.max_attempts} attempts")

    @staticmethod
    def _check_size(response: httpx.Response) -> None:
        if len(response.content) > MAX_BODY_BYTES:
            raise SourceUnavailableError("answer too large")

    @classmethod
    def _body(cls, response: httpx.Response) -> Any:
        cls._check_size(response)
        try:
            return response.json()
        except ValueError:
            raise SourceUnavailableError("the source did not answer JSON") from None


def _retry_after(response: httpx.Response) -> float | None:
    return retry_after_seconds(response.headers.get("Retry-After"), MAX_BACKOFF_SECONDS)
