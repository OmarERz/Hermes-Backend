"""Bounded HTTP fetcher: size, time, content type and redirect limits, with the SSRF guard on every hop."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from core.ingestion.ssrf import Resolver, UnsafeUrlError, system_resolver, validate_public_url

FEED_CONTENT_TYPES = frozenset(
    {
        "application/rss+xml",
        "application/atom+xml",
        "application/xml",
        "text/xml",
        "application/json",
        "text/csv",
        "text/plain",
    }
)
ARTICLE_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml"})
USER_AGENT = "hermes-ingestion/0.1"
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class FetchError(Exception):
    """A fetch was refused or failed; the message carries no URL query or credentials."""


@dataclass(frozen=True)
class FetchLimits:
    max_bytes: int = 2_000_000
    timeout_seconds: float = 15.0
    max_redirects: int = 3


@dataclass(frozen=True)
class FetchedDocument:
    url: str
    content_type: str
    body: bytes


class Fetcher:
    """GET over HTTPS with limits. `transport` and `resolver` are injectable so tests need no network."""

    def __init__(
        self,
        *,
        limits: FetchLimits | None = None,
        transport: httpx.BaseTransport | None = None,
        resolver: Resolver = system_resolver,
    ) -> None:
        self._limits = limits or FetchLimits()
        self._resolver = resolver
        self._client = httpx.Client(
            transport=transport,
            timeout=self._limits.timeout_seconds,
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": USER_AGENT},
        )

    def close(self) -> None:
        self._client.close()

    def get(self, url: str, accepted_types: frozenset[str] = FEED_CONTENT_TYPES) -> FetchedDocument:
        current = url
        for _ in range(self._limits.max_redirects + 1):
            try:
                validate_public_url(current, self._resolver)
            except UnsafeUrlError as exc:
                raise FetchError(f"Refused target: {exc}") from exc
            try:
                with self._client.stream("GET", current) as response:
                    if response.status_code in REDIRECT_STATUSES:
                        location = response.headers.get("location")
                        if not location:
                            raise FetchError("Redirect without a location")
                        current = urljoin(current, location)
                        continue
                    return self._read(current, response, accepted_types)
            except httpx.HTTPError as exc:
                raise FetchError(f"Request failed: {type(exc).__name__}") from exc
        raise FetchError("Too many redirects")

    def _read(self, url: str, response: httpx.Response, accepted_types: frozenset[str]) -> FetchedDocument:
        if response.status_code != httpx.codes.OK:
            raise FetchError(f"Unexpected status {response.status_code}")
        content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type not in accepted_types:
            raise FetchError("Unexpected content type")
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > self._limits.max_bytes:
            raise FetchError("Response too large")
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > self._limits.max_bytes:
                raise FetchError("Response too large")
        return FetchedDocument(url=url, content_type=content_type, body=bytes(body))
