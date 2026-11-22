"""Read-only client for iTop's REST API: `POST <itop>/webservices/rest.php?version=1.3` (ESC-01, ESC-02).

Only `core/get` and `list_operations` exist here on purpose: writing to iTop is the outbox's job (ARQ-01,
prototype C3). The token travels in the `Auth-Token` header, never in the URL or in a log line. ⚠️ The header
login type was verified in iTop's source, not yet against the live 3.2.2 instance (P-011).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import urlsplit

import httpx

from core.config import Settings
from core.db.session import is_local_host

REST_PATH: Final = "/webservices/rest.php"
API_VERSION: Final = "1.3"
LOCAL_HOSTS: Final = frozenset({"host.docker.internal", "itop"})
RETRYABLE_STATUS: Final = frozenset({429, 500, 502, 503, 504})
HTTP_OK: Final = 200
READ_OPERATIONS: Final = frozenset({"core/get", "list_operations"})
MAX_BACKOFF_SECONDS: Final = 30.0


class ItopError(Exception):
    """iTop answered but refused the operation (`code != 0`). Not retried."""

    def __init__(self, code: int) -> None:
        # iTop's own message is never kept: it may echo request data (SEG-21). The code tells what happened.
        super().__init__(f"iTop refused the operation (code {code})")
        self.code = code


class ItopUnavailableError(Exception):
    """No usable answer from iTop: network, timeout, HTTP error or an answer that is not iTop's JSON."""


@dataclass(frozen=True)
class ItopObject:
    """An object returned by `core/get`: its real class (iTop returns subclasses of the queried class)."""

    class_name: str
    key: str
    fields: dict[str, Any] = field(default_factory=dict)

    def text(self, name: str) -> str | None:
        """A field as stripped text; empty, `0` and missing count as no value (an unset external key)."""
        value = self.fields.get(name)
        if value is None:
            return None
        text = str(value).strip()
        return None if text in {"", "0"} else text


def _retry_after(response: httpx.Response) -> float | None:
    raw = response.headers.get("Retry-After", "")
    try:
        return min(max(float(raw), 0.0), MAX_BACKOFF_SECONDS)
    except ValueError:
        return None


@dataclass
class ItopReader:
    """Read-only iTop client. `http` is injectable so tests use `httpx.MockTransport`."""

    base_url: str
    token: str = field(repr=False)
    timeout: float = 15.0
    max_attempts: int = 3
    backoff_seconds: float = 0.5
    allow_insecure_http: bool = False
    http: httpx.Client | None = None
    sleep: Callable[[float], None] = time.sleep

    def __post_init__(self) -> None:
        if not self.token.strip():
            raise ValueError("an iTop token is required")
        parts = urlsplit(self.base_url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("the iTop URL must be an http(s) URL")
        if parts.username or parts.password:
            raise ValueError("the iTop URL must not carry credentials")
        local = is_local_host(parts.hostname) or parts.hostname in LOCAL_HOSTS
        if parts.scheme == "http" and not self.allow_insecure_http and not local:
            raise ValueError("refusing to send the iTop token over plain http to a remote host; use https")
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        self.base_url = self.base_url.rstrip("/")

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}{REST_PATH}?version={API_VERSION}"

    # --- transport -----------------------------------------------------------------------------------------
    def call(self, operation: dict[str, Any]) -> dict[str, Any]:
        """One read-only REST operation. Network failures, timeouts, 429 and 5xx are retried with backoff."""
        if operation.get("operation") not in READ_OPERATIONS:
            raise ValueError("this client only sends read operations; writes belong to the outbox (ARQ-01)")
        data = {"json_data": json.dumps(operation, ensure_ascii=False)}
        client = self.http or httpx.Client(timeout=httpx.Timeout(self.timeout))
        try:
            return self._call_with_retries(client, data)
        finally:
            if self.http is None:
                client.close()

    def _call_with_retries(self, client: httpx.Client, data: dict[str, str]) -> dict[str, Any]:
        last = "no attempt made"
        for attempt in range(1, self.max_attempts + 1):
            delay: float | None = None
            try:
                response = client.post(
                    self.endpoint,
                    data=data,
                    headers={"Auth-Token": self.token},
                    timeout=httpx.Timeout(self.timeout),
                )
            except httpx.TransportError as exc:
                last = f"no response from iTop ({type(exc).__name__})"
            else:
                if response.status_code == HTTP_OK:
                    return self._parse(response)
                last = f"iTop answered HTTP {response.status_code}"
                if response.status_code not in RETRYABLE_STATUS:
                    raise ItopUnavailableError(last)
                delay = _retry_after(response)
            if attempt < self.max_attempts:
                backoff = min(self.backoff_seconds * 2 ** (attempt - 1), MAX_BACKOFF_SECONDS)
                self.sleep(delay if delay is not None else backoff)
        raise ItopUnavailableError(f"{last} after {self.max_attempts} attempts")

    @staticmethod
    def _parse(response: httpx.Response) -> dict[str, Any]:
        try:
            body = response.json()
        except ValueError:
            raise ItopUnavailableError("iTop did not answer JSON (wrong URL or maintenance page?)") from None
        if not isinstance(body, dict) or "code" not in body:
            raise ItopUnavailableError("unexpected answer shape from iTop")
        if body["code"] != 0:
            raise ItopError(int(body["code"]))
        return body

    # --- operations (read only) -------------------------------------------------------------------------
    def get(self, class_name: str, key: str | int, fields: Sequence[str] | None = None) -> list[ItopObject]:
        """`core/get`. `key` is an OQL query or an object id. Returns [] when nothing matches."""
        body = self.call(
            {
                "operation": "core/get",
                "class": class_name,
                "key": key,
                "output_fields": ",".join(fields) if fields else "*",
            }
        )
        if "objects" not in body:  # iTop sends `"objects": null` for no match; a missing key is a broken answer
            raise ItopUnavailableError("incomplete core/get answer")
        raw_objects = body["objects"] or {}
        return [
            ItopObject(
                class_name=str(raw.get("class", class_name)),
                key=str(raw.get("key", "")),
                fields=dict(raw.get("fields") or {}),
            )
            for raw in raw_objects.values()
        ]

    def list_operations(self) -> list[str]:
        """Verbs iTop offers to this user; a cheap connection and credential check."""
        body = self.call({"operation": "list_operations"})
        return [str(op.get("verb")) for op in body.get("operations", [])]


def reader_from_settings(settings: Settings, *, http: httpx.Client | None = None) -> ItopReader:
    """Build the reader from `Settings`; fails closed when iTop is not configured (prototype C5)."""
    if settings.itop_url is None or settings.itop_token is None:
        raise ValueError("ITOP_URL and ITOP_TOKEN must be configured")
    return ItopReader(str(settings.itop_url), settings.itop_token.get_secret_value(), http=http)
