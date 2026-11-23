"""One safe test call per external service (D-042, SEG-23).

Each probe answers whether the service is configured and answers with the configured credentials. A probe never
returns or logs a key or the raw body of an error (some APIs echo the request headers): only a status, the
latency and a generic message in Spanish. Calls read nothing of value and have short timeouts, no retries.

Endpoints:
  iTop             `list_operations` on the REST API (read-only), one attempt.
  DeepSeek         `GET {base}/models` (OpenAI-compatible; spends no tokens).
  NVD              `GET /rest/json/cves/2.0?cveId=CVE-2021-44228` with the `apiKey` header.
  abuse.ch         `GET https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1/` with `Auth-Key` (documented).
  ransomware.live  `GET https://api-pro.ransomware.live/taxii2/intel/collections/` with `X-API-KEY` (documented for
                   the PRO TAXII feed; counts toward the PRO quota).
  Firebase         the Auth emulator answers, or the service account obtains an access token (5 s timeout).
The DeepSeek key is never sent over plain HTTP to a remote host.
The answer to a rejected key is not documented by abuse.ch nor ransomware.live: 401 and 403 count as rejected and
any other non-2xx answer as unexpected (docs/seguridad/pendientes-f12.md).
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Final, Literal
from urllib.parse import urlsplit

import httpx
from firebase_admin import credentials
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request

from core.config import Settings
from core.db.session import is_local_host
from core.itop.client import ItopError, ItopReader, ItopUnavailableError

log = logging.getLogger("core.connections")

Name = Literal["itop", "deepseek", "nvd", "abusech", "ransomwarelive", "firebase"]
NAMES: Final[tuple[Name, ...]] = ("itop", "deepseek", "nvd", "abusech", "ransomwarelive", "firebase")
TIMEOUT_SECONDS: Final = 5.0
NVD_URL: Final = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PROBE_CVE: Final = "CVE-2021-44228"
URLHAUS_URL: Final = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1/"
RANSOMWARE_LIVE_URL: Final = "https://api-pro.ransomware.live/taxii2/intel/collections/"
EMULATOR_ENV_VAR: Final = "FIREBASE_AUTH_EMULATOR_HOST"
REJECTED: Final = frozenset({401, 403})
ITOP_UNAUTHORIZED: Final = 1

# Message codes; `core.connections.messages` turns them into text in the configured output language.
MSG_OK: Final = "ok"
MSG_REJECTED: Final = "rejected"
MSG_OFFLINE: Final = "offline"
MSG_UNEXPECTED: Final = "unexpected"
MSG_MISSING: Final = "missing"
MSG_INSECURE: Final = "insecure"


@dataclass(frozen=True)
class ProbeResult:
    ok: bool
    latency_ms: int | None
    message: str
    missing_variable: str | None = None


def missing(variable: str) -> ProbeResult:
    return ProbeResult(ok=False, latency_ms=None, message=MSG_MISSING, missing_variable=variable)


Probe = Callable[[], ProbeResult]
Clock = Callable[[], float]


def _timed_get(
    http: httpx.Client, url: str, *, headers: dict[str, str], params: dict[str, str] | None = None, clock: Clock
) -> tuple[httpx.Response | None, int]:
    """The response (None when the service could not be reached) and the latency in milliseconds."""
    started = clock()
    try:
        response = http.get(url, headers=headers, params=params, timeout=TIMEOUT_SECONDS, follow_redirects=False)
    except httpx.HTTPError as error:
        log.warning("connection check to %s failed: %s", httpx.URL(url).host, type(error).__name__)
        return None, round((clock() - started) * 1000)
    return response, round((clock() - started) * 1000)


def _judge(response: httpx.Response | None, latency: int, accept: Callable[[httpx.Response], bool]) -> ProbeResult:
    if response is None:
        return ProbeResult(ok=False, latency_ms=None, message=MSG_OFFLINE)
    if response.status_code in REJECTED:
        return ProbeResult(ok=False, latency_ms=latency, message=MSG_REJECTED)
    if response.is_success and accept(response):
        return ProbeResult(ok=True, latency_ms=latency, message=MSG_OK)
    return ProbeResult(ok=False, latency_ms=latency, message=MSG_UNEXPECTED)


def _any(_response: httpx.Response) -> bool:
    return True


def _query_ok(response: httpx.Response) -> bool:
    """URLhaus answers `query_status: ok` (or `no_results`) when the key is accepted."""
    try:
        body = response.json()
    except ValueError:
        return False
    status = body.get("query_status") if isinstance(body, dict) else None
    return isinstance(status, str) and status in {"ok", "no_results"}


@dataclass(frozen=True)
class Probes:
    """Builds the probe of each service from the settings. `http` and `clock` are injectable for tests."""

    settings: Settings
    http: httpx.Client
    clock: Clock = time.monotonic
    token_fetcher: Callable[[Path], None] | None = None  # obtains (and discards) a service-account access token
    environ: Callable[[str], str | None] = os.environ.get

    def get(self, name: Name) -> Probe:
        return {
            "itop": self.itop,
            "deepseek": self.deepseek,
            "nvd": self.nvd,
            "abusech": self.abusech,
            "ransomwarelive": self.ransomwarelive,
            "firebase": self.firebase,
        }[name]

    def itop(self) -> ProbeResult:
        s = self.settings
        if s.itop_url is None:
            return missing("ITOP_URL")
        if s.itop_token is None:
            return missing("ITOP_TOKEN")
        started = self.clock()
        try:
            token = s.itop_token.get_secret_value()
            reader = ItopReader(str(s.itop_url), token, timeout=TIMEOUT_SECONDS, max_attempts=1, http=self.http)
            reader.list_operations()
        except ItopError as error:
            # iTop answers 200 with a code: 1 is "unauthorized" (bad token or user without REST rights).
            message = MSG_REJECTED if error.code == ITOP_UNAUTHORIZED else MSG_UNEXPECTED
            return ProbeResult(ok=False, latency_ms=round((self.clock() - started) * 1000), message=message)
        except (ItopUnavailableError, ValueError) as error:
            log.warning("connection check to iTop failed: %s", type(error).__name__)
            return ProbeResult(ok=False, latency_ms=None, message=MSG_OFFLINE)
        return ProbeResult(ok=True, latency_ms=round((self.clock() - started) * 1000), message=MSG_OK)

    def deepseek(self) -> ProbeResult:
        s = self.settings
        if s.deepseek_api_key is None:
            return missing("DEEPSEEK_API_KEY")
        base = str(s.llm_base_url_judge)
        parts = urlsplit(base)
        if parts.scheme != "https" and not is_local_host(parts.hostname):
            return ProbeResult(ok=False, latency_ms=None, message=MSG_INSECURE)  # never send the key in clear text
        url = f"{base.rstrip('/')}/models"
        headers = {"Authorization": f"Bearer {s.deepseek_api_key.get_secret_value()}"}
        return _judge(*_timed_get(self.http, url, headers=headers, clock=self.clock), _any)

    def nvd(self) -> ProbeResult:
        key = self.settings.nvd_api_key
        if key is None:
            return missing("NVD_API_KEY")
        headers = {"apiKey": key.get_secret_value()}
        params = {"cveId": NVD_PROBE_CVE}
        return _judge(*_timed_get(self.http, NVD_URL, headers=headers, params=params, clock=self.clock), _any)

    def abusech(self) -> ProbeResult:
        key = self.settings.abusech_auth_key
        if key is None:
            return missing("ABUSECH_AUTH_KEY")
        headers = {"Auth-Key": key.get_secret_value()}
        return _judge(*_timed_get(self.http, URLHAUS_URL, headers=headers, clock=self.clock), _query_ok)

    def ransomwarelive(self) -> ProbeResult:
        key = self.settings.ransomwarelive_api_key
        if key is None:
            return missing("RANSOMWARELIVE_API_KEY")
        headers = {"X-API-KEY": key.get_secret_value(), "Accept": "application/taxii+json;version=2.1"}
        return _judge(*_timed_get(self.http, RANSOMWARE_LIVE_URL, headers=headers, clock=self.clock), _any)

    def firebase(self) -> ProbeResult:
        emulator = self.environ(EMULATOR_ENV_VAR)
        if emulator:
            return _judge(*_timed_get(self.http, f"http://{emulator}/", headers={}, clock=self.clock), _any)
        path = self.settings.firebase_credentials_file
        if path is None:
            return missing("FIREBASE_CREDENTIALS_FILE")
        fetch = self.token_fetcher or service_account_token
        started = self.clock()
        try:
            fetch(path)
        except (ValueError, OSError, GoogleAuthError) as error:  # never the SDK's message (SEG-23)
            log.warning("connection check to Firebase failed: %s", type(error).__name__)
            return ProbeResult(ok=False, latency_ms=None, message=MSG_REJECTED)
        return ProbeResult(ok=True, latency_ms=round((self.clock() - started) * 1000), message=MSG_OK)


def service_account_token(path: Path) -> None:
    """Obtain an OAuth access token with the service account and discard it (proves the account is valid)."""
    account = credentials.Certificate(str(path)).get_credential()
    account.refresh(partial(Request(), timeout=TIMEOUT_SECONDS))  # the SDK's default transport waits 120 s
