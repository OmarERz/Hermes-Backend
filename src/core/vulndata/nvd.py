"""NVD CVE API 2.0 client, parser and loader (ESC-09).

`GET https://services.nvd.nist.gov/rest/json/cves/2.0`, key in the `apiKey` header, `resultsPerPage` up to 2000,
date filters at most 120 days wide, `virtualMatchString` for a CPE prefix. Without a key the public limit is 5
requests per rolling 30 seconds; with a key, 50. ⚠️ Those figures, the date format and the 403 on exceeding the
limit come from NVD's published guidance and could not be re-read from the official page in this session (its
pages need JavaScript); confirm them before the first real run.
Version ranges are stored as NVD publishes them and compared locally (F1.4).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import httpx
from pydantic import SecretStr
from sqlalchemy.orm import Session

from core.cpe.fields import split_cpe_fields, unescape_cpe
from core.shutdown import StopSignal
from core.vulndata.http import JsonSource, RateLimiter, SourceUnavailableError
from core.vulndata.records import (
    CVE_ID,
    CWE_ID,
    NVD_CPE,
    CveRecord,
    RangeRecord,
    ReferenceRecord,
    parse_score,
    parse_timestamp,
)
from core.vulndata.store import store_cve

NVD_URL: Final = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE: Final = 2000
WINDOW_DAYS: Final = 119  # the API accepts at most 120 days per date range
RECENCY_DAYS: Final = 90  # TODO(P-003): recency window of the scan (ESC-10), configurable later
LIMIT_WITHOUT_KEY: Final = (5, 30.0)
LIMIT_WITH_KEY: Final = (50, 30.0)
NVD_SOURCE: Final = "nvd@nist.gov"
CVSS_KEYS: Final = (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"))
NO_VERSION: Final = frozenset({"*", "-", ""})


def _english(items: list[dict[str, Any]], key: str = "value") -> str | None:
    for item in items:
        if item.get("lang") == "en" and isinstance(item.get(key), str):
            return str(item[key])
    return None


def _cvss(metrics: dict[str, Any]) -> tuple[str, str, str, Any] | None:
    """(version, vector, source, score): NVD's own score first, then a CNA's; newest CVSS version first."""
    found: list[tuple[int, int, str, dict[str, Any], str]] = []
    for key, version in CVSS_KEYS:
        for entry in metrics.get(key) or []:
            data = entry.get("cvssData") or {}
            if not data.get("vectorString") or parse_score(data.get("baseScore")) is None:
                continue
            is_nvd = entry.get("source") == NVD_SOURCE
            found.append(
                (0 if is_nvd else 1, CVSS_KEYS.index((key, version)), version, data, "nvd" if is_nvd else "cna")
            )
    if not found:
        return None
    _, _, version, data, source = min(found, key=lambda f: (f[0], f[1]))
    return version, str(data["vectorString"]), source, data["baseScore"]


def _ranges(configurations: list[dict[str, Any]]) -> list[RangeRecord]:
    ranges: list[RangeRecord] = []

    def walk(nodes: list[dict[str, Any]]) -> None:
        for node in nodes:
            if node.get("negate") is True:  # "not running X" conditions are not affected ranges
                continue
            for match in node.get("cpeMatch") or []:
                if match.get("vulnerable") is True and (record := _range(match)) is not None:
                    ranges.append(record)
            walk(node.get("children") or [])

    for configuration in configurations:
        walk(configuration.get("nodes") or [])
    return list(dict.fromkeys(ranges))


def _range(match: dict[str, Any]) -> RangeRecord | None:
    parts = split_cpe_fields(str(match.get("criteria", "")))
    cpe_fields = 6
    if len(parts) < cpe_fields or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    vendor, product, version = (unescape_cpe(p) for p in parts[3:6])
    if vendor in NO_VERSION or product in NO_VERSION:
        return None
    start, start_inclusive = (match.get("versionStartIncluding"), True)
    if start is None:
        start, start_inclusive = (match.get("versionStartExcluding"), False)
    end, end_inclusive = (match.get("versionEndIncluding"), True)
    if end is None:
        end, end_inclusive = (match.get("versionEndExcluding"), False)
    if start is None and end is None:
        if version == "-":
            return None
        if version not in NO_VERSION:  # one exact version
            return RangeRecord(NVD_CPE, vendor, product, version, True, version, True)
        return RangeRecord(NVD_CPE, vendor, product)
    return RangeRecord(
        NVD_CPE,
        vendor,
        product,
        None if start is None else str(start),
        None if start is None else start_inclusive,
        None if end is None else str(end),
        None if end is None else end_inclusive,
    )


def parse_cve(item: dict[str, Any]) -> CveRecord | None:
    """One `vulnerabilities[]` entry of the API answer; None when it has no valid CVE id."""
    cve = item.get("cve") or {}
    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not CVE_ID.match(cve_id):
        return None
    record = CveRecord(
        cve_id=cve_id,
        origin="nvd",
        description=_english(cve.get("descriptions") or []),
        published_at=parse_timestamp(cve.get("published")),
        last_modified_at=parse_timestamp(cve.get("lastModified")),
    )
    if (cvss := _cvss(cve.get("metrics") or {})) is not None:
        record.cvss_version, record.cvss_vector, record.cvss_source = cvss[0], cvss[1], cvss[2]
        record.cvss_score = parse_score(cvss[3])
    for weakness in cve.get("weaknesses") or []:
        value = _english(weakness.get("description") or [])
        if value and CWE_ID.match(value):
            record.cwes.append(value)
    for ref in cve.get("references") or []:
        if isinstance(ref.get("url"), str):
            record.references.append(ReferenceRecord(ref["url"], tuple(str(t) for t in ref.get("tags") or [])))
    record.ranges = _ranges(cve.get("configurations") or [])
    return record


def _stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


@dataclass
class NvdClient:
    """Paginated reader of the CVE API. Build it with `nvd_client`, or pass your own `JsonSource` in tests."""

    source: JsonSource
    api_key: SecretStr | None = field(default=None, repr=False)
    url: str = NVD_URL

    def _page(self, params: dict[str, str | int]) -> dict[str, Any]:
        headers = {"apiKey": self.api_key.get_secret_value()} if self.api_key else None
        body = self.source.get(self.url, params=params, headers=headers)
        if not isinstance(body, dict) or not isinstance(body.get("vulnerabilities"), list):
            raise SourceUnavailableError("incomplete NVD answer")
        if not isinstance(body.get("totalResults"), int):
            raise SourceUnavailableError("incomplete NVD answer")
        return body

    def iter_items(self, params: dict[str, str | int]) -> Iterator[dict[str, Any]]:
        """Every `vulnerabilities[]` entry of one query, following the pagination."""
        start = 0
        while True:
            body = self._page({**params, "resultsPerPage": PAGE_SIZE, "startIndex": start})
            items: list[dict[str, Any]] = body["vulnerabilities"]
            yield from items
            start += len(items)
            if not items or start >= body["totalResults"]:
                return

    def iter_published(
        self, start: datetime, end: datetime, *, virtual_match: str | None = None
    ) -> Iterator[dict[str, Any]]:
        """Entries published in [start, end], split into windows the API accepts."""
        cursor = start
        while cursor < end:
            window_end = min(cursor + timedelta(days=WINDOW_DAYS), end)
            params: dict[str, str | int] = {"pubStartDate": _stamp(cursor), "pubEndDate": _stamp(window_end)}
            if virtual_match:
                params["virtualMatchString"] = virtual_match
            yield from self.iter_items(params)
            cursor = window_end


def nvd_client(
    api_key: SecretStr | None = None,
    *,
    http: httpx.Client | None = None,
    limiter: RateLimiter | None = None,
    stop: StopSignal | None = None,
) -> NvdClient:
    """A client with the public rate limit, or the higher one when a key is configured.

    With the worker's `stop` signal the rate-limit pause (up to 30 s without a key) and the backoff sleep on it (#170).
    """
    calls, period = LIMIT_WITH_KEY if api_key else LIMIT_WITHOUT_KEY
    if limiter is None:
        limiter = RateLimiter(calls, period) if stop is None else RateLimiter(calls, period, sleep=stop.sleep)
    # 403 is how NVD answers when the rolling limit is exceeded (⚠️), so it is retried with backoff.
    source = JsonSource(
        http=http,
        limiter=limiter,
        retryable=frozenset({403, 429, 500, 502, 503, 504}),
        backoff_seconds=6.0,
        stop=stop,
    )
    return NvdClient(source=source, api_key=api_key)


@dataclass
class LoadResult:
    stored: int = 0
    skipped: int = 0


@dataclass(frozen=True)
class Window:
    """Which publications to fetch; the default is the recency window ending now."""

    start: datetime | None = None
    end: datetime | None = None
    virtual_match: str | None = None  # a CPE prefix such as cpe:2.3:a:f5:nginx


def load_nvd(
    session: Session, client: NvdClient, window: Window | None = None, *, now: datetime | None = None
) -> LoadResult:
    """Fetch the CVEs published in the window and store them."""
    window = window or Window()
    end = window.end or now or datetime.now(UTC)
    start = window.start or end - timedelta(days=RECENCY_DAYS)
    result = LoadResult()
    for item in client.iter_published(start, end, virtual_match=window.virtual_match):
        record = parse_cve(item)
        if record is None:
            result.skipped += 1
            continue
        store_cve(session, record, now=now)
        result.stored += 1
    return result
