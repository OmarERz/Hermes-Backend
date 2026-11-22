"""NVD 2.0: parsing recorded answers, pagination, date windows and the rate limit with or without a key."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from core.vulndata.http import JsonSource, SourceUnavailableError
from core.vulndata.nvd import LIMIT_WITH_KEY, LIMIT_WITHOUT_KEY, NvdClient, nvd_client, parse_cve
from core.vulndata.records import NVD_CPE, RangeRecord, ReferenceRecord

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "vulndata"


def page(name: str) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return loaded


def client_over(*answers: dict[str, Any]) -> tuple[NvdClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=answers[min(len(seen), len(answers)) - 1])

    http = httpx.Client(transport=httpx.MockTransport(handler))
    return NvdClient(JsonSource(http=http), api_key=SecretStr("key-123")), seen


def test_parse_analysed_cve() -> None:
    record = parse_cve(page("nvd_page1.json")["vulnerabilities"][0])
    assert record is not None
    assert record.cve_id == "CVE-2026-0001" and record.origin == "nvd"
    assert record.description == "Heap overflow in nginx before 1.25.3."
    assert record.published_at == datetime(2026, 10, 1, 10, 15, tzinfo=UTC)
    # NVD's own score wins over the CNA's, and the newest CVSS version is used
    assert (record.cvss_version, record.cvss_score, record.cvss_source) == ("3.1", Decimal("9.8"), "nvd")
    assert record.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert record.cwes == ["CWE-787"]
    assert record.references[0] == ReferenceRecord(
        "https://nginx.org/en/security_advisories.html", ("Vendor Advisory", "Patch")
    )
    assert record.references[2].tags == ()
    assert record.ranges == [
        RangeRecord(NVD_CPE, "f5", "nginx", "1.20.0", True, "1.25.3", False),
        RangeRecord(NVD_CPE, "f5", "nginx", "1.18.0", True, "1.18.0", True),
    ]


def test_parse_cve_without_analysis_has_no_cvss_or_ranges() -> None:
    record = parse_cve(page("nvd_page1.json")["vulnerabilities"][1])
    assert record is not None
    assert (record.cvss_score, record.cvss_source, record.ranges, record.cwes) == (None, None, [], [])


def test_parse_cna_only_score_and_escaped_cpe() -> None:
    record = parse_cve(page("nvd_page2.json")["vulnerabilities"][0])
    assert record is not None
    assert (record.cvss_version, record.cvss_score, record.cvss_source) == ("4.0", Decimal("9.3"), "cna")
    assert record.ranges == [RangeRecord(NVD_CPE, "vendor:inc", "wid+get", None, None, "2.1", True)]


def test_parse_skips_invalid_ids_and_handles_odd_cpe() -> None:
    assert parse_cve({"cve": {"id": "not-a-cve"}}) is None
    assert parse_cve({}) is None
    cve = {
        "id": "CVE-2026-0009",
        "configurations": [
            {
                "nodes": [
                    {
                        "children": [
                            {
                                "cpeMatch": [
                                    {"vulnerable": True, "criteria": "cpe:2.3:a:acme:tool:*:*:*:*:*:*:*:*"},
                                    {"vulnerable": True, "criteria": "cpe:2.3:a:acme:tool:-:*:*:*:*:*:*:*"},
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:acme:tool:1.0:*:*:*:*:*:*:*",
                                        "versionStartExcluding": "0.9",
                                    },
                                    {"vulnerable": True, "criteria": "garbage"},
                                ]
                            }
                        ]
                    }
                ]
            }
        ],
    }
    record = parse_cve({"cve": cve})
    assert record is not None
    assert record.ranges == [
        RangeRecord(NVD_CPE, "acme", "tool"),
        RangeRecord(NVD_CPE, "acme", "tool", "0.9", False, None, None),
    ]


def test_pagination_follows_start_index_until_total() -> None:
    client, seen = client_over(page("nvd_page1.json"), page("nvd_page2.json"))
    ids = [i["cve"]["id"] for i in client.iter_items({"pubStartDate": "x"})]
    assert ids == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "not-a-cve"]
    assert [r.url.params["startIndex"] for r in seen] == ["0", "2"]
    assert seen[0].url.params["resultsPerPage"] == "2000"


def test_api_key_travels_in_the_header_only() -> None:
    client, seen = client_over(page("nvd_page2.json") | {"totalResults": 1})
    list(client.iter_items({}))
    assert seen[0].headers["apiKey"] == "key-123"
    assert "key-123" not in str(seen[0].url)
    assert "key-123" not in repr(client)
    keyless = nvd_client()
    assert keyless.api_key is None


def test_windows_are_at_most_120_days_and_cover_the_range() -> None:
    empty = {"vulnerabilities": [], "totalResults": 0}
    client, seen = client_over(empty)
    list(
        client.iter_published(
            datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 9, 1, tzinfo=UTC), virtual_match="cpe:2.3:a:f5:nginx"
        )
    )
    starts = [r.url.params["pubStartDate"] for r in seen]
    ends = [r.url.params["pubEndDate"] for r in seen]
    assert len(seen) == 3
    assert starts[0] == "2026-01-01T00:00:00.000+00:00" and ends[-1] == "2026-09-01T00:00:00.000+00:00"
    assert starts[1:] == ends[:-1]
    assert all(r.url.params["virtualMatchString"] == "cpe:2.3:a:f5:nginx" for r in seen)


@pytest.mark.parametrize("body", [{"vulnerabilities": "no", "totalResults": 1}, {"vulnerabilities": []}, ["x"]])
def test_incomplete_answers_are_not_empty_results(body: Any) -> None:
    client, _ = client_over(body)
    with pytest.raises(SourceUnavailableError, match="incomplete"):
        list(client.iter_items({}))


def test_rate_limit_depends_on_the_key() -> None:
    assert LIMIT_WITHOUT_KEY == (5, 30.0) and LIMIT_WITH_KEY == (50, 30.0)
    without = nvd_client()
    with_key = nvd_client(SecretStr("k"))
    assert without.source.limiter is not None and with_key.source.limiter is not None
    assert (without.source.limiter.max_calls, with_key.source.limiter.max_calls) == (5, 50)
