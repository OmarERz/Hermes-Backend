"""KEV parsing, EPSS fetching in batches and OSV backport detection, all over recorded or scripted answers."""

from __future__ import annotations

import gzip
import json
from datetime import date
from pathlib import Path
from typing import Any

import httpx
import pytest

from core.vulndata.epss import BATCH_SIZE, fetch_daily, fetch_scores, parse_daily_csv
from core.vulndata.http import JsonSource, SourceUnavailableError
from core.vulndata.kev import fetch_catalogue, parse_entry
from core.vulndata.osv import OsvClient

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "vulndata"


def source_answering(answer: Any) -> tuple[JsonSource, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = answer(request) if callable(answer) else answer
        return httpx.Response(200, json=body)

    return JsonSource(http=httpx.Client(transport=httpx.MockTransport(handler))), seen


def test_kev_entries_parse_and_bad_ones_do_not() -> None:
    entries = json.loads((FIXTURES / "kev.json").read_text())["vulnerabilities"]
    parsed = [parse_entry(e) for e in entries]
    assert parsed[0] is not None and parsed[1] is not None
    assert (parsed[0].date_added, parsed[0].due_date, parsed[0].known_ransomware_use) == (
        date(2026, 11, 19),
        date(2026, 12, 10),
        True,
    )
    assert (parsed[1].due_date, parsed[1].known_ransomware_use) == (None, False)
    assert parsed[2] is None and parsed[3] is None


def test_kev_catalogue_must_have_the_list() -> None:
    source, _ = source_answering(json.loads((FIXTURES / "kev.json").read_text()))
    assert len(fetch_catalogue(source)) == 4
    for bad in ({"count": 0}, [], {"vulnerabilities": "x"}):
        source, _ = source_answering(bad)
        with pytest.raises(SourceUnavailableError, match="incomplete"):
            fetch_catalogue(source)


def test_epss_fetches_in_batches_of_100_and_drops_invalid_ids() -> None:
    source, seen = source_answering({"status": "OK", "data": [{"cve": "x"}]})
    ids = [f"CVE-2026-{n:04d}" for n in range(250)] + ["not-an-id"]
    rows = fetch_scores(source, ids)
    assert len(seen) == 3 and len(rows) == 3
    assert len(seen[0].url.params["cve"].split(",")) == BATCH_SIZE
    assert "not-an-id" not in seen[2].url.params["cve"]
    assert fetch_scores(source, []) == []


def test_daily_csv_is_parsed_with_its_date_and_gzip_is_detected() -> None:
    text = (
        "#model_version:v2025.03.14,score_date:2026-11-22T00:00:00Z\ncve,epss,percentile\n"
        "CVE-2026-0001,0.005,0.46\nCVE-2026-0002,0.1,0.9\n"
    )
    expected = [
        {"cve": "CVE-2026-0001", "epss": "0.005", "percentile": "0.46", "date": "2026-11-22"},
        {"cve": "CVE-2026-0002", "epss": "0.1", "percentile": "0.9", "date": "2026-11-22"},
    ]
    assert parse_daily_csv(text.encode()) == expected
    assert parse_daily_csv(gzip.compress(text.encode())) == expected
    source = JsonSource(
        http=httpx.Client(
            transport=httpx.MockTransport(lambda _r: httpx.Response(200, content=gzip.compress(text.encode())))
        )
    )
    assert fetch_daily(source) == expected


@pytest.mark.parametrize(
    "text", ["cve,epss,percentile\nCVE-2026-0001,0.1,0.2\n", "#score_date:2026-11-22\nwrong,header\n", ""]
)
def test_daily_csv_with_a_bad_layout_is_refused(text: str) -> None:
    with pytest.raises(SourceUnavailableError, match="layout"):
        parse_daily_csv(text.encode())


def test_daily_csv_decompression_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("core.vulndata.epss.MAX_CSV_BYTES", 10)
    with pytest.raises(SourceUnavailableError, match="too large"):
        parse_daily_csv(gzip.compress(b"x" * 1000))


def test_epss_incomplete_answer_is_an_error() -> None:
    source, _ = source_answering({"status": "OK"})
    with pytest.raises(SourceUnavailableError, match="incomplete"):
        fetch_scores(source, ["CVE-2026-0001"])


def osv_over(
    index: dict[tuple[str, bool], list[dict[str, Any]]], pages: int = 1
) -> tuple[OsvClient, list[dict[str, Any]]]:
    """An OSV double: key (package, queried-with-version) -> vulns, optionally split across pages."""
    sent: list[dict[str, Any]] = []

    def answer(request: httpx.Request) -> dict[str, Any]:
        body = json.loads(request.content)
        sent.append(body)
        vulns = index.get((body["package"]["name"], "version" in body), [])
        page = int(body.get("page_token", "0"))
        size = max(1, -(-len(vulns) // pages))
        chunk = vulns[page * size : (page + 1) * size]
        out: dict[str, Any] = {"vulns": chunk} if chunk else {}
        if (page + 1) * size < len(vulns):
            out["next_page_token"] = str(page + 1)
        return out

    source, _ = source_answering(answer)
    return OsvClient(source), sent


FIXED = [
    {
        "package": {"name": "openssl"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.2-0ubuntu1.13"}]}],
    }
]
USN = {"id": "UBUNTU-CVE-2026-0001", "aliases": ["CVE-2026-0001", "USN-9999-1"], "affected": FIXED}


def test_backport_fixed_when_the_distribution_covers_the_cve_but_not_this_version() -> None:
    client, sent = osv_over({("openssl", False): [USN], ("openssl", True): []})
    assert client.backport_status("CVE-2026-0001", "openssl", "Ubuntu:22.04", "3.0.2-0ubuntu1.12") == "fixed"
    assert sent[0]["package"] == {"name": "openssl", "ecosystem": "Ubuntu:22.04"} and "version" not in sent[0]
    assert sent[1]["version"] == "3.0.2-0ubuntu1.12"


def test_still_affected_and_unknown() -> None:
    client, _ = osv_over({("openssl", False): [USN], ("openssl", True): [USN]})
    assert client.backport_status("CVE-2026-0001", "openssl", "Ubuntu:22.04", "3.0.2-0ubuntu1.1") == "affected"
    assert client.backport_status("CVE-2026-0002", "openssl", "Ubuntu:22.04", "3.0.2") == "unknown"
    assert client.backport_status("CVE-2026-0001", "other", "Ubuntu:22.04", "1") == "unknown"
    with pytest.raises(ValueError, match="CVE id"):
        client.backport_status("GHSA-xxxx", "openssl", "Ubuntu:22.04", "1")


def test_no_suppression_without_a_fixed_version() -> None:
    last_affected = [{"ranges": [{"events": [{"introduced": "0"}, {"last_affected": "3.0.2"}]}]}]
    advisory = {"id": "OSV-1", "aliases": ["CVE-2026-0001"], "affected": last_affected}
    client, _ = osv_over({("openssl", False): [advisory], ("openssl", True): []})
    assert client.backport_status("CVE-2026-0001", "openssl", "Ubuntu:22.04", "3.0.2") == "unknown"


def test_pagination_follows_the_token() -> None:
    many = [{"id": f"OSV-{n}", "aliases": [f"CVE-2026-{n:04d}"]} for n in range(5)]
    client, sent = osv_over({("pkg", False): many}, pages=3)
    assert [v.id for v in client.query("pkg", "PyPI")] == [f"OSV-{n}" for n in range(5)]
    assert [s.get("page_token") for s in sent] == [None, "1", "2"]


def test_incomplete_or_endless_answers_are_errors() -> None:
    source, _ = source_answering({"vulns": "nope"})
    with pytest.raises(SourceUnavailableError, match="incomplete"):
        OsvClient(source).query("pkg", "PyPI")
    endless, _ = source_answering({"vulns": [], "next_page_token": "again"})
    with pytest.raises(SourceUnavailableError, match="too many"):
        OsvClient(endless).query("pkg", "PyPI")
