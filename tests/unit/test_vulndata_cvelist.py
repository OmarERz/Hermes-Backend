"""cvelistV5: parsing CVE JSON 5, the raw file layout and the fetch client."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

from core.vulndata.cvelist import CveOrgClient, parse_cve5, raw_path
from core.vulndata.http import JsonSource, SourceRefusedError
from core.vulndata.records import CNA_AFFECTED, RangeRecord, ReferenceRecord, WorkaroundRecord

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "vulndata"


def document(name: str) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return loaded


def test_raw_path_layout() -> None:
    assert raw_path("CVE-2024-1234") == "2024/1xxx/CVE-2024-1234.json"
    assert raw_path("CVE-2026-0001") == "2026/0xxx/CVE-2026-0001.json"
    assert raw_path("CVE-2023-123456") == "2023/123xxx/CVE-2023-123456.json"


def test_parse_published_record() -> None:
    record = parse_cve5(document("cve5_0001.json"))
    assert record is not None
    assert (record.cve_id, record.origin) == ("CVE-2026-0001", "cna")
    assert record.published_at == datetime(2026, 10, 1, 10, 0, tzinfo=UTC)
    assert (record.cvss_version, record.cvss_score, record.cvss_source) == ("3.1", Decimal("7.5"), "cna")
    assert record.cwes == ["CWE-787"]
    assert record.references == [
        ReferenceRecord("https://nginx.org/security", ("Vendor Advisory", "Patch")),
        ReferenceRecord("https://example.test/poc", ("Exploit",)),
    ]
    assert record.workarounds == [WorkaroundRecord("Disable the affected module.", "cna")]


def test_affected_ranges() -> None:
    record = parse_cve5(document("cve5_0001.json"))
    assert record is not None
    assert record.ranges == [
        RangeRecord(CNA_AFFECTED, "F5", "nginx", "1.20.0", True, "1.25.3", False),
        RangeRecord(CNA_AFFECTED, "F5", "nginx", None, None, "1.18.5", True),
        RangeRecord(CNA_AFFECTED, "F5", "nginx", "1.19.0", True, "1.19.0", True),
        RangeRecord(CNA_AFFECTED, "Acme", "Everything"),
    ]


def test_rejected_and_invalid_documents_are_skipped() -> None:
    assert parse_cve5(document("cve5_rejected.json")) is None
    assert parse_cve5({}) is None
    assert parse_cve5({"cveMetadata": {"cveId": "bad", "state": "PUBLISHED"}}) is None


def client_for(handler: Any) -> CveOrgClient:
    return CveOrgClient(JsonSource(http=httpx.Client(transport=httpx.MockTransport(handler)), max_attempts=1))


def test_fetch_requests_the_raw_file_and_maps_404_to_none() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if "CVE-2026-0001" in request.url.path:
            return httpx.Response(
                200, text=json.dumps(document("cve5_0001.json")), headers={"content-type": "text/plain"}
            )
        return httpx.Response(404)

    client = client_for(handler)
    assert client.fetch("CVE-2026-0001") is not None
    assert client.fetch("CVE-2026-0002") is None
    assert seen[0].endswith("/cves/2026/0xxx/CVE-2026-0001.json")


def test_fetch_rejects_a_bad_id_and_surfaces_other_refusals() -> None:
    client = client_for(lambda _r: httpx.Response(403))
    with pytest.raises(ValueError, match="CVE id"):
        client.fetch("../../etc/passwd")
    with pytest.raises(SourceRefusedError):
        client.fetch("CVE-2026-0001")


def test_fetch_ignores_a_non_object_answer() -> None:
    assert client_for(lambda _r: httpx.Response(200, json=[1])).fetch("CVE-2026-0001") is None
