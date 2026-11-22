"""cvelistV5 loader against PostgreSQL, alone and together with NVD."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session
from test_nvd_load import recorded_client

from core.vulndata.cvelist import CveOrgClient, load_cve_files, load_cve_org
from core.vulndata.http import JsonSource
from core.vulndata.nvd import Window, load_nvd

pytestmark = pytest.mark.integration
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "vulndata"
T0 = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)


def org_client() -> CveOrgClient:
    def handler(request: httpx.Request) -> httpx.Response:
        name = {"CVE-2026-0001": "cve5_0001.json", "CVE-2026-0004": "cve5_rejected.json"}.get(
            request.url.path.rsplit("/", 1)[-1].removesuffix(".json")
        )
        return httpx.Response(200, json=json.loads((FIXTURES / name).read_text())) if name else httpx.Response(404)

    return CveOrgClient(JsonSource(http=httpx.Client(transport=httpx.MockTransport(handler))))


def rows(engine: Engine, query: str) -> list[tuple[Any, ...]]:
    with engine.connect() as conn:
        return [tuple(r) for r in conn.execute(text(query))]


def test_cna_only_record_is_stored_with_cna_ranges(engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        result = load_cve_org(session, org_client(), ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0004"], now=T0)
    assert (result.stored, result.missing, result.skipped) == (1, 1, 1)
    assert rows(engine, "SELECT cvss_source, cvss_score FROM cve WHERE id = 'CVE-2026-0001'")[0][0] == "cna"
    ranges = rows(engine, "SELECT DISTINCT source FROM cve_affected_range WHERE cve_id = 'CVE-2026-0001'")
    assert ranges == [("cna_affected",)]
    assert rows(engine, "SELECT text, source FROM cve_workaround") == [("Disable the affected module.", "cna")]
    assert rows(engine, "SELECT tag FROM cve_reference_tag ORDER BY tag") == [
        ("Exploit",),
        ("Patch",),
        ("Vendor Advisory",),
    ]


def test_reload_is_idempotent(engine: Engine) -> None:
    for _ in range(2):
        with Session(engine) as session, session.begin():
            load_cve_org(session, org_client(), ["CVE-2026-0001"], now=T0)
    assert rows(engine, "SELECT count(*) FROM cve_affected_range") == [(4,)]
    assert rows(engine, "SELECT count(*) FROM cve_workaround") == [(1,)]
    assert rows(engine, "SELECT count(*) FROM cve_reference") == [(2,)]


def test_nvd_and_cna_coexist_and_nvd_wins_single_values(engine: Engine) -> None:
    window = Window(start=datetime(2026, 9, 1, tzinfo=UTC), end=datetime(2026, 10, 30, tzinfo=UTC))
    for order in ("cna-first", "nvd-first"):
        with Session(engine) as session, session.begin():
            if order == "cna-first":
                load_cve_org(session, org_client(), ["CVE-2026-0001"], now=T0)
                load_nvd(session, recorded_client(), window, now=T0)
            else:
                load_nvd(session, recorded_client(), window, now=T0)
                load_cve_org(session, org_client(), ["CVE-2026-0001"], now=T0)
        assert rows(engine, "SELECT cvss_source, cvss_score::text FROM cve WHERE id = 'CVE-2026-0001'") == [
            ("nvd", "9.8")
        ]
        assert rows(engine, "SELECT description FROM cve WHERE id = 'CVE-2026-0001'") == [
            ("Heap overflow in nginx before 1.25.3.",)
        ]
        assert rows(
            engine,
            "SELECT source, count(*) FROM cve_affected_range WHERE cve_id = 'CVE-2026-0001' GROUP BY 1 ORDER BY 1",
        ) == [
            ("cna_affected", 4),
            ("nvd_cpe", 2),
        ]


def test_load_from_local_clone_files(engine: Engine, tmp_path: Path) -> None:
    good = tmp_path / "CVE-2026-0001.json"
    good.write_text((FIXTURES / "cve5_0001.json").read_text())
    (tmp_path / "broken.json").write_text("{not json")
    (tmp_path / "list.json").write_text("[]")
    with Session(engine) as session, session.begin():
        result = load_cve_files(
            session, [good, tmp_path / "broken.json", tmp_path / "list.json", tmp_path / "gone.json"], now=T0
        )
    assert (result.stored, result.skipped) == (1, 3)
