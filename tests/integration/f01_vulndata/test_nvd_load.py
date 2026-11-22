"""NVD loader against PostgreSQL: rows satisfy the model's constraints and a reload changes nothing."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from core.vulndata.http import JsonSource
from core.vulndata.nvd import NvdClient, Window, load_nvd

pytestmark = pytest.mark.integration
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "vulndata"
T0 = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)


def recorded_client() -> NvdClient:
    pages = [json.loads((FIXTURES / n).read_text(encoding="utf-8")) for n in ("nvd_page1.json", "nvd_page2.json")]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=pages[int(request.url.params["startIndex"]) // 2])

    return NvdClient(JsonSource(http=httpx.Client(transport=httpx.MockTransport(handler))), api_key=SecretStr("k"))


def snapshot(engine: Engine) -> dict[str, list[tuple[Any, ...]]]:
    queries = {
        "cve": "SELECT id, description, published_at, cvss_version, cvss_vector, cvss_score, cvss_source "
        "FROM cve ORDER BY 1",
        "cwe": "SELECT cve_id, cwe_id FROM cve_cwe ORDER BY 1, 2",
        "ref": "SELECT r.cve_id, r.url, t.tag FROM cve_reference r "
        "LEFT JOIN cve_reference_tag t ON t.reference_id = r.id ORDER BY 1, 2, 3",
        "range": "SELECT cve_id, source, vendor, product, version_start, start_inclusive, version_end, end_inclusive "
        "FROM cve_affected_range ORDER BY 1, 3, 4, 5",
    }
    with engine.connect() as conn:
        return {k: [tuple(r) for r in conn.execute(text(q))] for k, q in queries.items()}


def load(engine: Engine, now: datetime) -> Any:
    window = Window(start=datetime(2026, 9, 1, tzinfo=UTC), end=datetime(2026, 10, 30, tzinfo=UTC))
    with Session(engine) as session, session.begin():
        return load_nvd(session, recorded_client(), window, now=now)


def test_load_fills_cve_tables(engine: Engine) -> None:
    result = load(engine, T0)
    assert (result.stored, result.skipped) == (3, 1)
    state = snapshot(engine)
    assert [row[0] for row in state["cve"]] == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
    first = state["cve"][0]
    assert (first[3], str(first[5]), first[6]) == ("3.1", "9.8", "nvd")
    assert state["cwe"] == [("CVE-2026-0001", "CWE-787")]
    assert ("CVE-2026-0001", "https://nginx.org/en/security_advisories.html", "Patch") in state["ref"]
    assert len([r for r in state["range"] if r[0] == "CVE-2026-0001"]) == 2
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM cve WHERE fetched_at IS NOT NULL")).scalar() == 3


def test_reload_is_idempotent(engine: Engine) -> None:
    load(engine, T0)
    before = snapshot(engine)
    load(engine, datetime(2026, 11, 23, tzinfo=UTC))
    assert snapshot(engine) == before


def test_changed_ranges_are_replaced_not_accumulated(engine: Engine) -> None:
    load(engine, T0)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO cve_affected_range (cve_id, source, vendor, product) "
                "VALUES ('CVE-2026-0001', 'nvd_cpe', 'stale', 'row')"
            )
        )
    load(engine, datetime(2026, 11, 23, tzinfo=UTC))
    assert not [r for r in snapshot(engine)["range"] if r[2] == "stale"]


def test_reload_keeps_the_same_rows_not_just_the_same_values(engine: Engine) -> None:
    ids = "SELECT id FROM cve_affected_range ORDER BY id"
    load(engine, T0)
    with engine.connect() as conn:
        before = conn.execute(text(ids)).all()
    load(engine, datetime(2026, 11, 23, tzinfo=UTC))
    with engine.connect() as conn:
        assert conn.execute(text(ids)).all() == before and before
