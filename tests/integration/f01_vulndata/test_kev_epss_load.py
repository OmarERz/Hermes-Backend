"""KEV and EPSS loaders against PostgreSQL."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from core.vulndata.epss import load_epss, refresh_epss
from core.vulndata.http import JsonSource
from core.vulndata.kev import load_kev

pytestmark = pytest.mark.integration
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "vulndata"


def rows(engine: Engine, query: str) -> list[tuple[Any, ...]]:
    with engine.connect() as conn:
        return [tuple(r) for r in conn.execute(text(query))]


def kev_entries() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = json.loads((FIXTURES / "kev.json").read_text())["vulnerabilities"]
    return entries


def test_kev_creates_minimal_cve_rows_and_is_idempotent(engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        session.execute(text("INSERT INTO cve (id, description, fetched_at) VALUES ('CVE-2026-0001', 'known', now())"))
        result = load_kev(session, kev_entries())
    assert (result.stored, result.skipped) == (2, 2)
    snapshot = rows(
        engine, "SELECT cve_id, date_added, due_date, required_action, known_ransomware_use FROM kev_entry ORDER BY 1"
    )
    assert snapshot[0][0] == "CVE-2026-0001" and snapshot[0][4] is True and snapshot[1][2] is None
    assert rows(engine, "SELECT description, fetched_at IS NULL FROM cve WHERE id = 'CVE-2026-0001'") == [
        ("known", False)
    ]
    assert rows(engine, "SELECT fetched_at IS NULL FROM cve WHERE id = 'CVE-2026-0777'") == [(True,)]
    with Session(engine) as session, session.begin():
        again = load_kev(session, kev_entries())
    assert again.stored == 2
    assert (
        rows(
            engine,
            "SELECT cve_id, date_added, due_date, required_action, known_ransomware_use FROM kev_entry ORDER BY 1",
        )
        == snapshot
    )


def test_kev_changes_are_applied(engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        load_kev(session, kev_entries())
    changed = kev_entries()
    changed[0]["requiredAction"] = "Updated action."
    with Session(engine) as session, session.begin():
        load_kev(session, changed)
    assert rows(engine, "SELECT required_action FROM kev_entry WHERE cve_id = 'CVE-2026-0001'") == [
        ("Updated action.",)
    ]


def test_epss_stores_only_known_cves_with_valid_numbers(engine: Engine) -> None:
    payload = json.loads((FIXTURES / "epss.json").read_text())
    with Session(engine) as session, session.begin():
        session.execute(text("INSERT INTO cve (id) VALUES ('CVE-2026-0001'), ('CVE-2026-0002'), ('CVE-2026-0003')"))
        result = load_epss(session, payload["data"])
    assert (result.stored, result.skipped) == (2, 2)  # unknown CVE and out-of-range score are dropped
    assert rows(engine, "SELECT cve_id, epss::text, percentile::text FROM epss_score ORDER BY 1") == [
        ("CVE-2026-0001", "0.00540", "0.46305"),
        ("CVE-2026-0002", "0.02134", "0.82456"),
    ]


def test_epss_is_a_daily_series_and_reload_does_not_duplicate(engine: Engine) -> None:
    def source(day: str, value: str) -> JsonSource:
        body = {"status": "OK", "data": [{"cve": "CVE-2026-0001", "epss": value, "percentile": "0.5", "date": day}]}
        return JsonSource(http=httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(200, json=body))))

    with Session(engine) as session, session.begin():
        session.execute(text("INSERT INTO cve (id) VALUES ('CVE-2026-0001')"))
    for day, value in (("2026-11-21", "0.1"), ("2026-11-22", "0.2"), ("2026-11-22", "0.3")):
        with Session(engine) as session, session.begin():
            refresh_epss(session, source(day, value), ["CVE-2026-0001"])
    assert rows(engine, "SELECT score_date::text, epss::text FROM epss_score ORDER BY 1") == [
        ("2026-11-21", "0.10000"),
        ("2026-11-22", "0.30000"),
    ]


def test_daily_file_refresh_stores_only_what_we_hold(engine: Engine) -> None:
    csv = (
        "#model_version:v1,score_date:2026-11-22T00:00:00Z\ncve,epss,percentile\n"
        "CVE-2026-0001,0.25,0.7\nCVE-2026-5555,0.9,0.99\n"
    )
    source = JsonSource(
        http=httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(200, content=csv.encode())))
    )
    with Session(engine) as session, session.begin():
        session.execute(text("INSERT INTO cve (id) VALUES ('CVE-2026-0001')"))
        result = refresh_epss(session, source)
    assert (result.stored, result.skipped) == (1, 1)


def test_refresh_with_nothing_to_fetch_does_nothing(engine: Engine) -> None:
    source = JsonSource(http=httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(500))))
    with Session(engine) as session, session.begin():
        assert refresh_epss(session, source, []).stored == 0
