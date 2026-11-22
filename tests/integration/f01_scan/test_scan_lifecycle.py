"""The scan and the finding lifecycle against PostgreSQL (ESC-09 to ESC-16, ARQ-04)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from core.scan.engine import (
    ScanAlreadyRunningError,
    ScanOptions,
    fail_stale_scans,
    next_status,
    run_scan,
)
from core.vulndata.http import JsonSource
from core.vulndata.osv import OsvClient

pytestmark = pytest.mark.integration
DAY0 = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
IDS = {name: uuid.uuid4() for name in ("web", "db", "nginx", "pg", "i_web", "i_db", "i_pg")}


def run(engine: Engine, statement: str, params: dict[str, Any] | None = None) -> None:
    with engine.begin() as conn:
        conn.execute(text(statement), params or {})


def rows(engine: Engine, statement: str) -> list[tuple[Any, ...]]:
    with engine.connect() as conn:
        return [tuple(r) for r in conn.execute(text(statement))]


def factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
def world(engine: Engine) -> Engine:
    """Two CIs: web-01 runs nginx 1.24.0 (mapped); db-01 runs PostgreSQL 15.4 (unmapped)."""
    run(engine, "INSERT INTO team (itop_team_id, name, is_default, synced_at) VALUES ('t', 'Ops', false, now())")
    for key, name in (("web", "web-01"), ("db", "db-01")):
        run(
            engine,
            "INSERT INTO asset (id, itop_ci_id, itop_class, name, criticality, confidentiality, synced_at) "
            "VALUES (:id, :ci, 'Server', :name, 'high', 'classified', now())",
            {"id": IDS[key], "ci": key, "name": name},
        )
    run(
        engine,
        "INSERT INTO software_product (id, itop_name, first_seen_at) "
        "VALUES (:a, 'nginx', now()), (:b, 'PostgreSQL', now())",
        {"a": IDS["nginx"], "b": IDS["pg"]},
    )
    for inst, asset, product, version in (
        ("i_web", "web", "nginx", "1.24.0"),
        ("i_db", "db", "nginx", "1.18.0"),
        ("i_pg", "db", "pg", "15.4"),
    ):
        run(
            engine,
            "INSERT INTO installed_software (id, itop_instance_id, asset_id, software_product_id, version, synced_at) "
            "VALUES (:id, :iid, :asset, :product, :version, now())",
            {"id": IDS[inst], "iid": inst, "asset": IDS[asset], "product": IDS[product], "version": version},
        )
    run(
        engine,
        "INSERT INTO cpe_mapping (software_product_id, nvd_vendor, nvd_product, cna_vendor, cna_product, "
        "origin, mapped_at) "
        "VALUES (:p, 'f5', 'nginx', 'F5', 'NGINX', 'manual', now())",
        {"p": IDS["nginx"]},
    )
    # CVE-2026-1001: recent, NVD range [1.20.0, 1.25.3). CVE-2020-2002: old, same range, not in KEV.
    # CVE-2019-3003: old, CNA-only range, in KEV. CVE-2026-4004: recent, hits only versions <= 1.18.5.
    for cve, published in (
        ("CVE-2026-1001", "2026-11-01"),
        ("CVE-2020-2002", "2020-01-01"),
        ("CVE-2019-3003", "2019-01-01"),
        ("CVE-2026-4004", "2026-11-05"),
    ):
        run(
            engine,
            "INSERT INTO cve (id, published_at, fetched_at) VALUES (:id, :p, now())",
            {"id": cve, "p": published},
        )
    ranges = (
        ("CVE-2026-1001", "nvd_cpe", "f5", "nginx", "1.20.0", True, "1.25.3", False),
        ("CVE-2020-2002", "nvd_cpe", "f5", "nginx", "1.20.0", True, "1.25.3", False),
        ("CVE-2019-3003", "cna_affected", "F5", "NGINX", None, None, "2.0.0", False),
        ("CVE-2026-4004", "nvd_cpe", "f5", "nginx", None, None, "1.18.5", True),
    )
    for cve, source, vendor, product, start, start_inc, end, end_inc in ranges:
        run(
            engine,
            "INSERT INTO cve_affected_range (cve_id, source, vendor, product, version_start, start_inclusive, "
            "version_end, end_inclusive) "
            "VALUES (:c, :s, :v, :p, :a, :ai, :e, :ei)",
            {"c": cve, "s": source, "v": vendor, "p": product, "a": start, "ai": start_inc, "e": end, "ei": end_inc},
        )
    run(
        engine,
        "INSERT INTO kev_entry (cve_id, date_added, required_action) "
        "VALUES ('CVE-2019-3003', '2026-01-01', 'Patch it')",
    )
    return engine


def current(engine: Engine) -> dict[tuple[str, str], str]:
    query = (
        "SELECT i.itop_instance_id, g.cve_id, c.status FROM finding_current c JOIN finding f ON f.id = c.finding_id "
        "JOIN finding_group g ON g.id = f.finding_group_id JOIN installed_software i ON i.id = f.installed_software_id"
    )
    return {(r[0], r[1]): r[2] for r in rows(engine, query)}


def scan(engine: Engine, day: int, options: ScanOptions | None = None) -> Any:
    return run_scan(factory(engine), options, now=DAY0 + timedelta(days=day))


def test_first_scan_finds_recent_cves_and_kev_whatever_their_age(world: Engine) -> None:
    result = scan(world, 0)
    assert current(world) == {
        ("i_web", "CVE-2026-1001"): "new",
        ("i_web", "CVE-2019-3003"): "new",
        ("i_db", "CVE-2026-4004"): "new",
        ("i_db", "CVE-2019-3003"): "new",
    }
    assert (result.new, result.unmapped_products, result.compare_errors) == (4, 1, 0)
    sources = dict(
        rows(
            world,
            "SELECT g.cve_id, f.match_source FROM finding f "
            "JOIN finding_group g ON g.id = f.finding_group_id GROUP BY 1, 2",
        )
    )
    assert sources == {"CVE-2026-1001": "nvd_cpe", "CVE-2019-3003": "kev", "CVE-2026-4004": "nvd_cpe"}
    assert rows(world, "SELECT status, progress, finished_at IS NOT NULL FROM run") == [("succeeded", 100, True)]
    assert rows(world, "SELECT count(*) FROM finding_group") == [(3,)]  # one group per CVE and product (ESC-15)


def test_same_scan_twice_is_persistent_and_changes_no_findings(world: Engine) -> None:
    scan(world, 0)
    second = scan(world, 1)
    assert (second.new, second.persistent) == (0, 4)
    assert set(current(world).values()) == {"persistent"}
    assert rows(world, "SELECT count(*) FROM finding") == [(4,)]


def test_changing_the_version_fixes_and_going_back_reopens(world: Engine) -> None:
    scan(world, 0)
    run(world, "UPDATE installed_software SET version = '1.25.3' WHERE itop_instance_id = 'i_web'")
    fixed = scan(world, 1)
    assert fixed.fixed == 1
    assert current(world)[("i_web", "CVE-2026-1001")] == "fixed"
    assert current(world)[("i_web", "CVE-2019-3003")] == "persistent"  # CNA range < 2.0.0 still covers 1.25.3
    assert scan(world, 2).fixed == 0  # a fixed finding does not change again
    run(world, "UPDATE installed_software SET version = '1.24.0' WHERE itop_instance_id = 'i_web'")
    assert scan(world, 3).reopened == 1
    assert current(world)[("i_web", "CVE-2026-1001")] == "reopened"
    history = rows(
        world,
        "SELECT c.status FROM finding_status_change c JOIN finding f ON f.id = c.finding_id "
        "JOIN finding_group g ON g.id = f.finding_group_id "
        "JOIN installed_software i ON i.id = f.installed_software_id "
        "WHERE i.itop_instance_id = 'i_web' AND g.cve_id = 'CVE-2026-1001' ORDER BY c.changed_at, c.id",
    )
    assert [h[0] for h in history] == ["new", "fixed", "reopened"]


def test_a_ci_left_out_of_the_scan_is_no_data_never_fixed(world: Engine) -> None:
    scan(world, 0)
    only_db = scan(world, 1, ScanOptions(asset_ids={IDS["db"]}))
    assert only_db.no_data == 2 and only_db.fixed == 0
    state = current(world)
    assert state[("i_web", "CVE-2026-1001")] == "no_data" and state[("i_db", "CVE-2026-4004")] == "persistent"
    assert scan(world, 2, ScanOptions(asset_ids={IDS["db"]})).no_data == 0  # already no_data: no new row
    back = scan(world, 3)
    assert back.persistent == 4 and back.reopened == 0
    assert current(world)[("i_web", "CVE-2026-1001")] == "persistent"


def test_a_finding_survives_its_cve_leaving_the_recency_window(world: Engine) -> None:
    scan(world, 0)
    later = scan(world, 200)  # CVE-2026-1001 is now 200 days old
    assert later.fixed == 0 and current(world)[("i_web", "CVE-2026-1001")] == "persistent"
    run(world, "UPDATE installed_software SET version = '1.30.0' WHERE itop_instance_id = 'i_web'")
    assert scan(world, 201).fixed == 1


def test_a_version_that_cannot_be_compared_is_an_error_not_a_fix(world: Engine) -> None:
    scan(world, 0)
    run(world, "UPDATE installed_software SET version = 'weird-build' WHERE itop_instance_id = 'i_web'")
    result = scan(world, 1)
    assert result.compare_errors > 0 and result.fixed == 0
    assert current(world)[("i_web", "CVE-2026-1001")] == "new"  # unchanged: not evidence either way


def test_unmapping_a_product_does_not_fix_its_findings(world: Engine) -> None:
    scan(world, 0)
    run(world, "DELETE FROM cpe_mapping")
    result = scan(world, 1)
    assert result.fixed == 0 and result.no_data == 4 and result.unmapped_products == 2


def test_removed_software_and_decommissioned_cis(world: Engine) -> None:
    scan(world, 0)
    run(world, "UPDATE installed_software SET removed_at = now() WHERE itop_instance_id = 'i_web'")
    run(world, "UPDATE asset SET decommissioned_at = now() WHERE itop_ci_id = 'db'")
    result = scan(world, 1)
    assert result.fixed == 2  # both findings of the removed instance
    state = current(world)
    assert state[("i_web", "CVE-2026-1001")] == "fixed" and state[("i_db", "CVE-2026-4004")] == "new"  # untouched


def osv_double(fixed: bool) -> OsvClient:
    advisory = {
        "id": "UBUNTU-CVE-2026-1001",
        "aliases": ["CVE-2026-1001"],
        "affected": [{"ranges": [{"events": [{"fixed": "1.24.0-1ubuntu1"}]}]}],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        vulns = [advisory] if ("version" not in body or not fixed) else []
        return httpx.Response(200, json={"vulns": vulns})

    return OsvClient(JsonSource(http=httpx.Client(transport=httpx.MockTransport(handler))))


def test_a_backported_patch_makes_an_exclusion_and_no_finding(world: Engine) -> None:
    run(
        world,
        "UPDATE installed_software SET package_name = 'nginx', package_ecosystem = 'Ubuntu:22.04', "
        "package_version = '1.24.0-1ubuntu1' WHERE itop_instance_id = 'i_web'",
    )
    first = scan(world, 0, ScanOptions(osv=osv_double(fixed=True)))
    assert first.excluded == 1
    assert ("i_web", "CVE-2026-1001") not in current(world)
    assert rows(world, "SELECT reason, osv_id, cve_id FROM finding_exclusion") == [
        ("backported_patch", "UBUNTU-CVE-2026-1001", "CVE-2026-1001")
    ]
    assert scan(world, 1, ScanOptions(osv=osv_double(fixed=True))).excluded == 0  # recorded once
    assert rows(world, "SELECT count(*) FROM finding_exclusion") == [(1,)]
    # OSV says it is still affected: the finding appears
    affected = scan(world, 2, ScanOptions(osv=osv_double(fixed=False)))
    assert affected.new == 1 and current(world)[("i_web", "CVE-2026-1001")] == "new"


def test_only_one_scan_at_a_time_and_stale_scans_are_closed(world: Engine) -> None:
    run(
        world,
        "INSERT INTO run (kind, status, progress, trigger_reason, started_at) "
        "VALUES ('scan', 'running', 10, 'manual', :t)",
        {"t": DAY0},
    )
    with pytest.raises(ScanAlreadyRunningError):
        scan(world, 0)
    assert rows(world, "SELECT count(*) FROM run") == [(1,)]
    with Session(world) as session, session.begin():
        assert fail_stale_scans(session, now=DAY0 + timedelta(minutes=30)) == 0  # not stale yet
        assert fail_stale_scans(session, now=DAY0 + timedelta(hours=3)) == 1
    assert rows(world, "SELECT status FROM run") == [("failed",)]
    assert scan(world, 0).new == 4


def test_a_failing_scan_is_marked_failed_and_releases_the_lock(world: Engine) -> None:
    run(
        world,
        "UPDATE installed_software SET package_name = 'nginx', package_ecosystem = 'Ubuntu:22.04', "
        "package_version = '1.24.0-1' WHERE itop_instance_id = 'i_web'",
    )
    broken = OsvClient(
        JsonSource(http=httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(500))), max_attempts=1)
    )
    with pytest.raises(Exception, match="500"):
        scan(world, 0, ScanOptions(osv=broken))
    assert rows(world, "SELECT status, finished_at IS NOT NULL FROM run") == [("failed", True)]
    assert rows(world, "SELECT count(*) FROM finding") == [(0,)]  # nothing half-written
    assert scan(world, 1).new == 4


@pytest.mark.parametrize(
    ("current_status", "last_active", "scanned", "present", "expected"),
    [
        ("new", None, True, True, "persistent"),
        ("persistent", None, True, False, "fixed"),
        ("reopened", None, True, False, "fixed"),
        ("fixed", None, True, True, "reopened"),
        ("fixed", None, True, False, None),
        ("fixed", None, False, True, None),
        ("persistent", None, False, False, "no_data"),
        ("no_data", None, False, True, None),
        ("no_data", "persistent", True, True, "persistent"),
        ("no_data", "fixed", True, True, "reopened"),
        ("no_data", "persistent", True, False, "fixed"),
    ],
)
def test_next_status_table(
    current_status: str, last_active: str | None, scanned: bool, present: bool, expected: str | None
) -> None:
    assert next_status(current_status, last_active, scanned=scanned, present=present) == expected
