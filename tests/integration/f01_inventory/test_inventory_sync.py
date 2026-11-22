"""iTop -> cache sync against PostgreSQL 18: idempotent, soft-deleting, and feeding `inventory_issue`."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from dbprovision import provisioned_database
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.session import make_engine
from core.inventory.sync import EmptyInventoryError, sync_from_itop, sync_inventory
from core.itop.client import ItopReader, ItopUnavailableError
from core.itop.inventory import InventorySnapshot
from doubles.itop import ItopDouble

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]
T0 = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)


@pytest.fixture
def engine(postgres_url: str) -> Iterator[Engine]:
    with provisioned_database(postgres_url, "inventory") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        engine = make_engine(db.superuser_url)
        try:
            yield engine
        finally:
            engine.dispose()


def build_double() -> ItopDouble:
    double = ItopDouble()
    double.add("Team", 10, name="Platform Ops")
    double.add("Person", 20, name="Rivera", first_name="Ana", email="Ana.Rivera@example.test")
    common: dict[str, Any] = {"business_criticity": "high", "internet_exposed": "no", "confidentiality": "classified"}
    double.add("Server", 100, name="web-01", managementip="10.0.0.11", owner_id="20", custodian_id="10", **common)
    double.add("Server", 101, name="orphan-01", **{**common, "internet_exposed": ""})  # no owner, custodian, exposure
    double.add("Software", 200, name="nginx", vendor="F5", version="1.24.0")
    double.add("Software", 201, name="OpenSSL", vendor="OpenSSL", version="3.0.2-0ubuntu1.12")
    double.add("Software", 202, name="NoVersion", vendor="X", version="")
    double.add("WebServer", 300, name="nginx @ web-01", system_id="100", software_id="200")
    double.add("OtherSoftware", 301, name="openssl @ web-01", system_id="100", software_id="201")
    double.add("OtherSoftware", 302, name="openssl @ orphan-01", system_id="101", software_id="201")
    double.add("OtherSoftware", 303, name="no version @ web-01", system_id="100", software_id="202")
    double.add("OtherSoftware", 304, name="ghost host", system_id="999", software_id="200")
    return double


def reader(double: ItopDouble) -> ItopReader:
    return ItopReader("http://localhost", str(double.token), http=double.client())


def run_sync(engine: Engine, double: ItopDouble, now: datetime = T0) -> Any:
    with Session(engine) as session, session.begin():
        return sync_from_itop(session, reader(double), now=now)


def table_state(engine: Engine) -> dict[str, list[tuple[Any, ...]]]:
    """Every cache row without the sync timestamp, ordered by the iTop key."""
    queries = {
        "team": "SELECT itop_team_id, name, is_default, removed_at FROM team ORDER BY 1",
        "person": "SELECT itop_person_id, name, email, removed_at FROM person ORDER BY 1",
        "asset": "SELECT itop_ci_id, itop_class, name, host(ip), os, criticality, exposed, confidentiality, "
        "personal_data, owner_person_id, custodian_team_id, description, decommissioned_at FROM asset ORDER BY 1",
        "product": "SELECT itop_name FROM software_product ORDER BY 1",
        "installed": "SELECT itop_instance_id, asset_id, software_product_id, version, package_version, removed_at "
        "FROM installed_software ORDER BY 1",
    }
    with engine.connect() as conn:
        return {name: [tuple(r) for r in conn.execute(text(sql))] for name, sql in queries.items()}


def issues(engine: Engine) -> set[tuple[str, str | None]]:
    sql = (
        "SELECT i.issue, COALESCE(a.name, p.itop_name) FROM inventory_issue i "
        "LEFT JOIN asset a ON a.id = i.asset_id LEFT JOIN software_product p ON p.id = i.software_product_id"
    )
    with engine.connect() as conn:
        return {(r[0], r[1]) for r in conn.execute(text(sql))}


def test_first_sync_fills_the_cache(engine: Engine) -> None:
    result = run_sync(engine, build_double())
    assert (result.teams.created, result.persons.created, result.assets.created) == (1, 1, 2)
    assert (result.products.created, result.instances.created) == (2, 3)
    with Session(engine) as session:
        web = session.scalars(select(m.Asset).where(m.Asset.itop_ci_id == "100")).one()
        assert (web.name, str(web.ip), web.criticality, web.exposed, web.confidentiality) == (
            "web-01",
            "10.0.0.11",
            "high",
            False,
            "classified",
        )
        assert web.synced_at == T0
        owner = session.get(m.Person, web.owner_person_id)
        team = session.get(m.Team, web.custodian_team_id)
        assert owner is not None and owner.name == "Ana Rivera" and owner.email == "Ana.Rivera@example.test"
        assert team is not None and (team.name, team.is_default) == ("Platform Ops", False)
        openssl = session.scalars(
            select(m.InstalledSoftware).where(m.InstalledSoftware.itop_instance_id == "301")
        ).one()
        assert (openssl.version, openssl.package_version) == ("3.0.2", "3.0.2-0ubuntu1.12")
    assert any("no host, product or version" in w for w in result.warnings)


def test_second_sync_changes_nothing_but_the_timestamp(engine: Engine) -> None:
    double = build_double()
    run_sync(engine, double)
    before = table_state(engine)
    second = run_sync(engine, double, T0 + timedelta(hours=6))
    assert table_state(engine) == before
    assert (second.assets.created, second.instances.created, second.products.created, second.teams.created) == (0,) * 4
    assert (second.assets.removed, second.instances.removed) == (0, 0)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT DISTINCT synced_at FROM asset")).scalars().all() == [T0 + timedelta(hours=6)]


def test_inventory_issues_list_incomplete_cis_and_unmapped_software(engine: Engine) -> None:
    run_sync(engine, build_double())
    found = issues(engine)
    assert {
        ("exposure_unknown", "orphan-01"),
        ("owner_missing", "orphan-01"),
        ("custodian_missing", "orphan-01"),
        ("software_unmapped", "nginx"),
        ("software_unmapped", "OpenSSL"),
    } <= found
    assert not any(name == "web-01" for _, name in found)
    with Session(engine) as session, session.begin():
        nginx = session.scalars(select(m.SoftwareProduct).where(m.SoftwareProduct.itop_name == "nginx")).one()
        session.add(
            m.CpeMapping(
                software_product_id=nginx.id, nvd_vendor="f5", nvd_product="nginx", origin="manual", mapped_at=T0
            )
        )
    assert ("software_unmapped", "nginx") not in issues(engine)


def test_disappearing_cis_are_soft_deleted_and_can_return(engine: Engine) -> None:
    double = build_double()
    run_sync(engine, double)
    removed_ci = double.data["Server"].pop("101")
    removed_instance = double.data["OtherSoftware"].pop("302")
    second = run_sync(engine, double, T0 + timedelta(hours=6))
    assert (second.assets.removed, second.instances.removed) == (1, 1)
    state = table_state(engine)
    assert [row[12] for row in state["asset"] if row[0] == "101"] == [T0 + timedelta(hours=6)]
    assert [row[5] for row in state["installed"] if row[0] == "302"] == [T0 + timedelta(hours=6)]
    assert not any(name == "orphan-01" for _, name in issues(engine))  # decommissioned CIs are not pending
    double.data["Server"]["101"] = removed_ci
    double.data["OtherSoftware"]["302"] = removed_instance
    run_sync(engine, double, T0 + timedelta(hours=12))
    state = table_state(engine)
    assert all(row[12] is None for row in state["asset"]) and all(row[5] is None for row in state["installed"])


def test_changing_the_version_in_itop_updates_the_instance(engine: Engine) -> None:
    double = build_double()
    run_sync(engine, double)
    double.data["Software"]["200"]["version"] = "1.26.1"
    run_sync(engine, double, T0 + timedelta(hours=6))
    with engine.connect() as conn:
        version = conn.execute(text("SELECT version FROM installed_software WHERE itop_instance_id = '300'")).scalar()
    assert version == "1.26.1"


def test_fields_that_are_ours_survive_a_sync(engine: Engine) -> None:
    double = build_double()
    run_sync(engine, double)
    with engine.begin() as conn:
        conn.execute(text("UPDATE team SET is_default = true"))
        conn.execute(text("UPDATE installed_software SET package_name = 'openssl', package_ecosystem = 'Ubuntu:22.04'"))
    run_sync(engine, double, T0 + timedelta(hours=6))
    with engine.connect() as conn:
        assert conn.execute(text("SELECT is_default FROM team")).scalar() is True
        names = conn.execute(text("SELECT DISTINCT package_name, package_ecosystem FROM installed_software")).all()
    assert [tuple(r) for r in names] == [("openssl", "Ubuntu:22.04")]


def test_unknown_owner_is_left_empty_with_a_warning(engine: Engine) -> None:
    double = build_double()
    double.data["Server"]["100"]["owner_id"] = "777"
    result = run_sync(engine, double)
    assert "CI 100: owner 777 is not in the inventory read, left empty" in result.warnings
    with engine.connect() as conn:
        assert conn.execute(text("SELECT owner_person_id FROM asset WHERE itop_ci_id = '100'")).scalar() is None


def test_an_empty_read_does_not_wipe_the_cache(engine: Engine) -> None:
    run_sync(engine, build_double())
    with Session(engine) as session, pytest.raises(EmptyInventoryError):
        sync_inventory(session, InventorySnapshot(), now=T0)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM asset WHERE decommissioned_at IS NULL")).scalar() == 2
    with Session(engine) as session, session.begin():
        sync_inventory(session, InventorySnapshot(), now=T0, allow_empty=True)  # an explicit decision
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM asset WHERE decommissioned_at IS NULL")).scalar() == 0


def test_itop_outage_writes_nothing(engine: Engine) -> None:
    double = build_double()
    run_sync(engine, double)
    before = table_state(engine)
    double.down = True
    failing = ItopReader("http://localhost", str(double.token), http=double.client(), max_attempts=1)
    with Session(engine) as session, pytest.raises(ItopUnavailableError, match="no response"):
        sync_from_itop(session, failing, now=T0 + timedelta(hours=6))
    assert table_state(engine) == before
