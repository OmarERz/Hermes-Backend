"""Saving the F18.3 inventory fields (D-088) into the cache: host CPU and RAM, installation category, status,
description and licence, and the iTop software licences (idempotent, soft-deleted, never creating products)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
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
from core.inventory.sync import SyncResult, sync_from_itop
from core.itop.client import ItopReader
from doubles.itop import ItopDouble

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]
T0 = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)


@pytest.fixture
def engine(postgres_url: str) -> Iterator[Engine]:
    with provisioned_database(postgres_url, "invfields") as db:
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
    common: dict[str, Any] = {"business_criticity": "high", "internet_exposed": "no", "confidentiality": "classified"}
    double.add("Server", 100, name="web-01", cpu="8 vCPU", ram="32 GB", **common)
    double.add("VirtualMachine", 110, name="vm-01", ram="4096", **common)
    double.add("Software", 200, name="nginx", vendor="F5", version="1.24.0", type="WebServer")
    double.add("Software", 201, name="Office", vendor="MS", version="2021", type="PCSoftware")
    double.add("Software", 202, name="Oracle DB", vendor="Oracle", version="19c", type="DBServer")  # not installed
    double.add(
        "WebServer",
        300,
        name="nginx @ web-01",
        system_id="100",
        software_id="200",
        status="active",
        description="Front de pagos",
        softwarelicence_id="400",
    )
    double.add("PCSoftware", 301, name="office @ vm-01", system_id="110", software_id="201", status="inactive")
    double.add(
        "SoftwareLicence",
        400,
        name="nginx plus",
        software_id="200",
        usage_limit="50 users",
        start_date="2026-01-01",
        end_date="2026-12-31",
        perpetual="no",
        licence_key="SECRET",
    )
    double.add("SoftwareLicence", 401, name="Oracle EE", software_id="202", perpetual="yes")
    return double


def run_sync(engine: Engine, double: ItopDouble, now: datetime = T0) -> SyncResult:
    with Session(engine) as session, session.begin():
        return sync_from_itop(session, ItopReader("http://localhost", str(double.token), http=double.client()), now=now)


def installation(session: Session, itop_id: str) -> m.InstalledSoftware:
    return session.scalars(select(m.InstalledSoftware).where(m.InstalledSoftware.itop_instance_id == itop_id)).one()


def licence(session: Session, itop_id: str) -> m.SoftwareLicence:
    return session.scalars(select(m.SoftwareLicence).where(m.SoftwareLicence.itop_licence_id == itop_id)).one()


def test_sync_stores_hosts_installations_and_licences(engine: Engine) -> None:
    result = run_sync(engine, build_double())
    assert (result.licences.created, result.licences.removed) == (2, 0)
    with Session(engine) as session:
        hosts = {a.itop_ci_id: (a.cpu, a.ram) for a in session.scalars(select(m.Asset))}
        assert hosts == {"100": ("8 vCPU", "32 GB"), "110": (None, "4096")}
        nginx, office = installation(session, "300"), installation(session, "301")
        assert (nginx.itop_class, nginx.status, nginx.description) == ("WebServer", "active", "Front de pagos")
        assert (office.itop_class, office.status, office.description, office.software_licence_id) == (
            "PCSoftware",
            "inactive",
            None,
            None,
        )
        plus = licence(session, "400")
        assert nginx.software_licence_id == plus.id
        assert plus.software_product_id == nginx.software_product_id
        assert (plus.name, plus.usage_limit, plus.start_date, plus.end_date, plus.perpetual) == (
            "nginx plus",
            "50 users",
            date(2026, 1, 1),
            date(2026, 12, 31),
            False,
        )
        assert plus.synced_at == T0


def test_a_licence_never_creates_a_product(engine: Engine) -> None:
    run_sync(engine, build_double())
    with Session(engine) as session:
        assert licence(session, "401").software_product_id is None
        assert set(session.scalars(select(m.SoftwareProduct.itop_name))) == {"nginx", "Office"}
    with engine.connect() as conn:
        unmapped = conn.execute(text("SELECT count(*) FROM inventory_issue WHERE issue = 'software_unmapped'"))
        assert unmapped.scalar_one() == 2


def test_the_licence_links_its_product_once_installed(engine: Engine) -> None:
    double = build_double()
    run_sync(engine, double)
    double.add("DBServer", 302, name="oracle @ web-01", system_id="100", software_id="202", softwarelicence_id="401")
    run_sync(engine, double, T0 + timedelta(hours=1))
    with Session(engine) as session:
        oracle = installation(session, "302")
        enterprise = licence(session, "401")
        assert enterprise.software_product_id == oracle.software_product_id
        assert oracle.software_licence_id == enterprise.id


def test_second_sync_changes_nothing(engine: Engine) -> None:
    double = build_double()
    run_sync(engine, double)
    query = (
        "SELECT itop_licence_id, software_product_id, name, usage_limit, start_date, end_date, perpetual, removed_at "
        "FROM software_licence ORDER BY 1"
    )
    links = "SELECT itop_instance_id, itop_class, status, description, software_licence_id FROM installed_software"
    with engine.connect() as conn:
        before = (conn.execute(text(query)).all(), set(conn.execute(text(links)).all()))
    second = run_sync(engine, double, T0 + timedelta(hours=6))
    with engine.connect() as conn:
        assert (conn.execute(text(query)).all(), set(conn.execute(text(links)).all())) == before
    assert (second.licences.created, second.licences.updated, second.licences.removed) == (0, 2, 0)


def test_a_removed_licence_is_soft_deleted_unlinked_and_can_return(engine: Engine) -> None:
    double = build_double()
    run_sync(engine, double)
    plus = double.data["SoftwareLicence"].pop("400")
    double.data["WebServer"]["300"]["softwarelicence_id"] = ""
    gone = run_sync(engine, double, T0 + timedelta(hours=1))
    assert gone.licences.removed == 1
    with Session(engine) as session:
        assert licence(session, "400").removed_at == T0 + timedelta(hours=1)
        assert installation(session, "300").software_licence_id is None
    double.data["SoftwareLicence"]["400"] = plus
    double.data["WebServer"]["300"]["softwarelicence_id"] = "400"
    run_sync(engine, double, T0 + timedelta(hours=2))
    with Session(engine) as session:
        back = licence(session, "400")
        assert back.removed_at is None
        assert installation(session, "300").software_licence_id == back.id


def test_a_dangling_or_foreign_licence_is_warned(engine: Engine) -> None:
    double = build_double()
    double.data["PCSoftware"]["301"]["softwarelicence_id"] = "999"  # not in the read
    double.add("Software", 203, name="Apache", vendor="ASF", version="2.4.58", type="WebServer")
    double.add("WebServer", 303, name="apache @ web-01", system_id="100", software_id="203", softwarelicence_id="400")
    result = run_sync(engine, double)
    assert "Software instance 301: licence 999 is not in the inventory read, left empty" in result.warnings
    assert "Software instance 303: licence 400 is for another software, kept" in result.warnings
    with Session(engine) as session:
        assert installation(session, "301").software_licence_id is None
        assert installation(session, "303").software_licence_id == licence(session, "400").id


def test_values_cleared_in_itop_are_cleared_in_the_cache(engine: Engine) -> None:
    double = build_double()
    run_sync(engine, double)
    double.data["Server"]["100"].update(cpu="", ram="")
    double.data["WebServer"]["300"].update(status="", description="")
    run_sync(engine, double, T0 + timedelta(hours=1))
    with Session(engine) as session:
        web = session.scalars(select(m.Asset).where(m.Asset.itop_ci_id == "100")).one()
        nginx = installation(session, "300")
        assert (web.cpu, web.ram, nginx.status, nginx.description) == (None, None, None, None)
        assert nginx.itop_class == "WebServer"


def test_an_installation_that_loses_its_version_still_follows_itop(engine: Engine) -> None:
    """ESC-12 keeps the row and its last version, but its status, description and licence are iTop's current ones."""
    double = build_double()
    run_sync(engine, double)
    double.data["Software"]["200"]["version"] = ""
    double.data["WebServer"]["300"].update(status="inactive", description="", softwarelicence_id="")
    result = run_sync(engine, double, T0 + timedelta(hours=1))
    assert "Software instance 300: no version, skipped (ESC-12)" in result.warnings
    with Session(engine) as session:
        nginx = installation(session, "300")
        assert (nginx.version, nginx.removed_at, nginx.synced_at) == ("1.24.0", None, T0)
        assert (nginx.itop_class, nginx.status, nginx.description, nginx.software_licence_id) == (
            "WebServer",
            "inactive",
            None,
            None,
        )
