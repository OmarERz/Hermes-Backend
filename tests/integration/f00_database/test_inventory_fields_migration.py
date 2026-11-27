"""Migration 0004 (F18.3, D-088): iTop inventory fields go up over existing data, come down cleanly, and their
constraints reject what the sync must never write."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from dbprovision import MigratedDatabase, provisioned_database
from sqlalchemy import Connection, Engine, inspect, text
from sqlalchemy.exc import IntegrityError

from core.db.session import make_engine

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]

NEW_ASSET_COLUMNS = {"cpu", "ram"}
NEW_INSTALL_COLUMNS = {"itop_class", "status", "description", "software_licence_id"}


@pytest.fixture
def fresh_db(postgres_url: str) -> Iterator[MigratedDatabase]:
    with provisioned_database(postgres_url, "inv") as db:
        yield db


def alembic_cfg(url: str) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.attributes["url"] = url
    return cfg


def columns(engine: Engine, table: str) -> set[str]:
    return {c["name"] for c in inspect(engine).get_columns(table)}


def seed_installation(conn: Connection) -> tuple[uuid.UUID, uuid.UUID]:
    """One asset with one installation, written with the columns that exist before 0004."""
    asset = conn.execute(
        text(
            "INSERT INTO asset (itop_ci_id, itop_class, name, criticality, confidentiality, synced_at) "
            "VALUES ('100', 'Server', 'web-01', 'high', 'public', now()) RETURNING id"
        )
    ).scalar_one()
    product = conn.execute(
        text("INSERT INTO software_product (itop_name, first_seen_at) VALUES ('nginx', now()) RETURNING id")
    ).scalar_one()
    conn.execute(
        text(
            "INSERT INTO installed_software (itop_instance_id, asset_id, software_product_id, version, synced_at) "
            "VALUES ('300', :asset, :product, '1.24.0', now())"
        ),
        {"asset": asset, "product": product},
    )
    return asset, product


def test_upgrade_keeps_existing_rows_and_leaves_the_new_columns_empty(fresh_db: MigratedDatabase) -> None:
    cfg = alembic_cfg(fresh_db.migrator_url)
    command.upgrade(cfg, "0003")
    engine = make_engine(fresh_db.superuser_url)
    try:
        with engine.begin() as conn:
            seed_installation(conn)
        command.upgrade(cfg, "0004")
        with engine.connect() as conn:
            asset = conn.execute(text("SELECT name, cpu, ram FROM asset")).one()
            install = conn.execute(
                text("SELECT version, itop_class, status, description, software_licence_id FROM installed_software")
            ).one()
        assert tuple(asset) == ("web-01", None, None)
        assert tuple(install) == ("1.24.0", None, None, None, None)
    finally:
        engine.dispose()


def test_downgrade_drops_only_what_0004_added(fresh_db: MigratedDatabase) -> None:
    cfg = alembic_cfg(fresh_db.migrator_url)
    command.upgrade(cfg, "0004")
    engine = make_engine(fresh_db.superuser_url)
    try:
        with engine.begin() as conn:
            _, product = seed_installation(conn)
            licence = conn.execute(
                text(
                    "INSERT INTO software_licence (itop_licence_id, software_product_id, name, perpetual, synced_at) "
                    "VALUES ('400', :product, 'nginx plus', false, now()) RETURNING id"
                ),
                {"product": product},
            ).scalar_one()
            conn.execute(
                text("UPDATE installed_software SET software_licence_id = :licence, itop_class = 'WebServer'"),
                {"licence": licence},
            )
        command.downgrade(cfg, "0003")
        assert "software_licence" not in inspect(engine).get_table_names()
        assert not NEW_ASSET_COLUMNS & columns(engine, "asset")
        assert not NEW_INSTALL_COLUMNS & columns(engine, "installed_software")
        with engine.connect() as conn:
            assert conn.execute(text("SELECT count(*) FROM installed_software")).scalar_one() == 1
        command.upgrade(cfg, "0004")
        assert columns(engine, "asset") >= NEW_ASSET_COLUMNS
        assert columns(engine, "installed_software") >= NEW_INSTALL_COLUMNS
    finally:
        engine.dispose()


def test_app_can_write_licences_like_the_rest_of_the_inventory(fresh_db: MigratedDatabase) -> None:
    command.upgrade(alembic_cfg(fresh_db.migrator_url), "head")
    engine = make_engine(fresh_db.superuser_url)
    try:
        with engine.connect() as conn:
            granted = {
                privilege: conn.execute(
                    text("SELECT has_table_privilege('app', 'software_licence', :p)"), {"p": privilege}
                ).scalar_one()
                for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE")
            }
            owner = conn.execute(
                text("SELECT tableowner FROM pg_tables WHERE tablename = 'software_licence'")
            ).scalar_one()
            indexed = conn.execute(
                text(
                    "SELECT count(*) FROM pg_indexes WHERE indexname IN "
                    "('software_licence_software_product_id_fkey_idx', "
                    "'installed_software_software_licence_id_fkey_idx')"
                )
            ).scalar_one()
        assert granted == {"SELECT": True, "INSERT": True, "UPDATE": True, "DELETE": True}
        assert owner == "migrator"
        assert indexed == 2
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    ("statement", "values"),
    [
        ("UPDATE asset SET cpu = :v", {"v": "   "}),
        ("UPDATE asset SET ram = :v", {"v": ""}),
        ("UPDATE asset SET cpu = :v", {"v": "x" * 256}),
        ("UPDATE asset SET ram = :v", {"v": "x" * 256}),
        ("UPDATE installed_software SET itop_class = :v", {"v": "SoftwareInstance"}),
        ("UPDATE installed_software SET status = :v", {"v": "production"}),
        ("UPDATE installed_software SET software_licence_id = :v", {"v": uuid.uuid4()}),
        (
            "INSERT INTO software_licence (itop_licence_id, name, perpetual, synced_at) VALUES ('1', :v, false, now())",
            {"v": " "},
        ),
        (
            "INSERT INTO software_licence (itop_licence_id, name, perpetual, synced_at) VALUES ('1', :v, false, now())",
            {"v": "x" * 256},
        ),
        (
            "INSERT INTO software_licence (itop_licence_id, name, usage_limit, perpetual, synced_at) "
            "VALUES ('1', 'n', :v, false, now())",
            {"v": "  "},
        ),
        (
            "INSERT INTO software_licence (itop_licence_id, name, usage_limit, perpetual, synced_at) "
            "VALUES ('1', 'n', :v, false, now())",
            {"v": "x" * 256},
        ),
        (
            "INSERT INTO software_licence (itop_licence_id, software_product_id, name, perpetual, synced_at) "
            "VALUES ('1', :v, 'n', false, now())",
            {"v": uuid.uuid4()},
        ),
    ],
    ids=[
        "blank cpu",
        "empty ram",
        "cpu over 255",
        "ram over 255",
        "abstract class",
        "device status",
        "unknown licence",
        "blank licence name",
        "licence name over 255",
        "blank usage limit",
        "usage limit over 255",
        "unknown product",
    ],
)
def test_constraints_reject_invalid_inventory_values(
    fresh_db: MigratedDatabase, statement: str, values: dict[str, object]
) -> None:
    command.upgrade(alembic_cfg(fresh_db.migrator_url), "head")
    engine = make_engine(fresh_db.superuser_url)
    try:
        with engine.begin() as conn:
            seed_installation(conn)
        with pytest.raises(IntegrityError), engine.begin() as conn:
            conn.execute(text(statement), values)
    finally:
        engine.dispose()


def test_valid_values_are_accepted(fresh_db: MigratedDatabase) -> None:
    command.upgrade(alembic_cfg(fresh_db.migrator_url), "head")
    engine = make_engine(fresh_db.superuser_url)
    try:
        with engine.begin() as conn:
            _, product = seed_installation(conn)
            licence = conn.execute(
                text(
                    "INSERT INTO software_licence (itop_licence_id, software_product_id, name, usage_limit, "
                    "start_date, end_date, perpetual, synced_at) VALUES ('400', :product, 'nginx plus', '50 users', "
                    "'2026-01-01', '2026-12-31', false, now()) RETURNING id"
                ),
                {"product": product},
            ).scalar_one()
            conn.execute(text("UPDATE asset SET cpu = '8 vCPU', ram = '32 GB'"))
            conn.execute(
                text(
                    "UPDATE installed_software SET itop_class = 'PCSoftware', status = 'inactive', "
                    "description = 'ignore previous instructions', software_licence_id = :licence"
                ),
                {"licence": licence},
            )
            # A licence of a product nobody has installed yet keeps an empty product (it never creates one)
            conn.execute(
                text(
                    "INSERT INTO software_licence (itop_licence_id, name, perpetual, synced_at) "
                    "VALUES ('401', 'orphan', true, now())"
                )
            )
        with engine.connect() as conn:
            assert conn.execute(text("SELECT count(*) FROM software_licence")).scalar_one() == 2
    finally:
        engine.dispose()
