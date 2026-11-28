"""Migration 0005 (F15.9, D-107): the CPE part of the NVD pair and content CHECKs on the CNA names of `cpe_mapping`.

Existing mappings with an NVD pair take part `a`; a CNA-only mapping keeps no part; going down drops only what 0005
added; the constraints reject a part outside a/o/h, a part without an NVD pair (and the reverse) and blank or long
CNA names."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from dbprovision import MigratedDatabase, provisioned_database
from sqlalchemy import Connection, Engine, inspect, text
from sqlalchemy.exc import IntegrityError

from core.db.session import make_engine

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]
NEW_CHECKS = {
    "cpe_mapping_nvd_part_check",
    "cpe_mapping_nvd_part_pair",
    "cpe_mapping_cna_vendor_check",
    "cpe_mapping_cna_product_check",
}


@pytest.fixture
def fresh_db(postgres_url: str) -> Iterator[MigratedDatabase]:
    with provisioned_database(postgres_url, "cpe") as db:
        yield db


def alembic_cfg(url: str) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.attributes["url"] = url
    return cfg


def product(conn: Connection, name: str) -> uuid.UUID:
    return uuid.UUID(
        str(
            conn.execute(
                text("INSERT INTO software_product (itop_name, first_seen_at) VALUES (:n, now()) RETURNING id"),
                {"n": name},
            ).scalar_one()
        )
    )


def seed_mappings(conn: Connection) -> dict[str, uuid.UUID]:
    """Three mappings written with the columns that exist before 0005: NVD only, CNA only, both pairs."""
    ids = {name: product(conn, name) for name in ("nginx", "kernel", "postgres")}
    conn.execute(
        text(
            "INSERT INTO cpe_mapping (software_product_id, nvd_vendor, nvd_product, cna_vendor, cna_product, origin, "
            "mapped_at) VALUES (:nginx, 'f5', 'nginx', NULL, NULL, 'manual', now()), "
            "(:kernel, NULL, NULL, 'Linux', 'Linux', 'manual', now()), "
            "(:postgres, 'postgresql', 'postgresql', 'n/a', 'PostgreSQL', 'manual', now())"
        ),
        {k: str(v) for k, v in ids.items()},
    )
    return ids


def seed_mappings_with_part(conn: Connection) -> None:
    """The same three mappings written after 0005, where an NVD pair needs its part."""
    ids = {name: str(product(conn, name)) for name in ("nginx", "kernel", "postgres")}
    conn.execute(
        text(
            "INSERT INTO cpe_mapping (software_product_id, nvd_part, nvd_vendor, nvd_product, cna_vendor, cna_product, "
            "origin, mapped_at) VALUES (:nginx, 'o', 'f5', 'nginx', NULL, NULL, 'manual', now()), "
            "(:kernel, NULL, NULL, NULL, 'Linux', 'Linux', 'manual', now()), "
            "(:postgres, 'a', 'postgresql', 'postgresql', 'n/a', 'PostgreSQL', 'manual', now())"
        ),
        ids,
    )


def checks(engine: Engine) -> set[str]:
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT conname FROM pg_constraint WHERE conrelid = 'cpe_mapping'::regclass AND contype = 'c'")
        )
        return {row[0] for row in rows}


def test_upgrade_gives_existing_nvd_pairs_part_a_and_cna_only_rows_none(fresh_db: MigratedDatabase) -> None:
    cfg = alembic_cfg(fresh_db.migrator_url)
    command.upgrade(cfg, "0004")
    engine = make_engine(fresh_db.superuser_url)
    try:
        with engine.begin() as conn:
            ids = seed_mappings(conn)
        command.upgrade(cfg, "0005")
        with engine.connect() as conn:
            parts = dict(conn.execute(text("SELECT software_product_id, nvd_part FROM cpe_mapping")).all())
        assert parts == {ids["nginx"]: "a", ids["kernel"]: None, ids["postgres"]: "a"}
        assert checks(engine) >= NEW_CHECKS
    finally:
        engine.dispose()


def test_downgrade_drops_only_what_0005_added_and_keeps_the_cna_names(fresh_db: MigratedDatabase) -> None:
    cfg = alembic_cfg(fresh_db.migrator_url)
    command.upgrade(cfg, "0005")
    engine = make_engine(fresh_db.superuser_url)
    try:
        with engine.begin() as conn:
            seed_mappings_with_part(conn)
        command.downgrade(cfg, "0004")
        names = {c["name"] for c in inspect(engine).get_columns("cpe_mapping")}
        assert "nvd_part" not in names
        assert {"cna_vendor", "cna_product"} <= names
        assert not NEW_CHECKS & checks(engine)
        assert {"cpe_mapping_one_pair", "cpe_mapping_nvd_pair", "cpe_mapping_cna_pair"} <= checks(engine)
        with engine.connect() as conn:
            kept = conn.execute(text("SELECT cna_vendor, cna_product FROM cpe_mapping ORDER BY cna_vendor")).all()
        assert [tuple(row) for row in kept] == [("Linux", "Linux"), ("n/a", "PostgreSQL"), (None, None)]
        command.upgrade(cfg, "0005")
        assert checks(engine) >= NEW_CHECKS
    finally:
        engine.dispose()


def test_upgrade_refuses_cna_names_the_api_never_writes(fresh_db: MigratedDatabase) -> None:
    """A blank CNA name already stored makes the whole upgrade roll back: nothing is lost or half applied."""
    cfg = alembic_cfg(fresh_db.migrator_url)
    command.upgrade(cfg, "0004")
    engine = make_engine(fresh_db.superuser_url)
    try:
        with engine.begin() as conn:
            item = product(conn, "odd")
            conn.execute(
                text(
                    "INSERT INTO cpe_mapping (software_product_id, cna_vendor, cna_product, origin, mapped_at) "
                    "VALUES (:p, '  ', 'x', 'manual', now())"
                ),
                {"p": str(item)},
            )
        with pytest.raises(psycopg.errors.CheckViolation):  # the migration runs on the raw psycopg cursor
            command.upgrade(cfg, "0005")
        assert "nvd_part" not in {c["name"] for c in inspect(engine).get_columns("cpe_mapping")}
    finally:
        engine.dispose()


INSERT = text(
    "INSERT INTO cpe_mapping (software_product_id, nvd_part, nvd_vendor, nvd_product, cna_vendor, cna_product, "
    "origin, mapped_at) VALUES (:p, :nvd_part, :nvd_vendor, :nvd_product, :cna_vendor, :cna_product, 'manual', now())"
)
COLUMNS = ("nvd_part", "nvd_vendor", "nvd_product", "cna_vendor", "cna_product")


def row(item: uuid.UUID, values: dict[str, str | None]) -> dict[str, str | None]:
    """The INSERT's parameters: the given values, every other column NULL."""
    return {"p": str(item), **dict.fromkeys(COLUMNS), **values}


NVD = {"nvd_vendor": "linux", "nvd_product": "linux_kernel"}


@pytest.mark.parametrize(
    "values",
    [
        {**NVD, "nvd_part": "x"},
        {**NVD, "nvd_part": "A"},
        {**NVD, "nvd_part": None},
        {"nvd_part": "o", "cna_vendor": "Linux", "cna_product": "Linux"},
        {"cna_vendor": "", "cna_product": "Linux"},
        {"cna_vendor": "Linux", "cna_product": "   "},
        {"cna_vendor": "v" * 201, "cna_product": "Linux"},
        {"cna_vendor": "Linux", "cna_product": "p" * 201},
    ],
    ids=[
        "unknown part",
        "upper-case part",
        "nvd pair without part",
        "part without nvd pair",
        "empty cna vendor",
        "blank cna product",
        "cna vendor over 200",
        "cna product over 200",
    ],
)
def test_constraints_reject_invalid_mappings(fresh_db: MigratedDatabase, values: dict[str, str | None]) -> None:
    command.upgrade(alembic_cfg(fresh_db.migrator_url), "head")
    engine = make_engine(fresh_db.superuser_url)
    try:
        with engine.begin() as conn:
            item = product(conn, "nginx")
        with pytest.raises(IntegrityError), engine.begin() as conn:
            conn.execute(INSERT, row(item, values))
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "values",
    [
        {**NVD, "nvd_part": "o"},
        {"nvd_part": "h", "nvd_vendor": "cisco", "nvd_product": "asa_5505"},
        {
            "nvd_part": "a",
            "nvd_vendor": "python",
            "nvd_product": "python",
            "cna_vendor": "PSF",
            "cna_product": "CPython",
        },
        {"cna_vendor": "v" * 200, "cna_product": "n/a"},
    ],
    ids=["os", "hardware", "both pairs", "cna only at the limit"],
)
def test_valid_mappings_are_accepted(fresh_db: MigratedDatabase, values: dict[str, str | None]) -> None:
    command.upgrade(alembic_cfg(fresh_db.migrator_url), "head")
    engine = make_engine(fresh_db.superuser_url)
    try:
        with engine.begin() as conn:
            item = product(conn, "nginx")
            conn.execute(INSERT, row(item, values))
        with engine.connect() as conn:
            assert conn.execute(text("SELECT count(*) FROM cpe_mapping")).scalar_one() == 1
    finally:
        engine.dispose()
