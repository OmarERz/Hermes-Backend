"""Fixtures for the constraint suite: one migrated database (alembic upgrade head) per session."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from dbprovision import provisioned_database
from dbsupport import Builder, Tbl, load_catalog

ROOT = Path(__file__).resolve().parents[4]


@pytest.fixture(scope="session")
def dsn(postgres_url: str) -> Iterator[str]:
    """A database provisioned and built by the real migrations (run as migrator), as the app will find it."""
    with provisioned_database(postgres_url, "constraints") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        yield db.superuser_url


@pytest.fixture(scope="session")
def catalog(dsn: str) -> dict[str, Tbl]:
    with psycopg.connect(dsn) as conn:
        return load_catalog(conn)


@pytest.fixture
def conn(dsn: str) -> Iterator[psycopg.Connection[Any]]:
    with psycopg.connect(dsn) as c:
        c.execute("BEGIN")
        try:
            yield c
        finally:
            c.rollback()


@pytest.fixture
def build(conn: psycopg.Connection[Any], catalog: dict[str, Tbl]) -> Builder:
    return Builder(conn, catalog)
