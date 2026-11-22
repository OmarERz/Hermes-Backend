"""Provision throwaway databases the way production does: provisioning SQL as superuser, then Alembic as migrator."""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import psycopg
from psycopg import sql
from sqlalchemy.engine import make_url

from core.db.provision import provision

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class MigratedDatabase:
    superuser_url: str
    migrator_url: str


@contextmanager
def provisioned_database(postgres_url: str, prefix: str) -> Iterator[MigratedDatabase]:
    """A fresh database provisioned as superuser (migrations/provision.sql), as compose does at first start.

    The migrator role gets a random login password so Alembic runs as migrator, never as superuser (DAT-05).
    """
    name = f"{prefix}_{secrets.token_hex(4)}"
    password = secrets.token_urlsafe(16)
    with psycopg.connect(postgres_url, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    superuser_url = make_url(postgres_url).set(database=name)
    try:
        provision(
            superuser_url.render_as_string(hide_password=False),
            {"migrator": password},
            ROOT / "migrations" / "provision.sql",
        )
        migrator_url = superuser_url.set(username="migrator", password=password)
        yield MigratedDatabase(
            superuser_url.render_as_string(hide_password=False), migrator_url.render_as_string(hide_password=False)
        )
    finally:
        with psycopg.connect(postgres_url, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))
