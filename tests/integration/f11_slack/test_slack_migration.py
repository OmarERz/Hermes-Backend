"""The Slack module's own chain (NOT-07, approved 23 Nov 2026): tables, constraints, grants, up and down."""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from dbprovision import MigratedDatabase, provisioned_database
from sqlalchemy import Engine, MetaData, Table, literal_column, select, text
from sqlalchemy import table as sql_table
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError, ProgrammingError

from core.db.provision import provision
from core.db.session import make_engine
from slack_app import migrate

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]
TABLES = ["slack_delivery", "slack_digest_item", "slack_thread"]
KEY = "a" * 64
NOW = "2026-11-23T10:00:00Z"


@pytest.fixture
def fresh_db(postgres_url: str) -> Iterator[MigratedDatabase]:
    with provisioned_database(postgres_url, "slackmig") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        yield db


def slack_tables(engine: Engine) -> list[str]:
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT tablename FROM pg_tables WHERE tablename LIKE 'slack%' ORDER BY 1"))
        return [r.tablename for r in rows]


def test_up_down_and_up_again(fresh_db: MigratedDatabase) -> None:
    engine = make_engine(fresh_db.superuser_url)
    try:
        migrate.run(fresh_db.migrator_url)
        assert slack_tables(engine) == ["slack_alembic_version", *TABLES]
        with engine.connect() as conn:
            owners = set(conn.execute(text("SELECT tableowner FROM pg_tables WHERE tablename LIKE 'slack%'")).scalars())
            version = conn.execute(text("SELECT version_num FROM slack_alembic_version")).scalar_one()
            main_version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        assert owners == {"migrator"}
        assert version == "s0001"
        assert main_version != "s0001"  # the backend's chain is untouched
        migrate.run(fresh_db.migrator_url, "downgrade", "base")
        assert slack_tables(engine) == ["slack_alembic_version"]
        migrate.run(fresh_db.migrator_url)
        assert slack_tables(engine) == ["slack_alembic_version", *TABLES]
    finally:
        engine.dispose()


def test_downgrade_aborts_on_a_foreign_dependency(fresh_db: MigratedDatabase) -> None:
    """No CASCADE: a view of someone else on a Slack table makes the downgrade fail instead of dropping it."""
    migrate.run(fresh_db.migrator_url)
    engine = make_engine(fresh_db.superuser_url)
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE VIEW foreign_view AS SELECT event_id FROM slack_delivery"))
        with pytest.raises(psycopg.errors.DependentObjectsStillExist):
            migrate.run(fresh_db.migrator_url, "downgrade", "base")
        assert "slack_delivery" in slack_tables(engine)
    finally:
        engine.dispose()


def test_runner_rejects_an_unknown_action() -> None:
    with pytest.raises(ValueError, match="upgrade or downgrade"):
        migrate.run("postgresql://x@localhost/db", "stamp")


GOOD: dict[str, dict[str, Any]] = {
    "slack_thread": {
        "thread_key": KEY,
        "audience": "standard",
        "channel_id": "C0123456",
        "root_ts": "1700000000.000100",
        "created_at": NOW,
        "updated_at": NOW,
    },
    "slack_delivery": {
        "event_id": "evt-1",
        "audience": "restricted",
        "channel_id": "C0123456",
        "delivery": "message",
        "message_ts": "1700000000.000100",
        "delivered_at": NOW,
    },
    "slack_digest_item": {
        "event_id": "evt-2",
        "channel_id": "C0123456",
        "payload": {"event_id": "evt-2"},
        "queued_at": NOW,
        "status": "queued",
        "attempts": 0,
        "next_attempt_at": NOW,
        "last_error": None,
        "digest_ts": None,
    },
}
BAD = [
    ("slack_thread", {"thread_key": "not-a-sha"}),
    ("slack_thread", {"audience": "everyone"}),
    ("slack_thread", {"channel_id": "#general"}),
    ("slack_thread", {"root_ts": "yesterday"}),
    ("slack_thread", {"updated_at": "2026-11-22T10:00:00Z"}),
    ("slack_delivery", {"event_id": ""}),
    ("slack_delivery", {"event_id": "e" * 129}),
    ("slack_delivery", {"delivery": "email"}),
    ("slack_delivery", {"message_ts": "1.2.3"}),
    ("slack_digest_item", {"payload": [1, 2]}),
    ("slack_digest_item", {"status": "sent"}),
    ("slack_digest_item", {"attempts": -1}),
    ("slack_digest_item", {"next_attempt_at": None}),
    ("slack_digest_item", {"status": "failed"}),  # a failed item has no next attempt
    ("slack_digest_item", {"last_error": "x" * 201}),
    ("slack_digest_item", {"digest_ts": "soon"}),
]


def insert(engine: Engine, table: str, row: dict[str, Any]) -> None:
    with engine.begin() as conn:
        conn.execute(Table(table, MetaData(), autoload_with=conn).insert().values(**row))


@pytest.mark.parametrize(("table", "change"), BAD)
def test_constraints_reject_invalid_rows(slack_engine: Engine, table: str, change: dict[str, Any]) -> None:
    with pytest.raises(IntegrityError):
        insert(slack_engine, table, {**GOOD[table], **change})


def test_valid_rows_are_accepted_and_keys_are_unique(slack_engine: Engine) -> None:
    for table, row in GOOD.items():
        insert(slack_engine, table, row)
    insert(slack_engine, "slack_delivery", {**GOOD["slack_delivery"], "audience": "standard"})  # other audience
    with pytest.raises(IntegrityError):
        insert(slack_engine, "slack_delivery", GOOD["slack_delivery"])


def test_slack_module_uses_only_its_tables(slack_engine: Engine) -> None:
    with slack_engine.connect() as conn, pytest.raises(ProgrammingError, match="permission denied"):
        conn.execute(text("SELECT 1 FROM notification_event LIMIT 1"))
    with slack_engine.connect() as conn, pytest.raises(ProgrammingError, match="permission denied"):
        conn.execute(text("SELECT 1 FROM slack_alembic_version"))


def test_the_backend_roles_cannot_read_slack_tables(slack_db: Any) -> None:
    engine = make_engine(slack_db.app_url)
    try:
        for table in TABLES:
            with engine.connect() as conn, pytest.raises(ProgrammingError, match="permission denied"):
                conn.execute(select(literal_column("1")).select_from(sql_table(table)))
    finally:
        engine.dispose()


def test_without_its_password_slack_module_cannot_log_in(fresh_db: MigratedDatabase) -> None:
    """Optional login role (approved 23 Nov 2026): LOGIN only while SLACK_DB_PASSWORD is configured."""
    sql_path = ROOT / "migrations" / "provision.sql"
    password = secrets.token_urlsafe(16)
    url = make_url(fresh_db.superuser_url).set(username="slack_module", password=password)
    provision(fresh_db.superuser_url, {"slack_module": password}, sql_path)
    with psycopg.connect(url.render_as_string(hide_password=False)) as conn:
        assert conn.execute("SELECT current_user").fetchone() == ("slack_module",)
    provision(fresh_db.superuser_url, {}, sql_path, nologin=["slack_module"])
    with pytest.raises(psycopg.OperationalError):
        psycopg.connect(url.render_as_string(hide_password=False))
