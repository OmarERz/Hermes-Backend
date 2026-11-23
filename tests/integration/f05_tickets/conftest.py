"""One migrated database per module for the ticket tests; ticket tables are emptied before each test."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from dbprovision import provisioned_database
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from core.db.session import make_engine

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def engine(postgres_url: str) -> Iterator[Engine]:
    with provisioned_database(postgres_url, "tickets") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        engine = make_engine(db.superuser_url)
        try:
            yield engine
        finally:
            engine.dispose()


@pytest.fixture
def factory(engine: Engine) -> Iterator[sessionmaker[Session]]:
    with engine.begin() as connection:
        connection.execute(text("TRUNCATE itop_outbox, notification_event, ticket_update, ticket_finding, ticket"))
    yield sessionmaker(engine, expire_on_commit=False)
