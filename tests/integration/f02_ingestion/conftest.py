"""One migrated database with the settings catalog per module; ingestion tables are emptied after each test."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from dbprovision import provisioned_database
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.db.seeds import seed
from core.db.session import make_engine

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def migrated_url(postgres_url: str) -> Iterator[str]:
    with provisioned_database(postgres_url, "ingestion") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        engine = make_engine(db.superuser_url)
        with Session(engine) as session, session.begin():
            seed(session, "empty")
        engine.dispose()
        yield db.superuser_url


@pytest.fixture
def session(migrated_url: str) -> Iterator[Session]:
    engine = make_engine(migrated_url)
    with Session(engine, expire_on_commit=False) as db_session:
        yield db_session
        db_session.rollback()
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE raw_article, story, source_fetch, run, source, audit_log CASCADE"))
    engine.dispose()
