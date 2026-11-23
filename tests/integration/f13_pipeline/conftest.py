"""One migrated database per module for the pipeline tests, with the demo seed (catalogs, formula, inventory)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from dbprovision import provisioned_database
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from core.db.seeds import seed
from core.db.session import make_engine

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def engine(postgres_url: str) -> Iterator[Engine]:
    with provisioned_database(postgres_url, "pipeline") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        engine = make_engine(db.superuser_url)
        with Session(engine) as session, session.begin():
            seed(session, "demo")
        try:
            yield engine
        finally:
            engine.dispose()


@pytest.fixture
def factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)
