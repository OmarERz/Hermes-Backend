"""The generated models describe data model v1 and are valid DDL on PostgreSQL 18."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, inspect, text

from core.db import models
from core.db.base import Base
from core.db.session import make_engine

pytestmark = pytest.mark.integration


@pytest.fixture
def scratch_engine(postgres_url: str) -> Iterator[Engine]:
    """A fresh schema per test, dropped afterwards."""
    engine = make_engine(postgres_url)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS models_probe CASCADE; CREATE SCHEMA models_probe"))
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS citext"))
    yield engine.execution_options(schema_translate_map={None: "models_probe"})
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA models_probe CASCADE"))
    engine.dispose()


def test_model_counts_match_data_model_v1() -> None:
    tables = Base.metadata.tables
    assert len(tables) == 75
    assert sum(len(t.foreign_keys) for t in tables.values()) == 118
    assert sum(len(t.columns) for t in tables.values()) == 519


def test_create_all_on_postgres_18(scratch_engine: Engine) -> None:
    Base.metadata.create_all(scratch_engine)
    names = set(inspect(scratch_engine).get_table_names(schema="models_probe"))
    assert names == set(Base.metadata.tables)


def test_uuid_primary_keys_default_to_uuidv7() -> None:
    column = models.AppUser.__table__.c.id
    assert column.server_default is not None
    assert "uuidv7" in str(column.server_default.arg)
