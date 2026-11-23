"""One migrated database per module (catalogs and formula only) and an admin API client with fake connection checks."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from dbprovision import provisioned_database
from f10ops import T0, FakeProbes
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from api.app import create_app
from api.auth import CurrentUser, Role, get_current_user
from core.config import Settings
from core.connections.checker import ConnectionChecker
from core.db import models as m
from core.db.seeds import seed
from core.db.session import make_engine

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def database(postgres_url: str) -> Iterator[tuple[str, Engine]]:
    with provisioned_database(postgres_url, "operations") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        engine = make_engine(db.superuser_url)
        with Session(engine) as session, session.begin():
            seed(session, "empty")
            session.add_all(
                [
                    m.AppUser(
                        firebase_uid="admin-1",
                        email="luis@example.test",
                        display_name="Luis Admin",
                        role="admin",
                        active=True,
                        created_at=T0,
                    ),
                    m.AppUser(
                        firebase_uid="analyst-1", email="ana@example.test", role="analyst", active=True, created_at=T0
                    ),
                ]
            )
        try:
            yield db.superuser_url, engine
        finally:
            engine.dispose()


@pytest.fixture
def engine(database: tuple[str, Engine]) -> Engine:
    return database[1]


@pytest.fixture(scope="module")
def probes() -> FakeProbes:
    return FakeProbes()


@pytest.fixture(scope="module")
def client(database: tuple[str, Engine], probes: FakeProbes) -> Iterator[TestClient]:
    settings = Settings.model_validate(
        {"database_url": database[0], "firebase_project_id": "p", "cursor_signing_key": "k" * 40}
    )
    app = create_app(settings)
    app.state.connections = ConnectionChecker(probes, min_interval=timedelta(0))  # tests re-check at once
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid="admin-1", email="luis@example.test", display_name="Luis Admin", role=Role.ADMIN
    )
    with TestClient(app, raise_server_exceptions=True) as test_client:
        yield test_client
