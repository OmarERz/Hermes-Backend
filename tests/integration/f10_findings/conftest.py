"""One migrated database per module with the findings scenario, and an API client on it."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from dbprovision import provisioned_database
from f10data import Scenario, build_scenario
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from api.app import create_app
from api.auth import CurrentUser, Role, get_current_user
from core.config import Settings
from core.db.session import make_engine

ROOT = Path(__file__).resolve().parents[3]
ITOP = "https://itop.example.test"


@pytest.fixture(scope="module")
def database(postgres_url: str) -> Iterator[tuple[str, Engine]]:
    with provisioned_database(postgres_url, "findings") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        engine = make_engine(db.superuser_url)
        try:
            yield db.superuser_url, engine
        finally:
            engine.dispose()


@pytest.fixture(scope="module")
def scenario(database: tuple[str, Engine]) -> Scenario:
    with Session(database[1]) as session, session.begin():
        return build_scenario(session)


@pytest.fixture(scope="module")
def client(database: tuple[str, Engine], scenario: Scenario) -> Iterator[TestClient]:
    assert scenario.groups  # the data is in place before the first request
    # model_validate skips the settings sources: the test sees only these values.
    settings = Settings.model_validate(
        {
            "database_url": database[0],
            "firebase_project_id": "p",
            "cursor_signing_key": "k" * 40,
            "itop_url": ITOP,
        }
    )
    app = create_app(settings)
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid="reader-1", email="reader@example.test", display_name=None, role=Role.READER
    )
    with TestClient(app, raise_server_exceptions=True) as test_client:
        yield test_client


@pytest.fixture
def get(client: TestClient) -> Callable[..., object]:
    def call(url: str, **params: object) -> object:
        response = client.get(url, params=params)
        assert response.status_code == 200, response.text
        return response.json()

    return call
