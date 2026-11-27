"""F18.1: the findings scenario of F10.2 plus recent activity (runs, reviews, a configuration change), one database
per module, and API clients as reader and as admin."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from dbprovision import provisioned_database
from f18data import Front, build_front
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
    with provisioned_database(postgres_url, "front") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        engine = make_engine(db.superuser_url)
        try:
            yield db.superuser_url, engine
        finally:
            engine.dispose()


@pytest.fixture(scope="module")
def front(database: tuple[str, Engine]) -> Front:
    with Session(database[1]) as session, session.begin():
        return build_front(session)


def _client(url: str, role: Role) -> TestClient:
    settings = Settings.model_validate(
        {"database_url": url, "firebase_project_id": "p", "cursor_signing_key": "k" * 40, "itop_url": ITOP}
    )
    app = create_app(settings)
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid=f"{role.value}-1", email=f"{role.value}@example.test", display_name=None, role=role
    )
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture(scope="module")
def client(database: tuple[str, Engine], front: Front) -> Iterator[TestClient]:
    assert front.scenario.groups  # the data is in place before the first request
    with _client(database[0], Role.READER) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def admin(database: tuple[str, Engine], front: Front) -> Iterator[TestClient]:
    assert front.scenario.groups
    with _client(database[0], Role.ADMIN) as test_client:
        yield test_client


@pytest.fixture
def get(client: TestClient) -> Callable[..., object]:
    def call(url: str, **params: object) -> object:
        response = client.get(url, params=params)
        assert response.status_code == 200, response.text
        return response.json()

    return call
