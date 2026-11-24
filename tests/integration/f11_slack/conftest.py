"""One database per module with both chains applied: the backend's (Alembic, as migrator) and the Slack module's."""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from dbprovision import provisioned_database
from slackdb import SlackDatabase
from sqlalchemy import Engine, text
from sqlalchemy.engine import make_url

from core.db.provision import provision
from core.db.session import make_engine
from slack_app import migrate

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def slack_db(postgres_url: str) -> Iterator[SlackDatabase]:
    with provisioned_database(postgres_url, "slack") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        migrate.run(db.migrator_url)
        slack_pw, app_pw = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
        provision(db.superuser_url, {"slack_module": slack_pw, "app": app_pw}, ROOT / "migrations" / "provision.sql")
        base = make_url(db.superuser_url)
        yield SlackDatabase(
            db.superuser_url,
            db.migrator_url,
            base.set(username="slack_module", password=slack_pw).render_as_string(hide_password=False),
            base.set(username="app", password=app_pw).render_as_string(hide_password=False),
        )


@pytest.fixture
def slack_engine(slack_db: SlackDatabase) -> Iterator[Engine]:
    """Connected as slack_module (what the Slack service uses); the slack_* tables are emptied first."""
    engine = make_engine(slack_db.slack_url)
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM slack_digest_item; DELETE FROM slack_delivery; DELETE FROM slack_thread"))
    try:
        yield engine
    finally:
        engine.dispose()
