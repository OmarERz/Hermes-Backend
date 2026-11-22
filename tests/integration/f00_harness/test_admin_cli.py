"""Admin CLI (core.devtools.admin): seed a scenario as migrator and list notification events (D-059)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from dbprovision import MigratedDatabase, provisioned_database
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.session import make_engine
from core.devtools.admin import main

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def migrated(postgres_url: str) -> Iterator[MigratedDatabase]:
    with provisioned_database(postgres_url, "admin") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        yield db


def _insert_events(url: str) -> None:
    now = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
    engine = make_engine(url)
    try:
        with engine.begin() as conn:
            for i, (event_type, status) in enumerate([("new_ticket", "pending"), ("fixed", "failed")]):
                conn.execute(
                    text(
                        "INSERT INTO notification_event (contract_version, event_type, priority, payload, status, "
                        "attempts, last_error, created_at) VALUES ('1.0', :t, 'normal', '{}', :s, :a, :e, :c)"
                    ),
                    {
                        "t": event_type,
                        "s": status,
                        "a": i,
                        "e": "timeout" if status == "failed" else None,
                        "c": now + timedelta(minutes=i),
                    },
                )
    finally:
        engine.dispose()


def test_seed_then_list_events(
    migrated: MigratedDatabase, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MIGRATION_DATABASE_URL", migrated.migrator_url)
    assert main(["seed", "--scenario", "demo"]) == 0
    engine = make_engine(migrated.superuser_url)
    try:
        with Session(engine) as session:
            assert session.scalar(select(func.count()).select_from(m.Finding)) == 2
    finally:
        engine.dispose()

    _insert_events(migrated.superuser_url)
    monkeypatch.setenv("DATABASE_URL", migrated.superuser_url)
    capsys.readouterr()
    assert main(["events", "--limit", "5"]) == 0
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [(r["type"], r["status"]) for r in rows] == [("fixed", "failed"), ("new_ticket", "pending")]
    assert rows[0]["last_error"] == "timeout"

    assert main(["events", "--status", "pending"]) == 0
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [r["type"] for r in rows] == ["new_ticket"]

    assert main(["events", "--type", "fixed"]) == 0
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [r["status"] for r in rows] == ["failed"]


def test_seeding_twice_reports_an_error(
    migrated: MigratedDatabase, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MIGRATION_DATABASE_URL", migrated.migrator_url)
    assert main(["seed", "--scenario", "empty"]) == 0
    assert main(["seed", "--scenario", "empty"]) == 2
    assert "already seeded" in capsys.readouterr().err


def test_missing_url_is_reported(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert main(["events"]) == 2
    assert "DATABASE_URL is not set" in capsys.readouterr().err


def test_limit_is_bounded() -> None:
    with pytest.raises(SystemExit):
        main(["events", "--limit", "0"])
