"""`python -m slack_app migrate`: the Slack module's own chain, run as migrator (F11.1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from slack_app import __main__ as entry
from slack_app import migrate

pytestmark = pytest.mark.unit


def test_the_chain_lives_in_the_slack_module() -> None:
    cfg = migrate.alembic_config()
    assert Path(str(cfg.get_main_option("script_location"))).name == "migrations"
    assert (migrate.MIGRATIONS / "env.py").is_file()
    assert (migrate.MIGRATIONS / "sql" / "0001_slack_tables_up.sql").is_file()


def test_migrations_never_use_the_application_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MIGRATION_DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgresql://app@db/hermes")
    with pytest.raises(RuntimeError, match="MIGRATION_DATABASE_URL"):
        migrate.migration_url()


def test_the_migrator_password_comes_from_its_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIGRATION_DATABASE_URL", "postgresql://migrator@db:5432/hermes")
    monkeypatch.setenv("MIGRATOR_DB_PASSWORD", "from-secret")
    assert "migrator:from-secret@db" in migrate.migration_url()


def test_entry_point_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    runs: list[tuple[object, ...]] = []
    monkeypatch.setattr(migrate, "migration_url", lambda: "postgresql://migrator@db/hermes")
    monkeypatch.setattr(migrate, "run", lambda *args: runs.append(args))
    assert entry.main(["migrate"]) == 0
    assert entry.main(["migrate", "downgrade", "base"]) == 0
    assert entry.main(["migrate", "stamp"]) == 2
    assert entry.main([]) == 2
    assert runs == [("postgresql://migrator@db/hermes",), ("postgresql://migrator@db/hermes", "downgrade", "base")]
