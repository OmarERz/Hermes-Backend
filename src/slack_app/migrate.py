"""The Slack module's own Alembic chain (NOT-07, version table `slack_alembic_version`), run as the migrator role.

The chain lives in `notifications_slack/migrations`; this runner gives it a connection made with the backend's rules
(`MIGRATION_DATABASE_URL`, the `migrator_db_password` secret, TLS off-host), exactly like the main chain. The compose
`migrate` service runs it right after `alembic upgrade head`.
"""

from __future__ import annotations

import os
from pathlib import Path

from alembic import command
from alembic.config import Config

import notifications_slack
from core.config import read_secret
from core.db.session import make_engine, with_password

MIGRATIONS = Path(notifications_slack.__file__).resolve().parent / "migrations"


def alembic_config() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    cfg.set_main_option("path_separator", "os")
    return cfg


def migration_url() -> str:
    """Never the application's DATABASE_URL: migrations run as migrator (DAT-05)."""
    url = os.environ.get("MIGRATION_DATABASE_URL")
    if not url:
        raise RuntimeError("Set MIGRATION_DATABASE_URL (migrator role) to run migrations")
    return with_password(url, read_secret("migrator_db_password"))


def run(url: str, action: str = "upgrade", revision: str = "head") -> None:
    """`upgrade` (default, to head) or `downgrade` (to `revision`), in one transaction."""
    if action not in ("upgrade", "downgrade"):
        raise ValueError("action must be upgrade or downgrade")
    engine = make_engine(url)
    try:
        with engine.begin() as connection:
            cfg = alembic_config()
            cfg.attributes["connection"] = connection
            if action == "upgrade":
                command.upgrade(cfg, revision)
            else:
                command.downgrade(cfg, revision)
    finally:
        engine.dispose()
