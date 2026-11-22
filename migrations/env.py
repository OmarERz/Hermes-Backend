"""Alembic environment: online migrations only, URL from the environment (never from alembic.ini)."""

from __future__ import annotations

import os

from alembic import context

from core.db import models
from core.db.session import make_engine

config = context.config
# Importing the models registers every table on Base.metadata (autogenerate compares against it).
target_metadata = models.Base.metadata

# Indexes and constraints come from the validated SQL (migrations/sql/), not from the models:
# autogenerate must not propose dropping the ones it finds only in the database.
DB_ONLY_KINDS = {"index", "unique_constraint", "foreign_key_constraint"}


def include_object(obj: object, name: str | None, type_: str, reflected: bool, compare_to: object) -> bool:
    # Tables that exist only in the database belong to someone else (e.g. the Slack team's slack_* tables):
    # autogenerate must never propose dropping them.
    if type_ == "table" and reflected and compare_to is None:
        return False
    return not (reflected and compare_to is None and type_ in DB_ONLY_KINDS)


def database_url() -> str:
    """Migrations run with the migrator role (DAT-05): never fall back to the application's DATABASE_URL."""
    url = config.attributes.get("url") or os.environ.get("MIGRATION_DATABASE_URL")
    if not url:
        raise RuntimeError("Set MIGRATION_DATABASE_URL (migrator role) to run migrations")
    return str(url)


def run_migrations_online() -> None:
    engine = make_engine(database_url())
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_object=include_object,
            # One transaction for the whole command: a downgrade blocked halfway leaves nothing half-undone.
            transaction_per_migration=False,
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    raise RuntimeError("Offline migrations are not supported")
run_migrations_online()
