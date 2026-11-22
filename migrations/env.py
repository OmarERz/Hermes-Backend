"""Alembic environment: online migrations only, URL from the environment (never from alembic.ini)."""

from __future__ import annotations

import os

from alembic import context

from core.db.session import make_engine

config = context.config
# No metadata until the models exist (F0.6-T2): `--autogenerate` then fails instead of proposing to drop
# every table of the schema.
target_metadata = None


def database_url() -> str:
    """Migrations run with the migrator role (DAT-05): never fall back to the application's DATABASE_URL."""
    url = config.attributes.get("url") or os.environ.get("MIGRATION_DATABASE_URL")
    if not url:
        raise RuntimeError("Set MIGRATION_DATABASE_URL (migrator role) to run migrations")
    return str(url)


def run_migrations_online() -> None:
    engine = make_engine(database_url())
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, transaction_per_migration=True)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    raise RuntimeError("Offline migrations are not supported")
run_migrations_online()
