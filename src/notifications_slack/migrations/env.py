"""Alembic environment of the Slack module's own chain (NOT-07): version table `slack_alembic_version`.

It never opens a connection itself: the runner (`python -m slack_app migrate`, the composition root) passes one as
the migrator role in `config.attributes["connection"]`, with the backend's TLS and secret handling. There is no target
metadata: the revisions are hand-written SQL, so autogenerate can never propose touching the backend's tables.
"""

from __future__ import annotations

from alembic import context

VERSION_TABLE = "slack_alembic_version"


def run_migrations_online() -> None:
    connection = context.config.attributes.get("connection")
    if connection is None:
        raise RuntimeError("Run the Slack migrations with: python -m slack_app migrate")
    context.configure(
        connection=connection,
        target_metadata=None,
        version_table=VERSION_TABLE,
        transaction_per_migration=False,
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    raise RuntimeError("Offline migrations are not supported")
run_migrations_online()
