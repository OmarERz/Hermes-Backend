"""Least-privilege database roles (DAT-05, model v1 §17): migrator owns the schema, app, retention, slack_module.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-22
"""

from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SQL = Path(__file__).resolve().parent.parent / "sql"


def run_sql(name: str) -> None:
    # Sent to psycopg without parameters, so '%' and '::' in the validated SQL reach the server as written.
    cursor = op.get_bind().connection.driver_connection.cursor()  # type: ignore[union-attr]
    cursor.execute((SQL / name).read_text(encoding="utf-8"))


def upgrade() -> None:
    run_sql("0002_roles_up.sql")


def downgrade() -> None:
    run_sql("0002_roles_down.sql")
