"""Initial schema: data model v1 as validated in capa 2 (extensions, tables, constraints, triggers, views).

Revision ID: 0001
Revises:
Create Date: 2026-11-22
"""

from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SQL = Path(__file__).resolve().parent.parent / "sql"


def run_sql(name: str) -> None:
    # Sent to psycopg without parameters, so '%' and '::' in the validated SQL reach the server as written.
    cursor = op.get_bind().connection.driver_connection.cursor()  # type: ignore[union-attr]
    cursor.execute((SQL / name).read_text(encoding="utf-8"))


def upgrade() -> None:
    run_sql("0001_schema_up.sql")


def downgrade() -> None:
    run_sql("0001_schema_down.sql")
