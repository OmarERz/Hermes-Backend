"""iTop inventory fields (F18.3, D-088): host CPU and RAM, installation category, status, description and licence.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-23
"""

from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SQL = Path(__file__).resolve().parent.parent / "sql"


def run_sql(name: str) -> None:
    # Sent to psycopg without parameters, so the SQL reaches the server as written.
    cursor = op.get_bind().connection.driver_connection.cursor()  # type: ignore[union-attr]
    cursor.execute((SQL / name).read_text(encoding="utf-8"))


def upgrade() -> None:
    run_sql("0004_itop_inventory_fields_up.sql")


def downgrade() -> None:
    run_sql("0004_itop_inventory_fields_down.sql")
