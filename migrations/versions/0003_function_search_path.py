"""Pin a trusted search_path on the functions of 0001 (temporary schema last).

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-22
"""

from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SQL = Path(__file__).resolve().parent.parent / "sql"


def run_sql(name: str) -> None:
    # Sent to psycopg without parameters, so the SQL reaches the server as written.
    cursor = op.get_bind().connection.driver_connection.cursor()  # type: ignore[union-attr]
    cursor.execute((SQL / name).read_text(encoding="utf-8"))


def upgrade() -> None:
    run_sql("0003_function_search_path_up.sql")


def downgrade() -> None:
    run_sql("0003_function_search_path_down.sql")
