"""Tables of the Slack module: slack_thread, slack_delivery, slack_digest_item (approved 23 Nov 2026).

Revision ID: s0001
Revises:
Create Date: 2026-11-23
"""

from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "s0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SQL = Path(__file__).resolve().parent.parent / "sql"


def run_sql(name: str) -> None:
    # Sent to psycopg without parameters, so the SQL reaches the server as written.
    cursor = op.get_bind().connection.driver_connection.cursor()  # type: ignore[union-attr]
    cursor.execute((SQL / name).read_text(encoding="utf-8"))


def upgrade() -> None:
    run_sql("0001_slack_tables_up.sql")


def downgrade() -> None:
    run_sql("0001_slack_tables_down.sql")
