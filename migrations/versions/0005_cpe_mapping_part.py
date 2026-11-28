"""CPE part of the NVD pair and CNA name CHECKs on cpe_mapping (F15.9, D-107).

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-27
"""

from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SQL = Path(__file__).resolve().parent.parent / "sql"


def run_sql(name: str) -> None:
    # Sent to psycopg without parameters, so the SQL reaches the server as written.
    cursor = op.get_bind().connection.driver_connection.cursor()  # type: ignore[union-attr]
    cursor.execute((SQL / name).read_text(encoding="utf-8"))


def upgrade() -> None:
    run_sql("0005_cpe_mapping_part_up.sql")


def downgrade() -> None:
    run_sql("0005_cpe_mapping_part_down.sql")
