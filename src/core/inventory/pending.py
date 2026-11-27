"""Inventory items waiting for a person (ESC-03c, ESC-07, FRO-17), read from the `inventory_issue` view."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import text
from sqlalchemy.orm import Session

ISSUES: Final = ("software_unmapped", "exposure_unknown", "unclassified", "owner_missing", "custodian_missing")
MAX_PAGE: Final = 200

# The last column is how many items match, computed before LIMIT in the same statement (one snapshot): a list and
# its total never contradict each other, even while an analyst maps a CPE or a sync adds a CI (F18.6).
_ROWS = text(
    "SELECT i.issue, i.asset_id, a.itop_ci_id, a.name, a.itop_class, i.software_product_id, p.itop_name, "
    "(SELECT count(*) FROM installed_software s WHERE s.software_product_id = p.id AND s.removed_at IS NULL), "
    "count(*) OVER () "
    "FROM inventory_issue i "
    "LEFT JOIN asset a ON a.id = i.asset_id "
    "LEFT JOIN software_product p ON p.id = i.software_product_id "
    "WHERE (CAST(:issue AS text) IS NULL OR i.issue = CAST(:issue AS text)) "
    "ORDER BY i.issue, COALESCE(a.name, p.itop_name), i.asset_id, i.software_product_id "
    "LIMIT :limit OFFSET :offset"
)
_COUNTS = text("SELECT issue, count(*) FROM inventory_issue GROUP BY issue")


@dataclass(frozen=True)
class PendingItem:
    issue: str
    asset_id: uuid.UUID | None
    asset_itop_id: str | None
    asset_name: str | None
    asset_class: str | None
    software_product_id: uuid.UUID | None
    software_name: str | None
    installations: int | None  # live installations of an unmapped product


def _rows(session: Session, issue: str | None, limit: int, offset: int) -> list[Any]:
    if issue is not None and issue not in ISSUES:
        raise ValueError("unknown issue")
    if not 1 <= limit <= MAX_PAGE or offset < 0:
        raise ValueError("limit must be 1 to 200 and offset not negative")
    return list(session.execute(_ROWS, {"issue": issue, "limit": limit, "offset": offset}))


def list_pending(session: Session, issue: str | None = None, *, limit: int = 50, offset: int = 0) -> list[PendingItem]:
    return [PendingItem(*row[:-1]) for row in _rows(session, issue, limit, offset)]


def first_pending(session: Session, issue: str, *, limit: int = MAX_PAGE) -> tuple[list[PendingItem], int]:
    """The first `limit` items of one type and how many of that type there are, both read by one statement."""
    rows = _rows(session, issue, limit, 0)
    return [PendingItem(*row[:-1]) for row in rows], int(rows[0][-1]) if rows else 0


def count_pending(session: Session) -> dict[str, int]:
    """Items per issue type, with zero for the types that have none."""
    counts = dict.fromkeys(ISSUES, 0)
    counts.update({issue: int(n) for issue, n in session.execute(_COUNTS)})
    return counts
