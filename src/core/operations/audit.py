"""The audit trail of the front (API-06 `GET /api/audit`): `audit_log`, newest first, with filters and a keyset."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from sqlalchemy import text
from sqlalchemy.orm import Session

SYSTEM_ACTOR: Final = "sistema"
AuditKey = tuple[datetime, uuid.UUID]  # (created_at, id) of the last row of a page

_PAGE: Final = text(
    """
    SELECT l.id, l.created_at, l."action", l.entity_type, l.entity_id, u.email::text AS email
      FROM audit_log l
      LEFT JOIN app_user u ON u.id = l.app_user_id
     WHERE (CAST(:actor AS text) IS NULL
            OR u.email = CAST(:actor AS citext) OR u.display_name = CAST(:actor AS text)
            OR (CAST(:actor AS text) = :system AND l.app_user_id IS NULL))
       AND (CAST(:action AS text) IS NULL OR l."action" = CAST(:action AS text))
       AND (CAST(:date_from AS timestamptz) IS NULL OR l.created_at >= CAST(:date_from AS timestamptz))
       AND (CAST(:date_to AS timestamptz) IS NULL OR l.created_at <= CAST(:date_to AS timestamptz))
       AND (CAST(:after_at AS timestamptz) IS NULL
            OR (l.created_at, l.id) < (CAST(:after_at AS timestamptz), CAST(:after_id AS uuid)))
     ORDER BY l.created_at DESC, l.id DESC
     LIMIT :limit
    """
)


@dataclass(frozen=True)
class AuditFilters:
    actor: str | None = None  # e-mail or display name; "sistema" for changes without a user
    action: str | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None


@dataclass(frozen=True)
class AuditRow:
    id: uuid.UUID
    created_at: datetime
    actor: str
    action: str
    target: str


def list_audit(
    session: Session, filters: AuditFilters, *, after: AuditKey | None, limit: int
) -> tuple[list[AuditRow], AuditKey | None]:
    """A page of the audit trail and the key of the next one. Never returns the before/after values."""
    rows = session.execute(
        _PAGE,
        {
            "actor": filters.actor,
            "system": SYSTEM_ACTOR,
            "action": filters.action,
            "date_from": filters.date_from,
            "date_to": filters.date_to,
            "after_at": after[0] if after else None,
            "after_id": after[1] if after else None,
            "limit": limit + 1,
        },
    ).all()
    page = [
        AuditRow(
            id=r.id,
            created_at=r.created_at,
            actor=r.email or SYSTEM_ACTOR,
            action=r.action,
            target=f"{r.entity_type}:{r.entity_id}",
        )
        for r in rows[:limit]
    ]
    next_key = (page[-1].created_at, page[-1].id) if len(rows) > limit else None
    return page, next_key
