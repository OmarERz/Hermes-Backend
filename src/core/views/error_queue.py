"""Error queue for the front (FRO-18, HI-9, D-088): what failed and waits for a person, read from three places.

- `notification`: notification events that exhausted their retries (`notification_event.status = 'failed'`); an admin
  retries one with `POST /api/notifications/events/{id}/retry`.
- `itop`: iTop writes of the outbox that exhausted their retries (`itop_outbox.status = 'failed'`).
- `llm_validation`: items an analyst or the judge could not process and that no run retries any more (PRE-01): given
  up, or pending with no next attempt. An item the next runs still retry stays out; the CVE of a judge item comes
  from its review package.

Read only: nothing here retries or changes a row. The stored error is the writer's own short text (never a payload or
a secret); it is cut to `MAX_ERROR` characters all the same.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from sqlalchemy import text
from sqlalchemy.orm import Session

ErrorKey = tuple[datetime, uuid.UUID]  # (created_at, id): newest first
KINDS: Final = ("notification", "itop", "llm_validation")
MAX_ERROR: Final = 500

_PAGE: Final = text(
    """
    SELECT x.* FROM (
      SELECT e.id, 'notification' AS kind, e.created_at, e.status, e.attempts, e.next_attempt_at,
             e.last_error AS error, e.event_type AS component, g.cve_id AS cve, tk.itop_ticket_id, tk.itop_ref,
             e.assessment_id
        FROM notification_event e
        LEFT JOIN ticket tk ON tk.id = e.ticket_id
        LEFT JOIN finding_group g ON g.id = tk.finding_group_id
       WHERE e.status = 'failed'
      UNION ALL
      SELECT o.id, 'itop', o.created_at, o.status, o.attempts, o.next_attempt_at, o.last_error, o.operation,
             g.cve_id, tk.itop_ticket_id, tk.itop_ref, u.assessment_id
        FROM itop_outbox o
        JOIN ticket_update u ON u.id = o.ticket_update_id
        JOIN ticket tk ON tk.id = u.ticket_id
        JOIN finding_group g ON g.id = tk.finding_group_id
       WHERE o.status = 'failed'
      UNION ALL
      SELECT q.id, 'llm_validation', q.created_at, q.status, q.attempts,
             CASE WHEN q.status = 'pending' THEN q.next_attempt_at END, q.reason, q.component,
             COALESCE(q.cve_id, pg.cve_id), NULL, NULL, NULL
        FROM error_queue q
        LEFT JOIN review_package p ON p.id = q.review_package_id
        LEFT JOIN finding_group pg ON pg.id = p.finding_group_id
       WHERE q.status = 'gave_up' OR (q.status = 'pending' AND q.next_attempt_at IS NULL)
    ) x
     WHERE (CAST(:kind AS text) IS NULL OR x.kind = CAST(:kind AS text))
       AND (CAST(:after_at AS timestamptz) IS NULL
            OR (x.created_at, x.id) < (CAST(:after_at AS timestamptz), CAST(:after_id AS uuid)))
     ORDER BY x.created_at DESC, x.id DESC
     LIMIT :limit
    """
)


@dataclass(frozen=True)
class ErrorItem:
    id: uuid.UUID
    kind: str
    created_at: datetime
    status: str
    attempts: int
    next_attempt_at: datetime | None
    error: str | None
    component: str
    cve: str | None
    ticket_itop_id: str | None
    ticket_ref: str | None
    assessment_id: uuid.UUID | None

    @property
    def retryable(self) -> bool:
        """Only a notification event has a retry route today."""
        return self.kind == "notification"


def list_errors(
    session: Session, kind: str | None, *, after: ErrorKey | None, limit: int
) -> tuple[list[ErrorItem], ErrorKey | None]:
    """The failed items of every kind (or of one), newest first; the second value keys the next page."""
    rows = session.execute(
        _PAGE,
        {
            "kind": kind,
            "after_at": after[0] if after else None,
            "after_id": after[1] if after else None,
            "limit": limit + 1,
        },
    ).all()
    kept = rows[:limit]
    found = [
        ErrorItem(
            id=row.id,
            kind=row.kind,
            created_at=row.created_at,
            status=row.status,
            attempts=int(row.attempts),
            next_attempt_at=row.next_attempt_at,
            error=None if row.error is None else row.error[:MAX_ERROR],
            component=row.component,
            cve=row.cve,
            ticket_itop_id=row.itop_ticket_id,
            ticket_ref=row.itop_ref,
            assessment_id=row.assessment_id,
        )
        for row in kept
    ]
    next_key = (kept[-1].created_at, kept[-1].id) if len(rows) > limit else None
    return found, next_key
