"""Ticket summary and log for the front (D-088, IN-3, AG-13, AG-15, AG-16, HI-4), read from `ticket` and its log.

The statuses are the ones Hermes keeps in step with iTop (`TicketStateSync`): waiting to be created, open, resolved
and closed. "Changed by a person" counts the tickets whose urgency someone changed in iTop (D-007). The resolution
time runs from the ticket's creation in iTop to its resolution (MET-23).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from decimal import ROUND_HALF_UP, Decimal
from typing import Final

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.notifications.events import ticket_url

UpdateKey = tuple[datetime, uuid.UUID]  # (created_at, id): newest first
STATUSES: Final = ("pending_creation", "open", "resolved", "closed")
ACTION_LABELS: Final = {
    "create": "Ticket creado",
    "add_ci": "CI agregado",
    "add_owner": "Dueño agregado",
    "comment": "Comentario",
    "raise_urgency": "Urgencia subida",
    "lower_urgency": "Urgencia bajada",
    "suggest": "Sugerencia de urgencia",
    "partial_fix": "Corrección parcial",
    "fix_comment": "Corrección verificada",
    "reopen": "Reabierto",
}

# Same urgency as the ticket list: the one iTop holds; before the first sync, the band of the ticket score.
_SUMMARY: Final = text(
    """
    SELECT tk.status, tk.last_human_change_at IS NOT NULL AS human,
           CASE WHEN tk.itop_ticket_id IS NULL THEN NULL ELSE COALESCE(tk.current_urgency, (
             SELECT b.urgency FROM ticket_score ts
               JOIN assessment a ON a.id = ts.assessment_id
               JOIN formula_urgency_band b ON b.formula_version_id = a.formula_version_id
              WHERE ts.ticket_id = tk.id AND ts.score >= b.min_score
              ORDER BY b.urgency LIMIT 1), 4) END::integer AS urgency,
           CASE WHEN tk.resolved_at IS NOT NULL
                THEN extract(epoch FROM tk.resolved_at - COALESCE(tk.itop_created_at, tk.created_at)) END
             AS resolution_seconds
      FROM ticket tk
    """
)
_LOG: Final = text(
    """
    SELECT u.id, u.created_at, u.action, u.assessment_id, tk.itop_ticket_id, tk.itop_ref, g.cve_id AS cve,
           team.name AS custodian, o.status AS itop_status
      FROM ticket_update u
      JOIN ticket tk ON tk.id = u.ticket_id
      JOIN finding_group g ON g.id = tk.finding_group_id
      JOIN team ON team.id = tk.custodian_team_id
      LEFT JOIN itop_outbox o ON o.ticket_update_id = u.id
     WHERE (CAST(:ticket AS text) IS NULL OR tk.itop_ticket_id = CAST(:ticket AS text))
       AND (CAST(:action AS text) IS NULL OR u.action = CAST(:action AS text))
       AND (CAST(:after_at AS timestamptz) IS NULL
            OR (u.created_at, u.id) < (CAST(:after_at AS timestamptz), CAST(:after_id AS uuid)))
     ORDER BY u.created_at DESC, u.id DESC
     LIMIT :limit
    """
)


@dataclass(frozen=True)
class Summary:
    total: int
    by_status: dict[str, int]
    by_urgency: dict[str, int]
    changed_by_person: int
    resolved: int
    resolved_percent: str | None
    avg_resolution_hours: str | None


@dataclass(frozen=True)
class Update:
    id: uuid.UUID
    created_at: datetime
    action: str
    label: str
    assessment_id: uuid.UUID | None
    ticket_itop_id: str | None
    ticket_ref: str | None
    ticket_url: str | None
    cve: str
    custodian: str
    itop_status: str | None


def _one_decimal(value: Decimal) -> str:
    return str(value.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def summary(session: Session) -> Summary:
    """Every ticket by status; urgency, resolved share and resolution time over the tickets already in iTop."""
    rows = session.execute(_SUMMARY).all()
    by_status = dict.fromkeys(STATUSES, 0)
    by_urgency = {str(u): 0 for u in range(1, 5)}
    seconds: list[Decimal] = []
    for row in rows:
        by_status[row.status] = by_status.get(row.status, 0) + 1
        if row.urgency is not None:
            by_urgency[str(row.urgency)] = by_urgency.get(str(row.urgency), 0) + 1
        if row.resolution_seconds is not None:
            seconds.append(max(Decimal(0), Decimal(str(row.resolution_seconds))))
    in_itop = len(rows) - by_status["pending_creation"]
    resolved = by_status["resolved"] + by_status["closed"]
    average = sum(seconds, Decimal(0)) / len(seconds) / 3600 if seconds else None
    return Summary(
        total=len(rows),
        by_status=by_status,
        by_urgency=by_urgency,
        changed_by_person=sum(1 for row in rows if row.human),
        resolved=resolved,
        resolved_percent=_one_decimal(Decimal(resolved) * 100 / in_itop) if in_itop else None,
        avg_resolution_hours=_one_decimal(average) if average is not None else None,
    )


@dataclass(frozen=True)
class UpdateQuery:
    ticket: str | None = None  # iTop ticket id
    action: str | None = None


def updates(
    session: Session, itop_base_url: str | None, query: UpdateQuery, *, after: UpdateKey | None, limit: int
) -> tuple[list[Update], UpdateKey | None]:
    """The log of what Hermes did in each ticket and why, newest first; the second value keys the next page."""
    rows = session.execute(
        _LOG,
        {
            "ticket": query.ticket,
            "action": query.action,
            "after_at": after[0] if after else None,
            "after_id": after[1] if after else None,
            "limit": limit + 1,
        },
    ).all()
    kept = rows[:limit]
    found = [
        Update(
            id=row.id,
            created_at=row.created_at,
            action=row.action,
            label=ACTION_LABELS.get(row.action, row.action),
            assessment_id=row.assessment_id,
            ticket_itop_id=row.itop_ticket_id,
            ticket_ref=row.itop_ref,
            ticket_url=ticket_url(itop_base_url, row.itop_ticket_id) or None,
            cve=row.cve,
            custodian=row.custodian,
            itop_status=row.itop_status,
        )
        for row in kept
    ]
    next_key = (kept[-1].created_at, kept[-1].id) if len(rows) > limit else None
    return found, next_key
