"""Tickets (D-036, TIC-03) and threat alerts (mode 2, R2/R3) as the front lists them."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.notifications.events import ticket_url

TicketKey = tuple[int, datetime, uuid.UUID]  # (urgency, created_at, id): most urgent first, then newest
AlertKey = tuple[datetime, uuid.UUID]  # (created_at, id): newest first
LEAST_URGENT: Final = 4
TICKET_STATUS: Final = {"open": "Abierto", "resolved": "Resuelto", "closed": "Cerrado"}

# Tickets already in iTop. Urgency: the one iTop holds; before the first sync, the band of the ticket score in
# the formula of its latest assessment; with no score, the least urgent. A CI counts as fixed when none of its
# linked findings is current or the CI was decommissioned.
_TICKETS: Final = text(
    """
    WITH t AS (
      SELECT tk.id, tk.itop_ticket_id, COALESCE(tk.itop_ref, tk.itop_ticket_id) AS itop_id, g.cve_id AS cve,
             team.name AS custodian, tk.status, tk.created_at,
             COALESCE(tk.current_urgency, (
               SELECT b.urgency FROM ticket_score ts
                 JOIN assessment a ON a.id = ts.assessment_id
                 JOIN formula_urgency_band b ON b.formula_version_id = a.formula_version_id
                WHERE ts.ticket_id = tk.id AND ts.score >= b.min_score
                ORDER BY b.urgency LIMIT 1), 4)::integer AS urgency,
             (SELECT count(DISTINCT i.asset_id) FROM ticket_finding tf
                JOIN finding f ON f.id = tf.finding_id
                JOIN installed_software i ON i.id = f.installed_software_id
               WHERE tf.ticket_id = tk.id AND tf.removed_at IS NULL)::integer AS total_cis,
             (SELECT count(DISTINCT i.asset_id) FROM ticket_finding tf
                JOIN finding f ON f.id = tf.finding_id
                JOIN installed_software i ON i.id = f.installed_software_id
                JOIN asset ast ON ast.id = i.asset_id
               WHERE tf.ticket_id = tk.id AND tf.removed_at IS NULL
                 AND (ast.decommissioned_at IS NOT NULL OR NOT EXISTS (
                   SELECT 1 FROM ticket_finding tf2
                     JOIN finding f2 ON f2.id = tf2.finding_id
                     JOIN installed_software i2 ON i2.id = f2.installed_software_id
                     JOIN finding_current fc2 ON fc2.finding_id = f2.id AND fc2.status <> 'fixed'
                    WHERE tf2.ticket_id = tk.id AND tf2.removed_at IS NULL AND i2.asset_id = i.asset_id)))::integer
               AS fixed_cis
        FROM ticket tk
        JOIN finding_group g ON g.id = tk.finding_group_id
        JOIN team ON team.id = tk.custodian_team_id
       WHERE tk.itop_ticket_id IS NOT NULL
    )
    SELECT * FROM t
     WHERE (CAST(:urgency AS integer) IS NULL OR t.urgency = CAST(:urgency AS integer))
       AND (CAST(:after_urgency AS integer) IS NULL
            OR t.urgency > CAST(:after_urgency AS integer)
            OR (t.urgency = CAST(:after_urgency AS integer) AND (t.created_at, t.id)
                < (CAST(:after_at AS timestamptz), CAST(:after_id AS uuid))))
     ORDER BY t.urgency, t.created_at DESC, t.id DESC
     LIMIT :limit
    """
)

# Alerts of mode 2 and of R2/R3 packages, newest first. Actor, victim, vector and CI: the first one by name.
_ALERTS: Final = text(
    """
    SELECT al.id, al.created_at, al.relevance,
           (SELECT ac.name FROM news_analysis na JOIN news_actor_mention m ON m.analysis_id = na.id
              JOIN actor ac ON ac.id = m.actor_id WHERE na.story_id = al.story_id ORDER BY ac.name LIMIT 1) AS actor,
           (SELECT v.name FROM news_analysis na JOIN news_victim v ON v.analysis_id = na.id
             WHERE na.story_id = al.story_id ORDER BY v.name LIMIT 1) AS victim,
           (SELECT av.vector_code FROM news_analysis na JOIN news_attack_vector av ON av.analysis_id = na.id
             WHERE na.story_id = al.story_id ORDER BY av.vector_code LIMIT 1) AS vector,
           COALESCE((SELECT na.summary FROM news_analysis na WHERE na.story_id = al.story_id),
                    al.relationship_detail, '') AS summary,
           (SELECT ast.itop_ci_id FROM alert_asset aa JOIN asset ast ON ast.id = aa.asset_id
             WHERE aa.alert_id = al.id ORDER BY ast.itop_ci_id LIMIT 1) AS ci_id
      FROM alert al
     WHERE al.relevance IN ('R2', 'R3', 'inferred')
       AND (CAST(:after_at AS timestamptz) IS NULL
            OR (al.created_at, al.id) < (CAST(:after_at AS timestamptz), CAST(:after_id AS uuid)))
     ORDER BY al.created_at DESC, al.id DESC
     LIMIT :limit
    """
)


@dataclass(frozen=True)
class TicketRow:
    id: uuid.UUID
    itop_id: str  # the iTop reference (R-000123) once known, else the numeric id: what people read
    itop_ticket_id: str  # the numeric iTop id: what the `ticket_itop_id` filters and the feedback take
    url: str
    cve: str
    custodian: str
    urgency: int
    status: str
    created_at: datetime
    fixed_cis: int
    total_cis: int


@dataclass(frozen=True)
class AlertRow:
    id: uuid.UUID
    created_at: datetime
    relevance: str
    inferred: bool
    actor: str | None
    victim: str | None
    vector: str | None
    summary: str
    ci_id: str | None


def list_tickets(
    session: Session, itop_base_url: str | None, *, urgency: int | None, after: TicketKey | None, limit: int
) -> tuple[list[TicketRow], TicketKey | None]:
    """Tickets already in iTop, most urgent first, then newest. The second value keys the next page."""
    rows = session.execute(
        _TICKETS,
        {
            "urgency": urgency,
            "after_urgency": after[0] if after else None,
            "after_at": after[1] if after else None,
            "after_id": after[2] if after else None,
            "limit": limit + 1,
        },
    ).all()
    tickets = [
        TicketRow(
            id=r.id,
            itop_id=r.itop_id,
            itop_ticket_id=r.itop_ticket_id,
            url=ticket_url(itop_base_url, r.itop_ticket_id),
            cve=r.cve,
            custodian=r.custodian,
            urgency=r.urgency,
            status=TICKET_STATUS.get(r.status, r.status),
            created_at=r.created_at,
            fixed_cis=r.fixed_cis,
            total_cis=r.total_cis,
        )
        for r in rows[:limit]
    ]
    last = tickets[-1] if tickets else None
    next_key = (last.urgency, last.created_at, last.id) if last is not None and len(rows) > limit else None
    return tickets, next_key


def list_alerts(session: Session, *, after: AlertKey | None, limit: int) -> tuple[list[AlertRow], AlertKey | None]:
    """R2, R3 and inferred alerts, newest first. The second value keys the next page."""
    rows = session.execute(
        _ALERTS,
        {"after_at": after[0] if after else None, "after_id": after[1] if after else None, "limit": limit + 1},
    ).all()
    alerts = [
        AlertRow(
            id=r.id,
            created_at=r.created_at,
            relevance=r.relevance,
            inferred=r.relevance == "inferred",
            actor=r.actor,
            victim=r.victim,
            vector=r.vector,
            summary=r.summary,
            ci_id=r.ci_id,
        )
        for r in rows[:limit]
    ]
    last = alerts[-1] if alerts else None
    next_key = (last.created_at, last.id) if last is not None and len(rows) > limit else None
    return alerts, next_key
