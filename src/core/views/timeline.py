"""History timeline for the front (D-088, HI-1 to HI-10): runs, LLM reviews and configuration changes in one list.

Readers see the configuration versions (who and what, as in `GET /api/config/versions`), never the full audit trail,
which stays admin only (`GET /api/audit`). A review event carries the assessment it fed, so the front can link the
feedback people gave on it (HI-8).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.views.telemetry import RUN_KINDS

EventKey = tuple[datetime, uuid.UUID]  # (at, id): newest first
RUN_TITLES: Final = {
    "scan": "Escaneo simulado",
    "news": "Ingesta de noticias",
    "recalculation": "Recálculo por cambio de fórmula",
    "nightly": "Recálculo nocturno",
    "inventory_sync": "Sincronización del inventario",
    "mode4": "Calibración semanal",
}
AGENT_TITLES: Final = {
    "judge": "Revisión del juez",
    "news_analyst": "Análisis de noticia",
    "cve_analyst": "Análisis de CVE",
}
AGENT_NAMES: Final = {"judge": "Juez", "news_analyst": "Analista de noticias", "cve_analyst": "Analista de CVE"}
SYSTEM: Final = "sistema"

_EVENTS: Final = text(
    """
    WITH events AS (
      SELECT r.id, 'run' AS type, r.started_at AS at,
             CASE r.status WHEN 'cancelled' THEN 'failed' ELSE r.status END AS status,
             COALESCE(u.display_name, CASE WHEN r.triggered_by IS NOT NULL THEN 'Usuario sin nombre' END) AS actor,
             r.trigger_reason AS trigger, r.kind AS run_kind, NULL::text AS agent, NULL::uuid AS assessment_id,
             NULL::integer AS config_version, NULL::text AS summary,
             CASE WHEN r.finished_at IS NOT NULL
                  THEN greatest(0, round(extract(epoch FROM r.finished_at - r.started_at)))::integer END
               AS duration_seconds
        FROM run r LEFT JOIN app_user u ON u.id = r.triggered_by
       WHERE r.started_at IS NOT NULL
      UNION ALL
      SELECT v.id, 'llm_review', v.created_at, v.status, NULL, NULL, NULL, v.agent,
             (SELECT a.id FROM assessment a WHERE a.llm_review_id = COALESCE(v.second_review_of_id, v.id)
               ORDER BY a.assessed_at, a.id LIMIT 1),
             NULL, NULL, greatest(0, round(v.latency_ms / 1000.0))::integer
        FROM llm_review v
      UNION ALL
      SELECT l.id, 'config_change', l.created_at, 'applied', COALESCE(u.display_name, CASE WHEN l.app_user_id
             IS NOT NULL THEN 'Usuario sin nombre' END), NULL, NULL, NULL, NULL,
             CASE WHEN l.entity_id ~ '^[0-9]{1,9}$' THEN l.entity_id::integer END, l."after" ->> 'summary', NULL
        FROM audit_log l LEFT JOIN app_user u ON u.id = l.app_user_id
       WHERE l.entity_type = 'config'
    )
    SELECT * FROM events e
     WHERE (CAST(:type AS text) IS NULL OR e.type = CAST(:type AS text))
       AND (CAST(:status AS text) IS NULL OR e.status = CAST(:status AS text))
       AND (CAST(:date_from AS timestamptz) IS NULL OR e.at >= CAST(:date_from AS timestamptz))
       AND (CAST(:date_to AS timestamptz) IS NULL OR e.at <= CAST(:date_to AS timestamptz))
       AND (CAST(:after_at AS timestamptz) IS NULL
            OR (e.at, e.id) < (CAST(:after_at AS timestamptz), CAST(:after_id AS uuid)))
     ORDER BY e.at DESC, e.id DESC
     LIMIT :limit
    """
)


@dataclass(frozen=True)
class Query:
    type: str | None = None  # run · llm_review · config_change
    status: str | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None


@dataclass(frozen=True)
class Event:
    id: uuid.UUID
    type: str
    at: datetime
    title: str
    status: str
    actor: str
    trigger: str | None
    run_kind: str | None
    agent: str | None
    assessment_id: uuid.UUID | None
    config_version: int | None
    duration_seconds: int | None


def _title(row: Any) -> str:
    if row.run_kind is not None:
        return RUN_TITLES.get(row.run_kind, "Corrida")
    if row.agent is not None:
        return AGENT_TITLES.get(row.agent, "Revisión de IA")
    return str(row.summary or "Cambio de configuración")


def events(
    session: Session, query: Query, *, after: EventKey | None, limit: int
) -> tuple[list[Event], EventKey | None]:
    """Newest first; the second value keys the next page."""
    rows = session.execute(
        _EVENTS,
        {
            "type": query.type,
            "status": query.status,
            "date_from": query.date_from,
            "date_to": query.date_to,
            "after_at": after[0] if after else None,
            "after_id": after[1] if after else None,
            "limit": limit + 1,
        },
    ).all()
    kept = rows[:limit]
    found = [
        Event(
            id=row.id,
            type=row.type,
            at=row.at,
            title=_title(row),
            status=row.status,
            actor=row.actor or (AGENT_NAMES.get(row.agent, SYSTEM) if row.agent else SYSTEM),
            trigger=row.trigger,
            run_kind=RUN_KINDS.get(row.run_kind) if row.run_kind else None,
            agent=row.agent,
            assessment_id=row.assessment_id,
            config_version=row.config_version,
            duration_seconds=row.duration_seconds,
        )
        for row in kept
    ]
    next_key = (kept[-1].at, kept[-1].id) if len(rows) > limit else None
    return found, next_key
