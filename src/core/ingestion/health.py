"""Source health (FUE-R2, F-19, MET-22): alert when a source goes `source_health_hours` without data.

A source is down when it has no successful read inside the window (a source never read counts from its creation),
or when its latest read found a changed format. The alert is a row in `audit_log` (`source.down`) and a warning in
the log; the matching `source.recovered` row closes it, so an outage alerts once and not on every run.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id
from core.ingestion.service import Clock, news_sources, utc_now
from core.ingestion.settings import get_int

log = logging.getLogger("ingestion")

HEALTH_LOCK_KEY = 20_260_223  # transaction-level advisory lock held while a check writes its alerts
ALERT_DOWN = "source.down"
ALERT_RECOVERED = "source.recovered"


@dataclass(frozen=True)
class HealthAlert:
    source_code: str
    reason: str  # no_data | format_changed
    last_ok_at: datetime | None


def monitored_sources(session: Session) -> list[m.Source]:
    """Enabled sources the pipeline reads, plus any enabled source that has been read at least once."""
    ids = {source.id for source in news_sources(session)}
    ids |= set(session.scalars(select(m.SourceFetch.source_id).distinct()))
    sources = session.scalars(select(m.Source).where(m.Source.enabled.is_(True), m.Source.id.in_(ids)))
    return sorted(sources, key=lambda s: s.code)


def _problem(session: Session, source: m.Source, now: datetime, hours: int) -> tuple[str, datetime | None] | None:
    row = session.execute(text("SELECT last_ok_at FROM source_health WHERE source_id = :id"), {"id": source.id}).first()
    last_ok = row[0] if row else None
    latest = session.scalar(
        select(m.SourceFetch.status)
        .where(m.SourceFetch.source_id == source.id)
        .order_by(m.SourceFetch.started_at.desc(), m.SourceFetch.id.desc())
        .limit(1)
    )
    if latest == "format_changed":
        return "format_changed", last_ok
    if now - (last_ok or source.created_at) > timedelta(hours=hours):
        return "no_data", last_ok
    return None


def _open_alert(session: Session, source_id: uuid.UUID) -> bool:
    last = session.scalar(
        select(m.AuditLog.action)
        .where(
            m.AuditLog.entity_type == "source",
            m.AuditLog.entity_id == str(source_id),
            m.AuditLog.action.in_((ALERT_DOWN, ALERT_RECOVERED)),
        )
        .order_by(m.AuditLog.created_at.desc(), m.AuditLog.id.desc())
        .limit(1)
    )
    return last == ALERT_DOWN


def _record(session: Session, source: m.Source, action: str, now: datetime, detail: dict[str, object]) -> None:
    session.add(
        m.AuditLog(
            id=new_id(),
            action=action,
            entity_type="source",
            entity_id=str(source.id),
            after={"code": source.code, **detail},
            created_at=now,
        )
    )


def check_source_health(session: Session, clock: Clock = utc_now, hours: int | None = None) -> list[HealthAlert]:
    """New alerts of this check (an outage already alerted is not repeated); commits."""
    # One check at a time: two runs could both see "no open alert" and record the same outage twice.
    session.execute(select(func.pg_advisory_xact_lock(HEALTH_LOCK_KEY)))
    now = clock()
    window = hours if hours is not None else get_int(session, "source_health_hours")
    alerts: list[HealthAlert] = []
    for source in monitored_sources(session):
        problem = _problem(session, source, now, window)
        is_open = _open_alert(session, source.id)
        if problem is None:
            if is_open:
                _record(session, source, ALERT_RECOVERED, now, {})
                log.info("source %s recovered", source.code)
            continue
        reason, last_ok = problem
        if is_open:
            continue
        alert = HealthAlert(source_code=source.code, reason=reason, last_ok_at=last_ok)
        _record(
            session,
            source,
            ALERT_DOWN,
            now,
            {"reason": reason, "last_ok_at": last_ok.isoformat() if last_ok else None, "hours": window},
        )
        log.warning("source %s is down: %s", source.code, reason)
        alerts.append(alert)
    session.commit()
    return alerts
