"""Recalculation requests (FRO-08, D-033): saving or restoring a formula queues one `recalculation` run that the
worker picks up. Only models are imported here, so the configuration service can queue without the scoring engine."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from core.db import models as m


def queue_recalculation(
    session: Session, now: datetime, formula_version_id: uuid.UUID, triggered_by: uuid.UUID | None = None
) -> m.Run:
    """A `queued` recalculation run for the formula version the save just created (D-061).

    Every save queues its own request (never a shared one), so a worker that already took an older request cannot
    swallow it: the pass of the new request starts after the save commits and reads the formula it saved. Passes
    over unchanged groups store nothing. Flushes; the caller commits.
    """
    run = m.Run(
        kind="recalculation",
        status="queued",
        progress=0,
        trigger_reason="formula_change",
        triggered_by=triggered_by,
        formula_version_id=formula_version_id,
        started_at=now,
    )
    session.add(run)
    session.flush()
    return run


def requeue_abandoned_recalculations(session: Session) -> int:
    """Put back the requests a dead worker left `running`. Only call it holding the pipeline lock: a queued request
    runs under that lock, so a `running` one cannot belong to a live process. A pass is idempotent, so redoing it
    is safe."""
    rows = session.scalars(
        update(m.Run)
        .where(m.Run.kind == "recalculation", m.Run.status == "running")
        .values(status="queued", progress=0)
        .returning(m.Run.id)
    )
    return len(rows.all())


def next_queued_recalculation(session: Session) -> uuid.UUID | None:
    """The oldest recalculation request still waiting."""
    return session.scalar(
        select(m.Run.id)
        .where(m.Run.kind == "recalculation", m.Run.status == "queued")
        .order_by(m.Run.started_at, m.Run.id)
        .limit(1)
    )


def claim_recalculation(session: Session, run_id: uuid.UUID, now: datetime) -> bool:
    """Move a queued request to `running`; False when someone else already took it."""
    claimed = session.scalar(
        update(m.Run)
        .where(m.Run.id == run_id, m.Run.kind == "recalculation", m.Run.status == "queued")
        .values(status="running", started_at=now)
        .returning(m.Run.id)
    )
    return claimed is not None


def has_running_recalculation(session: Session) -> bool:
    return (
        session.scalar(select(m.Run.id).where(m.Run.kind == "recalculation", m.Run.status == "running").limit(1))
        is not None
    )
