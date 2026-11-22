"""Error queue (PRE-01, PRE-02): what failed after its retries waits here with the rule that failed.

An item is retried in the next 2 runs; after that it stays `pending` without a next attempt, which is how the front
lists it as a pending item. A second failure for the same item updates its row instead of adding another one
(idempotency): a retry never duplicates work.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id

COMPONENTS = ("news_analyst", "cve_analyst", "judge")
AUTOMATIC_ATTEMPTS = 3  # the original failure plus the 2 following runs


@dataclass(frozen=True)
class QueueRef:
    """Exactly one of the three references of an `error_queue` row."""

    component: str
    story_id: uuid.UUID | None = None
    cve_id: str | None = None
    review_package_id: uuid.UUID | None = None

    def validate(self) -> None:
        if self.component not in COMPONENTS:
            raise ValueError("Unknown component")
        if sum(ref is not None for ref in (self.story_id, self.cve_id, self.review_package_id)) != 1:
            raise ValueError("An error queue item needs exactly one reference")


def _find(session: Session, ref: QueueRef) -> m.ErrorQueue | None:
    stmt = select(m.ErrorQueue).where(m.ErrorQueue.component == ref.component, m.ErrorQueue.status == "pending")
    stmt = stmt.where(
        m.ErrorQueue.story_id == ref.story_id if ref.story_id is not None else m.ErrorQueue.story_id.is_(None),
        m.ErrorQueue.cve_id == ref.cve_id if ref.cve_id is not None else m.ErrorQueue.cve_id.is_(None),
        m.ErrorQueue.review_package_id == ref.review_package_id
        if ref.review_package_id is not None
        else m.ErrorQueue.review_package_id.is_(None),
    )
    return session.scalars(stmt.limit(1)).first()


def enqueue_failure(session: Session, ref: QueueRef, reason: str, now: datetime) -> m.ErrorQueue:
    """Record a failure: a new pending row, or one more attempt on the pending row of the same item."""
    ref.validate()
    # Serialize the check and the insert per item: two runs failing on the same item share one pending row (PRE-02).
    key = f"{ref.component}:{ref.story_id}:{ref.cve_id}:{ref.review_package_id}"
    session.execute(select(func.pg_advisory_xact_lock(func.hashtextextended(key, 0))))
    row = _find(session, ref)
    if row is None:
        row = m.ErrorQueue(
            id=new_id(),
            component=ref.component,
            story_id=ref.story_id,
            cve_id=ref.cve_id,
            review_package_id=ref.review_package_id,
            reason=reason,
            attempts=1,
            next_attempt_at=now,
            status="pending",
            created_at=now,
        )
        session.add(row)
    else:
        row.attempts += 1
        row.reason = reason
        row.next_attempt_at = now if row.attempts < AUTOMATIC_ATTEMPTS else None
    session.flush()
    return row


def due_items(session: Session, now: datetime) -> list[m.ErrorQueue]:
    """Pending items that the next run should retry, oldest first."""
    stmt = (
        select(m.ErrorQueue)
        .where(
            m.ErrorQueue.status == "pending",
            m.ErrorQueue.next_attempt_at.is_not(None),
            m.ErrorQueue.next_attempt_at <= now,
        )
        .order_by(m.ErrorQueue.created_at, m.ErrorQueue.id)
    )
    return list(session.scalars(stmt))


def needs_attention(session: Session) -> list[m.ErrorQueue]:
    """Pending items that ran out of automatic retries: the front shows them (PRE-01)."""
    stmt = (
        select(m.ErrorQueue)
        .where(m.ErrorQueue.status == "pending", m.ErrorQueue.next_attempt_at.is_(None))
        .order_by(m.ErrorQueue.created_at, m.ErrorQueue.id)
    )
    return list(session.scalars(stmt))


def resolve(session: Session, row: m.ErrorQueue) -> None:
    row.status = "resolved"
    row.next_attempt_at = None
    session.flush()


def give_up(session: Session, row: m.ErrorQueue) -> None:
    row.status = "gave_up"
    row.next_attempt_at = None
    session.flush()
