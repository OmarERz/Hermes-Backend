"""Notification events for the admin screen (NOT-02): the real `notification_event` outbox, listed and retried.

The API says `error` where the table says `failed` (the frontend contract of docs/13). A retry puts a failed event
back in the queue with a fresh attempt budget; the dispatcher delivers it on its next pass.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Final, Literal, Protocol

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from api.errors import ApiError
from api.routes.models import NotificationEventRow
from core.db import models as m

ApiStatus = Literal["pending", "delivered", "error"]
TO_DB: Final[dict[str, str]] = {"pending": "pending", "delivered": "delivered", "error": "failed"}
TO_API: Final[dict[str, ApiStatus]] = {"pending": "pending", "delivered": "delivered", "failed": "error"}
PRIORITIES: Final[dict[str, Literal["immediate", "normal", "digest"]]] = {
    "immediate": "immediate",
    "normal": "normal",
    "digest": "digest",
}
LIST_LIMIT: Final = 500


class EventQueue(Protocol):
    def list(self, status: ApiStatus) -> list[NotificationEventRow]: ...

    def retry(self, event_id: str) -> NotificationEventRow: ...


def _row(event: m.NotificationEvent) -> NotificationEventRow:
    return NotificationEventRow(
        id=str(event.id),
        type=event.event_type,
        priority=PRIORITIES[event.priority],
        status=TO_API[event.status],
        attempts=event.attempts,
        last_error=event.last_error,
        created_at=event.created_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
    )


@dataclass
class SqlEventQueue:
    session_factory: sessionmaker[Session]
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def list(self, status: ApiStatus) -> list[NotificationEventRow]:
        """The newest events with that status (at most `LIST_LIMIT`)."""
        with self.session_factory() as session:
            rows = session.scalars(
                select(m.NotificationEvent)
                .where(m.NotificationEvent.status == TO_DB[status])
                .order_by(m.NotificationEvent.created_at.desc(), m.NotificationEvent.id.desc())
                .limit(LIST_LIMIT)
            ).all()
            return [_row(row) for row in rows]

    def retry(self, event_id: str) -> NotificationEventRow:
        try:
            key = uuid.UUID(event_id)
        except ValueError:
            raise ApiError(404, "not_found", "El evento no existe.") from None
        with self.session_factory() as session, session.begin():
            event = session.get(m.NotificationEvent, key, with_for_update=True)
            if event is None:
                raise ApiError(404, "not_found", "El evento no existe.")
            if event.status != "failed":
                raise ApiError(409, "not_in_error", "Solo se pueden reintentar eventos en error.")
            event.status, event.attempts, event.last_error = "pending", 0, None
            event.next_attempt_at = self.clock()
            return _row(event)


def get_event_queue(request: Request) -> EventQueue:
    return SqlEventQueue(request.app.state.session_factory)


Events = Annotated[EventQueue, Depends(get_event_queue)]
