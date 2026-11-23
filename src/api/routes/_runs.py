"""Runs for the API (ARQ-04, ARQ-05, FRO-19): scan requests, the run list and the progress stream, over `run`.

`POST /api/scans` leaves a `queued` scan run that the worker picks up and runs on that same row; the run list and
the server-sent events read the `run` table, so the frontend follows the real progress of scans, news runs and
recalculations.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Final, Literal, Protocol

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from api.errors import ApiError
from api.routes.models import Run
from core.db import models as m
from core.scan.engine import queue_scan

ApiKind = Literal["scan", "ingestion", "recalculation", "nightly"]
ApiStatus = Literal["queued", "running", "succeeded", "failed"]
KINDS: Final[dict[str, ApiKind]] = {
    "scan": "scan",
    "news": "ingestion",
    "recalculation": "recalculation",
    "nightly": "nightly",
}
STATUSES: Final[dict[str, ApiStatus]] = {
    "queued": "queued",
    "running": "running",
    "succeeded": "succeeded",
    "failed": "failed",
    "cancelled": "failed",
}
TERMINAL: Final = frozenset({"succeeded", "failed"})
LIST_LIMIT: Final = 500


class RunSource(Protocol):
    def list(self) -> list[Run]: ...

    def queue_scan(self, firebase_uid: str | None) -> Run: ...

    def progress(self, run_id: str) -> Iterator[Run]:
        """Snapshots of the run until it ends; raises ApiError 404 when it does not exist."""
        ...


def _iso(moment: datetime | None) -> str | None:
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z") if moment is not None else None


def to_api(run: m.Run) -> Run:
    return Run(
        id=str(run.id),
        kind=KINDS[run.kind],
        status=STATUSES[run.status],
        started_at=_iso(run.started_at) or "",
        finished_at=_iso(run.finished_at),
        progress=run.progress,
    )


@dataclass
class SqlRunSource:
    session_factory: sessionmaker[Session]
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    poll_seconds: float = 1.0
    max_polls: int = 900  # a stream ends after ~15 minutes; the frontend reconnects
    sleep: Callable[[float], None] = time.sleep

    def list(self) -> list[Run]:
        with self.session_factory() as session:
            rows = session.scalars(
                select(m.Run)
                .where(m.Run.kind.in_(KINDS))
                .order_by(m.Run.started_at.desc().nulls_first(), m.Run.id.desc())
                .limit(LIST_LIMIT)
            ).all()
            return [to_api(row) for row in rows]

    def queue_scan(self, firebase_uid: str | None) -> Run:
        with self.session_factory() as session, session.begin():
            user_id = (
                session.scalar(select(m.AppUser.id).where(m.AppUser.firebase_uid == firebase_uid))
                if firebase_uid
                else None
            )
            return to_api(queue_scan(session, self.clock(), user_id))

    def _read(self, key: uuid.UUID) -> Run | None:
        with self.session_factory() as session:
            row = session.get(m.Run, key)
            return to_api(row) if row is not None and row.kind in KINDS else None

    def progress(self, run_id: str) -> Iterator[Run]:
        try:
            key = uuid.UUID(run_id)
        except ValueError:
            raise ApiError(404, "not_found", "La corrida no existe.") from None
        first = self._read(key)
        if first is None:
            raise ApiError(404, "not_found", "La corrida no existe.")
        return self._follow(key, first)

    def _follow(self, key: uuid.UUID, first: Run) -> Iterator[Run]:
        current: Run | None = first
        last: tuple[str, int] | None = None
        for _ in range(self.max_polls):
            if current is None:
                return
            if (current.status, current.progress) != last:
                last = (current.status, current.progress)
                yield current
            if current.status in TERMINAL:
                return
            self.sleep(self.poll_seconds)
            current = self._read(key)


def get_run_source(request: Request) -> RunSource:
    return SqlRunSource(request.app.state.session_factory)


Runs = Annotated[RunSource, Depends(get_run_source)]
