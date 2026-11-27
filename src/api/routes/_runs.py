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
from sqlalchemy import case, func, select, tuple_
from sqlalchemy.orm import Session, sessionmaker

from api.errors import ApiError
from api.routes.models import Run, RunFilters, parse_moment
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


# (null start: 1 or 0, start or the epoch, id) of the last run of a page: runs not started yet come first, then the
# newest; the id breaks ties. Paged in SQL, so the list is never cut at a fixed size (pending F13.0 #79).
RunKey = tuple[int, datetime, str]
EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)


class RunSource(Protocol):
    def page(
        self, after: RunKey | None, limit: int, filters: RunFilters | None = None
    ) -> tuple[list[Run], RunKey | None]: ...

    def queue_scan(self, firebase_uid: str | None) -> Run: ...

    def progress(self, run_id: str) -> Iterator[Run]:
        """Snapshots of the run until it ends; raises ApiError 404 when it does not exist."""
        ...


def _iso(moment: datetime | None) -> str | None:
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z") if moment is not None else None


TRIGGERS: Final[dict[str, Literal["schedule", "manual", "after_scan", "formula_change"]]] = {
    "schedule": "schedule",
    "manual": "manual",
    "after_scan": "after_scan",
    "formula_change": "formula_change",
}
API_TO_DB_KINDS: Final = {api: db for db, api in KINDS.items()}
UNNAMED: Final = "Usuario sin nombre"


def to_api(run: m.Run, launched_by: str | None = None) -> Run:
    return Run(
        id=str(run.id),
        kind=KINDS[run.kind],
        status=STATUSES[run.status],
        started_at=_iso(run.started_at) or "",
        finished_at=_iso(run.finished_at),
        progress=run.progress,
        trigger_reason=TRIGGERS.get(run.trigger_reason),
        triggered_by=launched_by,
    )


def _launcher(run: m.Run, name: str | None) -> str | None:
    """Who launched the run (HI-10): their display name, a generic label without one, None for the scheduler."""
    if run.triggered_by is None:
        return None
    return name or UNNAMED


def _with_launcher(session: Session, run: m.Run) -> Run:
    """One run for the API with who launched it, as the list shows it (HI-10)."""
    if run.triggered_by is None:
        return to_api(run)
    name = session.scalar(select(m.AppUser.display_name).where(m.AppUser.id == run.triggered_by))
    return to_api(run, _launcher(run, name))


@dataclass
class SqlRunSource:
    session_factory: sessionmaker[Session]
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    poll_seconds: float = 1.0
    max_polls: int = 900  # a stream ends after ~15 minutes; the frontend reconnects
    sleep: Callable[[float], None] = time.sleep

    def page(
        self, after: RunKey | None, limit: int, filters: RunFilters | None = None
    ) -> tuple[list[Run], RunKey | None]:
        unstarted = case((m.Run.started_at.is_(None), 1), else_=0)
        started = func.coalesce(m.Run.started_at, EPOCH)
        query = (
            select(m.Run, unstarted, started, m.AppUser.display_name)
            .outerjoin(m.AppUser, m.AppUser.id == m.Run.triggered_by)
            .where(m.Run.kind.in_(KINDS))
        )
        if filters is not None:
            if filters.kind is not None:
                query = query.where(m.Run.kind == API_TO_DB_KINDS[filters.kind])
            if filters.status is not None:  # the API says `failed` for cancelled runs too
                wanted = [db for db, api in STATUSES.items() if api == filters.status]
                query = query.where(m.Run.status.in_(wanted))
            if (since := parse_moment(filters.date_from)) is not None:
                query = query.where(m.Run.started_at >= since)
            if (until := parse_moment(filters.date_to)) is not None:
                query = query.where(m.Run.started_at <= until)
        if after is not None:
            try:
                after_id = uuid.UUID(after[2])
            except ValueError:
                raise ApiError(400, "invalid_cursor", "El cursor de paginación no es válido.") from None
            query = query.where(tuple_(unstarted, started, m.Run.id) < tuple_(after[0], after[1], after_id))
        query = query.order_by(unstarted.desc(), started.desc(), m.Run.id.desc()).limit(limit + 1)
        with self.session_factory() as session:
            rows = session.execute(query).all()
        kept = rows[:limit]
        next_key = None
        if len(rows) > limit:
            last = kept[-1]
            next_key = (int(last[1]), last[2], str(last[0].id))
        return [to_api(row[0], _launcher(row[0], row[3])) for row in kept], next_key

    def queue_scan(self, firebase_uid: str | None) -> Run:
        with self.session_factory() as session, session.begin():
            user_id = (
                session.scalar(select(m.AppUser.id).where(m.AppUser.firebase_uid == firebase_uid))
                if firebase_uid
                else None
            )
            return _with_launcher(session, queue_scan(session, self.clock(), user_id))

    def _read(self, key: uuid.UUID) -> Run | None:
        with self.session_factory() as session:
            row = session.get(m.Run, key)
            return to_api(row) if row is not None and row.kind in KINDS else None  # the stream omits the launcher

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
