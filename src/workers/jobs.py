"""Periodic jobs of the worker process: a minimal loop until the APScheduler queue arrives (D-029).

Each job runs in turn on the worker thread; a failing job is logged and retried at its next interval, never
stopping the others. Jobs are built only for the integrations that are configured (fail closed, prototype C5).
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session, sessionmaker

from core.config import Settings
from core.itop.client import reader_from_settings
from core.itop.outbox import ItopOutboxWorker, writer_from_settings
from core.metrics.ladder import evaluate
from core.metrics.nightly import NightlyMetrics
from core.tickets.sync import TicketStateSync

log = logging.getLogger("workers.jobs")

ITOP_OUTBOX_SECONDS = 10.0
TICKET_SYNC_SECONDS = 15 * 60.0  # ARQ-02
NIGHTLY_SECONDS = 24 * 3600.0  # docs/10 §1: once a day (and once at worker start; the job is idempotent)


@dataclass(frozen=True)
class PeriodicJob:
    name: str
    interval: float
    run: Callable[[], object]


def run_jobs(
    stop: threading.Event,
    jobs: Sequence[PeriodicJob],
    *,
    tick: float = 1.0,
    clock: Callable[[], float] = time.monotonic,
) -> None:
    """Run every job when due until `stop` is set. All jobs are due at start."""
    due = dict.fromkeys((job.name for job in jobs), clock())
    while not stop.is_set():
        for job in jobs:
            if stop.is_set():
                break
            now = clock()
            if now < due[job.name]:
                continue
            try:
                job.run()
            except Exception:
                log.exception("job %s failed; retrying at its next interval", job.name)
            due[job.name] = now + job.interval
        stop.wait(tick)


@dataclass
class NightlyJob:
    """Aggregates yesterday's metrics (UTC) and then applies the judge ladder rule (L14) on them."""

    session_factory: sessionmaker[Session]
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))

    def __call__(self) -> None:
        now = self.clock()
        day = now.astimezone(UTC).date() - timedelta(days=1)
        NightlyMetrics(self.session_factory, clock=lambda: now).run(day)
        with self.session_factory() as session, session.begin():
            evaluate(session, day, now)


def build_jobs(settings: Settings, session_factory: sessionmaker[Session]) -> list[PeriodicJob]:
    """The nightly metrics always; the iTop jobs only when iTop is configured."""
    jobs = [PeriodicJob("nightly_metrics", NIGHTLY_SECONDS, NightlyJob(session_factory))]
    if settings.itop_url is None or settings.itop_token is None:
        log.info("iTop is not configured: the ticket jobs are off")
        return jobs
    outbox = ItopOutboxWorker(session_factory, writer_from_settings(settings))
    sync = TicketStateSync(session_factory, reader_from_settings(settings), settings.itop_system_user)
    return [
        *jobs,
        PeriodicJob("itop_outbox", ITOP_OUTBOX_SECONDS, outbox.drain),
        PeriodicJob("ticket_sync", TICKET_SYNC_SECONDS, sync.sync_open_tickets),
    ]
