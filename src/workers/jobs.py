"""Periodic jobs of the worker process: a minimal loop until the APScheduler queue arrives (D-029).

Each job runs in turn on the worker thread; a failing job is logged and retried at its next interval, never
stopping the others. Jobs are built only for the integrations that are configured (fail closed, prototype C5).
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session, sessionmaker

from core.calibration.proposals import run_weekly
from core.config import Settings
from core.itop.client import reader_from_settings
from core.itop.outbox import ItopOutboxWorker, writer_from_settings
from core.metrics.ladder import evaluate
from core.metrics.nightly import NightlyMetrics
from core.notifications.dispatcher import NotificationDispatcher, configured_consumer_name, consumer_for
from core.tickets.sync import TicketStateSync
from notifications_api import NotificationConsumer
from workers.pipeline_jobs import pipeline_jobs

log = logging.getLogger("workers.jobs")

ITOP_OUTBOX_SECONDS = 10.0
TICKET_SYNC_SECONDS = 15 * 60.0  # ARQ-02
DISPATCH_SECONDS = 5.0  # NOT-02: an immediate event must not wait
NIGHTLY_SECONDS = 24 * 3600.0  # docs/10 §1: once a day (and once at worker start; the job is idempotent)


@dataclass(frozen=True)
class PeriodicJob:
    name: str
    interval: float
    run: Callable[[], object]
    lane: str = "main"  # jobs of one lane run in turn on one thread; lanes run in parallel


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


@dataclass
class WeeklyCalibrationJob:
    """Mode 4 in supervised mode (D-020): writes this week's proposals and applies none. It checks daily and the
    job itself skips a week that already has a run, so a restart never doubles the proposals."""

    session_factory: sessionmaker[Session]
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))

    def __call__(self) -> None:
        with self.session_factory() as session, session.begin():
            result = run_weekly(session, self.clock())
        if result.run_id is not None:
            log.info("calibration: %d proposal(s) waiting for approval", len(result.created))


@dataclass
class DispatchJob:
    """Delivers pending notification events with the consumer configured in `notifications.consumer` (NOT-05)."""

    session_factory: sessionmaker[Session]
    itop_base_url: str | None = None
    consumers: dict[str, NotificationConsumer] = field(default_factory=dict)

    def __call__(self) -> int:
        with self.session_factory() as session:
            name = configured_consumer_name(session)
        consumer = self.consumers.get(name) or self.consumers.setdefault(name, consumer_for(name))
        return NotificationDispatcher(self.session_factory, consumer, itop_base_url=self.itop_base_url).drain()


def run_jobs_in_threads(stop: threading.Event, jobs: Sequence[PeriodicJob], *, tick: float = 1.0) -> None:
    """One thread per lane: a slow lane (iTop) never delays another (notifications, NOT-03), while the jobs of a
    lane stay serialized (the iTop outbox and the ticket sync must not interleave, D-007)."""
    lanes: dict[str, list[PeriodicJob]] = {}
    for job in jobs:
        lanes.setdefault(job.lane, []).append(job)
    threads = [
        threading.Thread(
            target=run_jobs, args=(stop, lane_jobs), kwargs={"tick": tick}, name=f"lane-{lane}", daemon=True
        )
        for lane, lane_jobs in lanes.items()
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def _pipeline_job(name: str, interval: float, run: Callable[[], object]) -> PeriodicJob:
    """The pipeline cycles share one lane: they take turns (and their own lock) without delaying notifications."""
    return PeriodicJob(name, interval, run, lane="pipeline")


def build_jobs(
    settings: Settings,
    session_factory: sessionmaker[Session],
    consumers: Mapping[str, NotificationConsumer] | None = None,
) -> list[PeriodicJob]:
    """The notification dispatcher, the nightly metrics and the pipeline cycles always (each on its own lane); the
    iTop jobs only when iTop is configured.

    `consumers` registers consumers by the name `notifications.consumer` selects (the Slack module plugs in here in
    F11); `log` is always available.
    """
    itop_url = str(settings.itop_url) if settings.itop_url is not None else None
    dispatch = DispatchJob(session_factory, itop_url, dict(consumers or {}))
    jobs = [
        PeriodicJob("notification_dispatch", DISPATCH_SECONDS, dispatch, lane="notifications"),
        PeriodicJob("nightly_metrics", NIGHTLY_SECONDS, NightlyJob(session_factory), lane="nightly"),
        PeriodicJob("weekly_calibration", NIGHTLY_SECONDS, WeeklyCalibrationJob(session_factory), lane="nightly"),
        *pipeline_jobs(settings, session_factory, _pipeline_job),
    ]
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
