"""Worker process entry point: python -m workers.

Runs the periodic jobs of the configured integrations (workers.jobs) until SIGTERM/SIGINT; with none
configured it only waits. APScheduler and the PostgreSQL queue arrive with the features that need them.
"""

from __future__ import annotations

import logging
import signal
import threading

from core.config import Settings
from core.db.session import make_session_factory
from core.logging import configure_logging
from workers.jobs import build_jobs, run_jobs_in_threads

log = logging.getLogger("workers")


def run(stop: threading.Event, settings: Settings | None = None) -> None:
    settings = settings or Settings()
    configure_logging(settings.secret_values())
    log.info("workers started")
    jobs = build_jobs(settings, make_session_factory(settings), stop=stop)
    if jobs:
        run_jobs_in_threads(stop, jobs)
    else:
        stop.wait()
    log.info("workers stopped")


def main() -> None:
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    run(stop)


if __name__ == "__main__":
    main()
