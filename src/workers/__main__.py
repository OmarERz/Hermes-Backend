"""Worker process entry point: python -m workers.

F0 only starts, logs and waits for SIGTERM/SIGINT; APScheduler and the PostgreSQL queue arrive with
the features that need them.
"""

from __future__ import annotations

import logging
import signal
import threading

from core.config import Settings
from core.logging import configure_logging

log = logging.getLogger("workers")


def run(stop: threading.Event, settings: Settings | None = None) -> None:
    settings = settings or Settings()
    configure_logging(settings.secret_values())
    log.info("workers started")
    stop.wait()
    log.info("workers stopped")


def main() -> None:
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    run(stop)


if __name__ == "__main__":
    main()
