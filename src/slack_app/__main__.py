"""Entry point of the Slack service: `python -m slack_app` runs it until SIGTERM/SIGINT; `python -m slack_app migrate
[downgrade <revision>]` runs the Slack module's own migrations."""

from __future__ import annotations

import signal
import sys
import threading
from collections.abc import Sequence

from core.config import read_secret
from core.logging import configure_logging
from slack_app import migrate, service

USAGE = "usage: python -m slack_app [migrate [downgrade <revision>]]"


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        stop = threading.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: stop.set())
        return service.run(stop)
    if args[0] == "migrate":
        configure_logging([read_secret("migrator_db_password") or ""])  # the backend's JSON log with masking
        rest = args[1:]
        if not rest:
            migrate.run(migrate.migration_url())
            return 0
        if len(rest) == 2 and rest[0] == "downgrade":  # noqa: PLR2004
            migrate.run(migrate.migration_url(), "downgrade", rest[1])
            return 0
    print(USAGE, file=sys.stderr)  # noqa: T201 - command-line usage message
    return 2


if __name__ == "__main__":
    sys.exit(main())
