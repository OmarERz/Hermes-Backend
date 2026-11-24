"""Entry point: `python -m slack_app migrate [downgrade <revision>]` runs the Slack module's own migrations."""

from __future__ import annotations

import logging
import sys
from collections.abc import Sequence

from slack_app import migrate

log = logging.getLogger("slack_app")
USAGE = "usage: python -m slack_app migrate [downgrade <revision>]"


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["migrate"]:
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
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())
