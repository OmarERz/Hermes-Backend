"""Admin CLI for local development and tests (docs/12 F0.7, D-059).

    python -m core.devtools.admin seed --scenario empty|demo|edge
    python -m core.devtools.admin bootstrap
    python -m core.devtools.admin events [--limit N] [--status pending|delivered|failed] [--type new_ticket ...]

`bootstrap` is what the compose stack runs after the migrations (F-01): it loads the factory values (the `empty`
scenario) only when there is no formula version, and syncs the default news sources; running it again changes
nothing. `seed` loads a seed scenario as the migrator role (it owns the catalogs): MIGRATION_DATABASE_URL plus the
migrator_db_password secret. `events` lists the latest notification events as JSON lines, read as the app role:
DATABASE_URL plus the pgpassword secret. Passwords never go on the command line.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.config import read_secret
from core.db import models as m
from core.db.seeds import SCENARIOS, seed
from core.db.session import make_engine, with_password
from core.ingestion.catalog import sync_default_sources

MAX_EVENTS = 500
EVENT_STATUSES = ("pending", "delivered", "failed")
EVENT_TYPES = ("new_ticket", "level_up", "reopened", "partially_fixed", "fixed", "threat_alert", "inferred_alert")


class AdminError(RuntimeError):
    """A configuration problem the CLI reports without a traceback."""


def database_url_from_env(env_name: str, secret_name: str) -> str:
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        raise AdminError(f"{env_name} is not set")
    return with_password(raw, read_secret(secret_name))


def run_seed(url: str, scenario: str) -> None:
    engine = make_engine(url)
    try:
        with Session(engine) as session, session.begin():
            seed(session, scenario)
    finally:
        engine.dispose()


def run_bootstrap(url: str, now: datetime | None = None) -> str:
    """Factory values on a fresh database and the default sources; idempotent. Returns what it did."""
    engine = make_engine(url)
    try:
        with Session(engine) as session, session.begin():
            fresh = session.scalar(select(m.FormulaVersion.id).limit(1)) is None
            if fresh:
                seed(session, "empty")
            added = sync_default_sources(session, now or datetime.now(UTC))
    finally:
        engine.dispose()
    return f"factory values {'loaded' if fresh else 'already present'}; {len(added)} source(s) added"


def list_events(url: str, *, limit: int, status: str | None, event_type: str | None) -> list[dict[str, Any]]:
    query = select(m.NotificationEvent).order_by(m.NotificationEvent.created_at.desc()).limit(limit)
    if status:
        query = query.where(m.NotificationEvent.status == status)
    if event_type:
        query = query.where(m.NotificationEvent.event_type == event_type)
    engine = make_engine(url)
    try:
        with Session(engine) as session:
            return [
                {
                    "id": str(e.id),
                    "created_at": e.created_at.isoformat(),
                    "type": e.event_type,
                    "priority": e.priority,
                    "status": e.status,
                    "attempts": e.attempts,
                    "ticket_id": str(e.ticket_id) if e.ticket_id else None,
                    "last_error": e.last_error,
                }
                for e in session.scalars(query)
            ]
    finally:
        engine.dispose()


def _positive(value: str) -> int:
    number = int(value)
    if not 1 <= number <= MAX_EVENTS:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_EVENTS}")
    return number


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="core.devtools.admin", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    seed_cmd = commands.add_parser("seed", help="load a seed scenario")
    seed_cmd.add_argument("--scenario", choices=SCENARIOS, required=True)
    commands.add_parser("bootstrap", help="load the factory values and default sources if missing (idempotent)")
    events_cmd = commands.add_parser("events", help="list the latest notification events")
    events_cmd.add_argument("--limit", type=_positive, default=20)
    events_cmd.add_argument("--status", choices=EVENT_STATUSES)
    events_cmd.add_argument("--type", dest="event_type", choices=EVENT_TYPES)
    args = parser.parse_args(argv)
    try:
        if args.command == "seed":
            run_seed(database_url_from_env("MIGRATION_DATABASE_URL", "migrator_db_password"), args.scenario)
            sys.stdout.write(f"seeded scenario {args.scenario}\n")
        elif args.command == "bootstrap":
            sys.stdout.write(
                run_bootstrap(database_url_from_env("MIGRATION_DATABASE_URL", "migrator_db_password")) + "\n"
            )
        else:
            rows = list_events(
                database_url_from_env("DATABASE_URL", "pgpassword"),
                limit=args.limit,
                status=args.status,
                event_type=args.event_type,
            )
            for row in rows:
                sys.stdout.write(json.dumps(row, ensure_ascii=False) + "\n")
    except (AdminError, RuntimeError) as error:
        sys.stderr.write(f"error: {error}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
