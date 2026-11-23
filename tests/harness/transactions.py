"""Probe for F12.2 #105: is any database transaction (and with it any row or transaction-level lock) open?

Called from the LLM double's `on_request` hook, it looks at the server from a fresh connection, so it sees what the
code under test holds at the moment the model is "answering". It returns what it finds instead of asserting: an
exception raised inside the HTTP transport would reach the code under test as a transport failure.
"""

from __future__ import annotations

from sqlalchemy import Engine, text

_OPEN = text(
    "SELECT a.pid, a.state, count(l.pid) AS locks FROM pg_stat_activity a LEFT JOIN pg_locks l ON l.pid = a.pid "
    "WHERE a.datname = current_database() AND a.pid <> pg_backend_pid() AND a.xact_start IS NOT NULL "
    "AND a.backend_type = 'client backend' "  # not autovacuum or autoanalyze workers
    "GROUP BY a.pid, a.state"
)


def open_transactions(engine: Engine) -> list[tuple[int, str, int]]:
    """(pid, state, locks held) of every other backend of this database that is inside a transaction."""
    with engine.connect() as probe:
        return [(int(pid), str(state), int(locks)) for pid, state, locks in probe.execute(_OPEN)]
