"""One pipeline cycle at a time (ARQ-04): a session-level advisory lock held on its own connection.

The lock lives as long as the connection, so a crashed worker frees it at once. A cycle that finds it taken does
not wait: it is skipped and the next schedule tries again. The scan keeps its own lock (`core.scan.engine`).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Final

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

# Unique among the advisory lock keys of the code base (a unit test checks it): 7_001_010 is the configuration
# write lock, and sharing it made every configuration write wait for a whole pipeline cycle.
PIPELINE_LOCK_KEY: Final = 7_001_030


@contextmanager
def cycle_lock(factory: sessionmaker[Session], key: int = PIPELINE_LOCK_KEY) -> Iterator[bool]:
    """Yields True with the lock held, or False at once when another cycle holds it.

    The guard connection runs in autocommit: it holds the session lock without an open transaction, so it never
    keeps a snapshot or table locks while the cycle runs.
    """
    bind = factory.kw["bind"]
    with bind.connect().execution_options(isolation_level="AUTOCOMMIT") as guard:
        acquired = bool(guard.execute(select(func.pg_try_advisory_lock(key))).scalar())
        try:
            yield acquired
        finally:
            if acquired:
                guard.execute(select(func.pg_advisory_unlock(key)))
