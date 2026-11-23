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

PIPELINE_LOCK_KEY: Final = 7_001_010


@contextmanager
def cycle_lock(factory: sessionmaker[Session], key: int = PIPELINE_LOCK_KEY) -> Iterator[bool]:
    """Yields True with the lock held, or False at once when another cycle holds it."""
    bind = factory.kw["bind"]
    with bind.connect() as guard:
        acquired = bool(guard.execute(select(func.pg_try_advisory_lock(key))).scalar())
        try:
            yield acquired
        finally:
            if acquired:
                guard.execute(select(func.pg_advisory_unlock(key)))
