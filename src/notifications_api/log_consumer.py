"""Default consumer (NOT-05): one structured log line per event, without personal data (NOT-08)."""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict

from notifications_api.models import NotificationEvent

_logger = logging.getLogger("notifications_api.log_consumer")


class LogConsumer:
    """Writes each event to the log so the backend works end to end without the Slack module.

    Only identifiers and levels are logged: no owner names or e-mails, no news titles, no free text,
    and assets by `ci_id` only.

    Idempotent by `event_id` (NOT-02: delivery is at least once): an event already seen is not logged again.
    The memory of seen ids is bounded and per instance; durable, restart-proof idempotency lives in the outbox
    (the dispatcher marks an event delivered only after `process` returns). Stream errors inside a logging
    handler are swallowed by the `logging` module itself, so only exceptions raised by the logger propagate.
    """

    def __init__(self, logger: logging.Logger | None = None, max_seen: int = 100_000) -> None:
        self._logger = logger or _logger
        self._max_seen = max_seen
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._lock = threading.Lock()

    def process(self, event: NotificationEvent) -> None:
        with self._lock:  # held during the write: a concurrent duplicate waits, then sees the outcome
            if event.event_id in self._seen:
                return
            self._write(event)
            # Recorded only after a successful write, so a failed write is retried by the dispatcher.
            self._seen[event.event_id] = None
            if len(self._seen) > self._max_seen:
                self._seen.popitem(last=False)

    def _write(self, event: NotificationEvent) -> None:
        self._logger.info(
            "notification event_id=%s type=%s priority=%s ticket=%s cve=%s level=%s final=%s assets=%s news=%d",
            event.event_id,
            event.type,
            event.priority,
            event.ticket.itop_id if event.ticket else None,
            event.vulnerability.cve if event.vulnerability else None,
            event.score.level if event.score else None,
            event.score.final if event.score else None,
            ",".join(asset.ci_id for asset in event.assets) or "-",
            len(event.news),
        )
