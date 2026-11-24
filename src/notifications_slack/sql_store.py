"""`SlackStore` over PostgreSQL: the module's own `slack_*` tables (NOT-07), used through the `slack_module` role.

Table definitions live here with their own `MetaData` (never the backend's `Base`); the schema itself comes from the
module's Alembic chain (`notifications_slack/migrations`, approved 23 Nov 2026). The engine is passed in by the
composition root, which applies the backend's connection and TLS rules.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    Column,
    DateTime,
    Engine,
    MetaData,
    SmallInteger,
    Table,
    Text,
    delete,
    func,
    select,
    update,
)
from sqlalchemy.dialects.postgresql import JSONB, insert

from notifications_slack.routing import Audience
from notifications_slack.store import MAX_ATTEMPTS, DeliveryRecord, QueuedItem, ThreadRef, backoff

metadata = MetaData()

slack_thread = Table(
    "slack_thread",
    metadata,
    Column("thread_key", Text, primary_key=True),
    Column("audience", Text, primary_key=True),
    Column("channel_id", Text, nullable=False),
    Column("root_ts", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

slack_delivery = Table(
    "slack_delivery",
    metadata,
    Column("event_id", Text, primary_key=True),
    Column("audience", Text, primary_key=True),
    Column("channel_id", Text, nullable=False),
    Column("delivery", Text, nullable=False),
    Column("message_ts", Text, nullable=False),
    Column("delivered_at", DateTime(timezone=True), nullable=False),
)

slack_digest_item = Table(
    "slack_digest_item",
    metadata,
    Column("event_id", Text, primary_key=True),
    Column("channel_id", Text, nullable=False),
    Column("payload", JSONB, nullable=False),
    Column("queued_at", DateTime(timezone=True), nullable=False),
    Column("status", Text, nullable=False),
    Column("attempts", SmallInteger, nullable=False),
    Column("next_attempt_at", DateTime(timezone=True)),
    Column("last_error", Text),
    Column("digest_ts", Text),
)

_d, _t, _q = slack_delivery.c, slack_thread.c, slack_digest_item.c


class SqlSlackStore:
    """Same rules as `InMemorySlackStore`; one short transaction per call."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def is_known(self, event_id: str, audience: Audience) -> bool:
        with self.engine.connect() as conn:
            if conn.execute(select(1).where(_d.event_id == event_id, _d.audience == audience)).first():
                return True
            return audience == "standard" and conn.execute(select(1).where(_q.event_id == event_id)).first() is not None

    def record_delivery(self, record: DeliveryRecord) -> None:
        with self.engine.begin() as conn:
            conn.execute(self._delivery(record))

    @staticmethod
    def _delivery(record: DeliveryRecord) -> Any:
        return (
            insert(slack_delivery)
            .values(
                event_id=record.event_id,
                audience=record.audience,
                channel_id=record.channel_id,
                delivery=record.kind,
                message_ts=record.message_ts,
                delivered_at=record.at,
            )
            .on_conflict_do_nothing(index_elements=["event_id", "audience"])
        )

    def thread(self, thread_key: str, audience: Audience) -> ThreadRef | None:
        with self.engine.connect() as conn:
            row = conn.execute(
                select(_t.channel_id, _t.root_ts).where(_t.thread_key == thread_key, _t.audience == audience)
            ).first()
        return ThreadRef(row.channel_id, row.root_ts) if row else None

    def save_thread(self, thread_key: str, audience: Audience, ref: ThreadRef, now: datetime) -> None:
        statement = insert(slack_thread).values(
            thread_key=thread_key,
            audience=audience,
            channel_id=ref.channel_id,
            root_ts=ref.root_ts,
            created_at=now,
            updated_at=now,
        )
        statement = statement.on_conflict_do_update(
            index_elements=["thread_key", "audience"],
            set_={
                "channel_id": statement.excluded.channel_id,
                "root_ts": statement.excluded.root_ts,
                "updated_at": func.greatest(slack_thread.c.created_at, statement.excluded.updated_at),
            },
        )
        with self.engine.begin() as conn:
            conn.execute(statement)

    def enqueue(self, event_id: str, channel_id: str, payload: dict[str, Any], now: datetime, due: datetime) -> None:
        with self.engine.begin() as conn:
            delivered = conn.execute(select(1).where(_d.event_id == event_id, _d.audience == "standard")).first()
            if delivered:
                return
            conn.execute(
                insert(slack_digest_item)
                .values(
                    event_id=event_id,
                    channel_id=channel_id,
                    payload=payload,
                    queued_at=now,
                    status="queued",
                    attempts=0,
                    next_attempt_at=due,
                )
                .on_conflict_do_nothing(index_elements=["event_id"])
            )

    def due_channels(self, now: datetime) -> list[str]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(_q.channel_id)
                .where(_q.status == "queued", _q.next_attempt_at <= now)
                .distinct()
                .order_by(_q.channel_id)
            )
            return [str(row.channel_id) for row in rows]

    def due_items(self, channel_id: str, now: datetime) -> list[QueuedItem]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(_q.event_id, _q.channel_id, _q.payload, _q.queued_at, _q.attempts, _q.digest_ts)
                .where(_q.channel_id == channel_id, _q.status == "queued", _q.next_attempt_at <= now)
                .order_by(_q.queued_at, _q.event_id)
            ).all()
        return [
            QueuedItem(r.event_id, r.channel_id, dict(r.payload), r.queued_at, int(r.attempts), r.digest_ts)
            for r in rows
        ]

    def set_digest_ts(self, event_ids: list[str], digest_ts: str) -> None:
        if not event_ids:
            return
        with self.engine.begin() as conn:
            conn.execute(
                update(slack_digest_item)
                .where(_q.event_id.in_(event_ids), _q.status == "queued")
                .values(digest_ts=digest_ts)
            )

    def complete_item(self, record: DeliveryRecord) -> None:
        with self.engine.begin() as conn:
            conn.execute(self._delivery(record))
            conn.execute(delete(slack_digest_item).where(_q.event_id == record.event_id))

    def fail_item(self, event_id: str, code: str, now: datetime, *, permanent: bool) -> bool:
        with self.engine.begin() as conn:
            row = conn.execute(
                select(_q.attempts).where(_q.event_id == event_id, _q.status == "queued").with_for_update()
            ).first()
            if row is None:
                return False
            attempts = int(row.attempts) + 1
            failed = permanent or attempts >= MAX_ATTEMPTS
            conn.execute(
                update(slack_digest_item)
                .where(_q.event_id == event_id)
                .values(
                    attempts=attempts,
                    last_error=code[:200],
                    status="failed" if failed else "queued",
                    next_attempt_at=None if failed else now + backoff(attempts),
                )
            )
            return failed

    def purge(self, deliveries_before: datetime, threads_before: datetime) -> int:
        with self.engine.begin() as conn:
            removed = conn.execute(delete(slack_delivery).where(_d.delivered_at < deliveries_before)).rowcount
            removed += conn.execute(delete(slack_thread).where(_t.updated_at < threads_before)).rowcount
            removed += conn.execute(
                delete(slack_digest_item).where(_q.status == "failed", _q.queued_at < deliveries_before)
            ).rowcount
            return int(removed)
