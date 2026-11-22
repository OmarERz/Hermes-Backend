"""Error queue and budget usage against PostgreSQL."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

import pytest
from ingestion_support import NOW, Feed
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id
from core.validation.budget import spent_on
from core.validation.queue import (
    QueueRef,
    due_items,
    enqueue_failure,
    give_up,
    needs_attention,
    resolve,
)

pytestmark = pytest.mark.integration


def story(session: Session, outlet: str = "a") -> m.Story:
    article = Feed(session).article(outlet, "t", "body")
    row = m.Story(id=new_id(), representative_article_id=article.id, relevance_status="relevant", created_at=NOW)
    session.add(row)
    session.flush()
    return row


def review(session: Session, cost: str, when: datetime, agent: str = "news_analyst") -> None:
    session.add(
        m.LlmReview(
            id=new_id(),
            agent=agent,
            model="deepseek-flash",
            response_model={},
            prompt_version="1",
            prompt_hash="h",
            schema_version="1",
            schema_hash="h",
            parameters={},
            input_ref="x",
            calls=[],
            status="applied",
            attempts=1,
            tokens_input=1,
            tokens_cached=0,
            tokens_output=1,
            tokens_reasoning=0,
            cost_usd=Decimal(cost),
            latency_ms=1,
            ladder_level=0,
            created_at=when,
        )
    )
    session.flush()


def test_failures_queue_once_per_item_and_run_out_of_automatic_retries(session: Session) -> None:
    ref = QueueRef("news_analyst", story_id=story(session).id)
    first = enqueue_failure(session, ref, "VAL-03.quote", NOW)
    assert (first.attempts, first.status, first.next_attempt_at) == (1, "pending", NOW)
    assert [r.id for r in due_items(session, NOW)] == [first.id]
    assert due_items(session, NOW - timedelta(hours=1)) == []
    again = enqueue_failure(session, ref, "VAL-02.schema", NOW)
    assert again.id == first.id
    assert (again.attempts, again.reason, again.next_attempt_at) == (2, "VAL-02.schema", NOW)
    third = enqueue_failure(session, ref, "VAL-02.schema", NOW)
    assert (third.attempts, third.next_attempt_at) == (3, None)
    assert due_items(session, NOW) == []
    assert [r.id for r in needs_attention(session)] == [first.id]
    assert session.scalar(select(func.count()).select_from(m.ErrorQueue)) == 1


def test_resolved_and_abandoned_items_leave_the_queue_and_a_new_failure_starts_a_new_row(session: Session) -> None:
    ref = QueueRef("cve_analyst", cve_id=None, story_id=story(session).id)
    row = enqueue_failure(session, ref, "x", NOW)
    resolve(session, row)
    assert (row.status, row.next_attempt_at) == ("resolved", None)
    assert due_items(session, NOW) == [] == needs_attention(session)
    other = enqueue_failure(session, ref, "x", NOW)
    assert other.id != row.id
    give_up(session, other)
    assert other.status == "gave_up"
    assert needs_attention(session) == []


@pytest.mark.parametrize(
    "ref",
    [
        QueueRef("unknown", cve_id="CVE-2026-0001"),
        QueueRef("judge"),
        QueueRef("judge", cve_id="CVE-2026-0001", review_package_id=new_id()),
    ],
)
def test_a_queue_item_needs_a_known_component_and_exactly_one_reference(session: Session, ref: QueueRef) -> None:
    with pytest.raises(ValueError, match=r"component|exactly one"):
        enqueue_failure(session, ref, "x", NOW)


def test_items_of_different_references_do_not_merge(session: Session) -> None:
    a, b = story(session, "a"), story(session, "b")
    session.flush()
    first = enqueue_failure(session, QueueRef("news_analyst", story_id=a.id), "x", NOW)
    second = enqueue_failure(session, QueueRef("news_analyst", story_id=b.id), "x", NOW)
    assert first.id != second.id


def test_spent_today_sums_the_reviews_of_the_utc_day(session: Session) -> None:
    review(session, "0.250000", NOW)
    review(session, "0.100000", NOW + timedelta(hours=1), agent="judge")
    review(session, "9.000000", NOW - timedelta(days=1))
    assert spent_on(session, date(2026, 11, 22)) == Decimal("0.35")
    assert spent_on(session, date(2026, 11, 20)) == Decimal(0)
    assert NOW.tzinfo is UTC
