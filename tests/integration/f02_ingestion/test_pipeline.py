"""Ingestion plus dedup from simulated feeds: a republished note is one story with both URLs."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from core.db import models as m
from core.ingestion.fetcher import Fetcher
from core.ingestion.pipeline import PipelineOptions, run_news_pipeline
from doubles.embedding import fake_embed
from doubles.web import FakeWeb

pytestmark = pytest.mark.integration
NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
BODY = (
    "Acme firewall appliances contain a flaw that lets remote attackers run arbitrary code on exposed devices. "
    "Customers should review exposure and apply the vendor guidance as soon as possible. "
) * 4


def clock() -> datetime:
    return NOW


def rss(link: str, title: str, body: str, date: str) -> bytes:
    return (
        '<?xml version="1.0"?><rss version="2.0"><channel><title>S</title>'
        f"<item><title>{title}</title><link>{link}</link><pubDate>{date}</pubDate>"
        f"<description>{body}</description></item></channel></rss>"
    ).encode()


def test_republished_note_ends_as_one_story_with_two_urls(session: Session) -> None:
    web = FakeWeb()
    web.serve(
        "https://thn.example.com/feed",
        rss("https://thn.example.com/a", "Acme flaw", BODY, "Sat, 21 Nov 2026 08:00:00 GMT"),
    )
    web.serve(
        "https://bleeping.example.com/feed",
        rss(
            "https://bleeping.example.com/b",
            "Acme flaw reported",
            BODY + " Researchers say so.",
            "Sat, 21 Nov 2026 11:00:00 GMT",
        ),
    )
    for code in ("thn", "bleeping"):
        session.add(
            m.Source(
                code=code, name=code, kind="rss", url=f"https://{code}.example.com/feed", trust_tier="N3",
                is_structural=False, is_custom=False, enabled=True, created_at=NOW,
            )
        )  # fmt: skip
    session.commit()
    fetcher = Fetcher(transport=web.transport(), resolver=lambda _h: ["93.184.216.34"])
    result = run_news_pipeline(session, fetcher, fake_embed, PipelineOptions(clock=clock))
    assert sum(r.items_new for r in result.ingested) == 2
    assert [p.layer for p in result.placements] == ["new", "similarity"]
    assert session.scalar(select(func.count()).select_from(m.Story)) == 1
    urls = session.execute(text("SELECT urls FROM story_timeline")).scalar_one()
    assert urls == ["https://thn.example.com/a", "https://bleeping.example.com/b"]
    # A second pass finds nothing new: same canonical URLs, nothing pending.
    again = run_news_pipeline(session, fetcher, fake_embed, PipelineOptions(clock=clock))
    assert sum(r.items_new for r in again.ingested) == 0
    assert again.placements == []


def seven_hours_later() -> datetime:
    return NOW + timedelta(hours=7)


def test_down_source_raises_an_alert_through_the_pipeline_and_stories_are_filtered(session: Session) -> None:
    web = FakeWeb()
    web.serve("https://down.example.com/feed", b"", status=503)
    session.add(
        m.Source(
            code="down", name="down", kind="rss", url="https://down.example.com/feed", trust_tier="N3",
            is_structural=False, is_custom=False, enabled=True, created_at=NOW,
        )
    )  # fmt: skip
    session.commit()
    fetcher = Fetcher(transport=web.transport(), resolver=lambda _h: ["93.184.216.34"])
    first = run_news_pipeline(session, fetcher, fake_embed, PipelineOptions(clock=clock))
    assert first.alerts == []  # inside the grace period
    second = run_news_pipeline(session, fetcher, fake_embed, PipelineOptions(clock=seven_hours_later))
    # The default feeds are also loaded and unreachable in this fake web; the 503 source is among the alerts.
    assert ("down", "no_data") in [(a.source_code, a.reason) for a in second.alerts]
    down = session.scalars(select(m.Source).where(m.Source.code == "down")).one()
    assert session.scalar(select(m.AuditLog.action).where(m.AuditLog.entity_id == str(down.id))) == "source.down"


def test_unrelated_story_is_filtered_by_the_pipeline(session: Session) -> None:
    web = FakeWeb()
    web.serve(
        "https://thn.example.com/feed",
        rss("https://thn.example.com/x", "Sports", BODY, "Sat, 21 Nov 2026 08:00:00 GMT"),
    )
    session.add(
        m.Source(
            code="thn", name="thn", kind="rss", url="https://thn.example.com/feed", trust_tier="N3",
            is_structural=False, is_custom=False, enabled=True, created_at=NOW,
        )
    )  # fmt: skip
    session.commit()
    fetcher = Fetcher(transport=web.transport(), resolver=lambda _h: ["93.184.216.34"])
    result = run_news_pipeline(session, fetcher, fake_embed, PipelineOptions(clock=clock))
    # No products, CVEs, sectors or peers are configured: nothing can pass the filter.
    assert (result.filtered.relevant, result.filtered.filtered) == (0, 1)
    assert session.scalar(select(m.Story.relevance_status)) == "filtered"
