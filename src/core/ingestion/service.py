"""News ingestion service (ING-02 to ING-04): fetch each source, clean, and store articles per source fetch.

One `source_fetch` row per read (FUE-R1) belongs to one `run` of kind `news`. A failing source never stops the
others; a failing full-article download keeps the feed summary. Deduplication into stories is a later step.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id
from core.ingestion.article import extract_article
from core.ingestion.catalog import is_summary_only, mapping_for, sync_default_sources
from core.ingestion.cleaning import clean_html, clean_plain
from core.ingestion.connectors import FeedItem, FormatChangedError, parse_feed
from core.ingestion.fetcher import ARTICLE_CONTENT_TYPES, Fetcher, FetchError
from core.ingestion.urls import InvalidUrlError, canonicalize_url

log = logging.getLogger("ingestion")

# A feed entry with less text than this is treated as summary-only and the full article is downloaded (ING-04).
FULL_ARTICLE_MIN_CHARS = 600
MAX_ERROR_CHARS = 500

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class IngestResult:
    source_code: str
    status: str
    items_new: int
    error: str | None = None


def news_sources(session: Session) -> list[m.Source]:
    """Enabled sources read as news: RSS and Atom feeds, and custom JSON or CSV feeds (D-041)."""
    custom_data_feed = m.Source.is_custom.is_(True) & m.Source.kind.in_(("json", "csv"))
    stmt = (
        select(m.Source)
        .where(m.Source.enabled.is_(True))
        .where(m.Source.kind.in_(("rss", "atom")) | custom_data_feed)
        .order_by(m.Source.code)
    )
    return list(session.scalars(stmt))


def _build_text(item: FeedItem, fetcher: Fetcher, summary_only: bool) -> tuple[str, bool]:
    """Cleaned text of an entry and its suspicious mark.

    The full article is downloaded for sources that only publish summaries (THN) and, for any source, when the
    entry text is too short to be the article (ING-04).
    """
    summary = clean_html(item.summary)
    text, suspicious = summary.text, summary.is_suspicious
    if summary_only or len(text) < FULL_ARTICLE_MIN_CHARS:
        try:
            page = fetcher.get(item.url, ARTICLE_CONTENT_TYPES)
            article = extract_article(page.body.decode("utf-8", errors="replace"))
        except FetchError as exc:
            log.info("Full article not downloaded: %s", exc)
            article = None
        if article is not None:
            suspicious = suspicious or article.is_suspicious  # the mark never depends on which text is kept
            if len(article.text) > len(text):
                text = article.text
    return text, suspicious


TextBuilder = Callable[[FeedItem], tuple[str, bool]]


def _store_item(session: Session, item: FeedItem, fetch_id: uuid.UUID, now: datetime, build_text: TextBuilder) -> bool:
    try:
        canonical = canonicalize_url(item.url)
    except InvalidUrlError:
        return False
    if session.scalar(select(m.RawArticle.id).where(m.RawArticle.canonical_url == canonical)) is not None:
        return False
    title = clean_plain(item.title)
    text, suspicious = build_text(item)
    published = item.published_at if item.published_at and item.published_at <= now else now
    stmt = (
        insert(m.RawArticle)
        .values(
            id=new_id(),
            source_fetch_id=fetch_id,
            canonical_url=canonical,
            title=title.text,
            clean_text=text or None,
            published_at=published,
            captured_at=now,
            is_suspicious=suspicious or title.is_suspicious,
        )
        .on_conflict_do_nothing(index_elements=[m.RawArticle.canonical_url])
        .returning(m.RawArticle.id)
    )
    return session.execute(stmt).first() is not None


def ingest_source(
    session: Session, source: m.Source, fetcher: Fetcher, run_id: uuid.UUID, clock: Clock = utc_now
) -> IngestResult:
    """Read one source and store its new articles; commits its own transaction."""
    now = clock()
    fetch = m.SourceFetch(id=new_id(), source_id=source.id, run_id=run_id, started_at=now, status="error", items_new=0)
    session.add(fetch)
    session.flush()
    status, error, created = "ok", None, 0
    try:
        document = fetcher.get(source.url)
        items = parse_feed(source.kind, document.body, mapping_for(source.code))
        seen: set[str] = set()
        summary_only = is_summary_only(source.code)

        def build_text(item: FeedItem) -> tuple[str, bool]:
            return _build_text(item, fetcher, summary_only)

        for item in items:
            if item.url in seen:
                continue
            seen.add(item.url)
            created += _store_item(session, item, fetch.id, now, build_text)
    except FetchError as exc:
        status, error = "error", str(exc)[:MAX_ERROR_CHARS]
    except FormatChangedError as exc:
        status, error = "format_changed", str(exc)[:MAX_ERROR_CHARS]
    fetch.status, fetch.error, fetch.items_new, fetch.finished_at = status, error, created, clock()
    session.commit()
    log.info("source %s: %s, %d new", source.code, status, created)
    return IngestResult(source_code=source.code, status=status, items_new=created, error=error)


def run_news_ingestion(
    session: Session,
    fetcher: Fetcher,
    trigger_reason: str = "schedule",
    clock: Clock = utc_now,
    *,
    load_defaults: bool = True,
) -> list[IngestResult]:
    """One `news` run over every enabled news source (hourly, and after each scan: ING-02)."""
    if load_defaults:  # idempotent: a fresh install reads the default feeds on its first run
        sync_default_sources(session, clock())
    run = m.Run(
        id=new_id(), kind="news", status="running", progress=0, trigger_reason=trigger_reason, started_at=clock()
    )
    session.add(run)
    session.commit()
    results = [ingest_source(session, source, fetcher, run.id, clock) for source in news_sources(session)]
    run.status = "failed" if results and all(r.status != "ok" for r in results) else "succeeded"
    run.progress, run.finished_at = 100, clock()
    session.commit()
    return results
