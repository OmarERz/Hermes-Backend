"""Shared helpers of the ingestion integration tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id

NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)


class Feed:
    """Creates sources, one fetch per source and articles."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.run = m.Run(id=new_id(), kind="news", status="succeeded", progress=100, trigger_reason="manual")
        session.add(self.run)
        self.sources: dict[str, m.Source] = {}
        self.fetches: dict[str, m.SourceFetch] = {}
        self.count = 0

    def source_for(self, outlet: str) -> m.Source:
        if outlet not in self.sources:
            source = m.Source(
                id=new_id(),
                code=outlet,
                name=outlet,
                kind="rss",
                url=f"https://{outlet}.example.com/feed",
                trust_tier="N3",
                is_structural=False,
                is_custom=False,
                enabled=True,
                created_at=NOW,
            )
            self.session.add(source)
            self.session.flush()
            self.sources[outlet] = source
        return self.sources[outlet]

    def fetch_for(self, outlet: str) -> m.SourceFetch:
        """The one fetch that articles of this outlet hang from (an ok read at NOW)."""
        if outlet not in self.fetches:
            fetch = m.SourceFetch(
                id=new_id(),
                source_id=self.source_for(outlet).id,
                run_id=self.run.id,
                started_at=NOW,
                status="ok",
                items_new=0,
            )
            self.session.add(fetch)
            self.session.flush()
            self.fetches[outlet] = fetch
        return self.fetches[outlet]

    def article(self, outlet: str, title: str, body: str, hours: float = 0.0) -> m.RawArticle:
        self.count += 1
        article = m.RawArticle(
            id=new_id(),
            source_fetch_id=self.fetch_for(outlet).id,
            canonical_url=f"https://{outlet}.example.com/n{self.count}",
            title=title,
            clean_text=body,
            published_at=NOW + timedelta(hours=hours),
            captured_at=NOW,
            is_suspicious=False,
        )
        self.session.add(article)
        self.session.flush()
        return article
