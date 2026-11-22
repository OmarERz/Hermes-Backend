"""Dedup layers and stories against PostgreSQL + pgvector with a deterministic embedding double."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id
from core.ingestion.embeddings import EMBEDDING_MODEL, EmbeddingError
from core.ingestion.entities import ArticleEntities, regex_entities
from core.ingestion.stories import Placement, group_new_articles
from doubles.embedding import fake_embed

pytestmark = pytest.mark.integration
NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)

BASE = "acme firewall appliances contain a flaw that lets remote attackers run arbitrary code on exposed devices"
OTHER = "quarterly earnings call transcript mentions revenue growth across several european retail markets"


def clock() -> datetime:
    return NOW


class Feed:
    """Creates sources, one fetch per source and articles."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.run = m.Run(id=new_id(), kind="news", status="succeeded", progress=100, trigger_reason="manual")
        session.add(self.run)
        self.fetches: dict[str, m.SourceFetch] = {}
        self.count = 0

    def _fetch(self, outlet: str) -> m.SourceFetch:
        if outlet not in self.fetches:
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
            fetch = m.SourceFetch(
                id=new_id(), source_id=source.id, run_id=self.run.id, started_at=NOW, status="ok", items_new=0
            )
            self.session.add(fetch)
            self.session.flush()
            self.fetches[outlet] = fetch
        return self.fetches[outlet]

    def article(self, outlet: str, title: str, body: str, hours: float = 0.0) -> m.RawArticle:
        self.count += 1
        article = m.RawArticle(
            id=new_id(),
            source_fetch_id=self._fetch(outlet).id,
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


def layers(placements: list[Placement]) -> list[str]:
    return [p.layer for p in placements]


def test_republished_note_makes_one_story_with_both_urls(session: Session) -> None:
    feed = Feed(session)
    first = feed.article("outlet_a", "Acme firewall flaw", BASE)
    second = feed.article("outlet_b", "Acme firewall flaw reported", BASE + " according to researchers", hours=3)
    placements = group_new_articles(session, fake_embed, clock=clock)
    assert layers(placements) == ["new", "similarity"]
    assert placements[1].similarity is not None
    assert placements[1].similarity >= Decimal("0.85")
    story = session.scalars(select(m.Story)).one()
    assert story.relevance_status == "pending"
    assert story.embedding_model == EMBEDDING_MODEL
    assert story.representative_article_id == first.id
    assert first.story_id == second.story_id == story.id
    timeline = session.execute(text("SELECT first_published_at, urls FROM story_timeline")).one()
    assert timeline.first_published_at == first.published_at
    assert set(timeline.urls) == {first.canonical_url, second.canonical_url}


def test_second_pass_has_nothing_to_do(session: Session) -> None:
    Feed(session).article("outlet_a", "Acme firewall flaw", BASE)
    assert layers(group_new_articles(session, fake_embed, clock=clock)) == ["new"]
    assert group_new_articles(session, fake_embed, clock=clock) == []
    assert session.scalar(select(func.count()).select_from(m.Story)) == 1


def test_unrelated_and_out_of_window_notes_start_their_own_story(session: Session) -> None:
    feed = Feed(session)
    feed.article("outlet_a", "Acme firewall flaw", BASE)
    feed.article("outlet_b", "Earnings call", OTHER, hours=1)
    feed.article("outlet_c", "Acme firewall flaw", BASE, hours=24 * 5)  # same text, five days later
    assert layers(group_new_articles(session, fake_embed, clock=clock)) == ["new", "new", "new"]


def test_same_cves_and_event_group_even_when_the_text_differs(session: Session) -> None:
    feed = Feed(session)
    feed.article("outlet_a", "CVE-2026-0001 exploited", "Attackers exploit CVE-2026-0001 against exposed servers.")
    feed.article("outlet_b", "Vendor warns", OTHER + " cve-2026-0001 actively exploited", hours=2)
    feed.article("outlet_c", "CVE-2026-0001 fixed", "Security update released. " + OTHER + " CVE-2026-0001", hours=2)
    placements = group_new_articles(session, fake_embed, clock=clock)
    assert layers(placements) == ["new", "cve_event", "new"]  # a patch note is another event type


def test_gray_zone_is_decided_by_the_entities_not_by_similarity_alone(session: Session) -> None:
    words = BASE.split()[:15]
    gray = " ".join(words) + " plus several extra unrelated words about weather and travel plans today"
    feed = Feed(session)
    feed.article("outlet_a", "t", BASE)
    feed.article("outlet_b", "t", gray, hours=1)
    # Similar enough for the gray zone (0.75 to 0.85) but no shared CVE or attack: two stories.
    assert layers(group_new_articles(session, fake_embed, clock=clock)) == ["new", "new"]
    # A pair in the gray zone that shares a CVE set with another event hint (layer 2 does not apply): one story.
    feed.article("outlet_c", "t", BASE + " CVE-2026-0042 exploited", hours=300)
    feed.article("outlet_d", "t", " ".join(words) + " CVE-2026-0042 patched plus more filler words here", hours=301)
    placements = group_new_articles(session, fake_embed, clock=clock)
    assert layers(placements) == ["new", "gray_zone"]
    assert placements[1].similarity is not None
    assert Decimal("0.75") <= placements[1].similarity < Decimal("0.85")


def test_victim_and_actor_group_attacks_without_cve(session: Session) -> None:
    def provider(title: str, body: str | None) -> ArticleEntities:
        base = regex_entities(title, body)
        return ArticleEntities(base.cves, base.event_hint, victim="acme", actor="lockbit")

    feed = Feed(session)
    feed.article("outlet_a", "Gang claims hospital", "A gang claims an attack on a hospital network.")
    feed.article("outlet_b", "Totally different words", OTHER, hours=5)
    assert layers(group_new_articles(session, fake_embed, entities=provider, clock=clock)) == ["new", "attack"]


def test_older_article_arriving_later_becomes_the_representative(session: Session) -> None:
    feed = Feed(session)
    later = feed.article("outlet_a", "Acme firewall flaw", BASE, hours=4)
    assert layers(group_new_articles(session, fake_embed, clock=clock)) == ["new"]
    earlier = feed.article("outlet_b", "Acme firewall flaw", BASE, hours=1)
    assert layers(group_new_articles(session, fake_embed, clock=clock)) == ["similarity"]
    story = session.scalars(select(m.Story)).one()
    assert story.representative_article_id == earlier.id
    assert later.story_id == story.id


def test_embedding_function_with_wrong_shape_is_rejected(session: Session) -> None:
    Feed(session).article("outlet_a", "t", BASE)
    with pytest.raises(EmbeddingError):
        group_new_articles(session, lambda texts: [[0.0] for _ in texts], clock=clock)
    assert session.scalar(select(func.count()).select_from(m.Story)) == 0
