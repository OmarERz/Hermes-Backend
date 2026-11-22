"""Dedup layers and stories against PostgreSQL + pgvector with a deterministic embedding double."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from ingestion_support import Feed
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.session import make_engine
from core.ingestion.embeddings import EMBEDDING_MODEL, EmbeddingError
from core.ingestion.entities import ArticleEntities, regex_entities
from core.ingestion.stories import DEDUP_LOCK_KEY, Placement, group_new_articles
from doubles.embedding import fake_embed

pytestmark = pytest.mark.integration
NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)

BASE = "acme firewall appliances contain a flaw that lets remote attackers run arbitrary code on exposed devices"
OTHER = "quarterly earnings call transcript mentions revenue growth across several european retail markets"


def clock() -> datetime:
    return NOW


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


def analyst_entities(title: str, body: str | None) -> ArticleEntities:
    base = regex_entities(title, body)
    return ArticleEntities(base.cves, base.event_hint, victim="acme", actor="lockbit")


def test_gray_zone_needs_analyst_entities_and_checks_every_neighbor(session: Session) -> None:
    words = BASE.split()[:15]
    gray = " ".join(words) + " plus several extra unrelated words about weather and travel plans today"
    feed = Feed(session)
    feed.article("outlet_a", "t", BASE)
    feed.article("outlet_b", "t", gray, hours=1)
    # Similar enough for the gray zone (0.75 to 0.85) but regex entities cannot settle it: two stories.
    placements = group_new_articles(session, fake_embed, clock=clock)
    assert layers(placements) == ["new", "new"]
    # With analyst entities the same kind of pair (far in time, so a fresh window) is one story.
    # (one side cites a CVE, so layer 4, for attacks without CVE, does not apply; the victim and actor decide)
    feed.article("outlet_c", "t", BASE + " CVE-2026-0042", hours=300)
    feed.article("outlet_d", "t", " ".join(words[:13]) + " weather today", hours=301)
    placements = group_new_articles(session, fake_embed, entities=analyst_entities, clock=clock)
    assert layers(placements) == ["new", "gray_zone"]
    assert placements[1].similarity is not None
    assert Decimal("0.75") <= placements[1].similarity < Decimal("0.85")


def test_gray_zone_skips_a_closer_neighbor_whose_entities_disagree(session: Session) -> None:
    words = BASE.split()
    feed = Feed(session)
    feed.article("outlet_a", "t", " ".join(words[:12]) + " weather today")  # 0.79 to the new note: the closer one
    feed.article("outlet_b", "t", " ".join(words[4:]) + " sports scores tonight")  # 0.77
    assert layers(group_new_articles(session, fake_embed, clock=clock)) == ["new", "new"]
    farther = session.scalars(select(m.RawArticle).where(m.RawArticle.canonical_url.like("%outlet_b%"))).one()

    def by_body(title: str, body: str | None) -> ArticleEntities:
        victim = "other" if "weather" in (body or "") else "acme"
        return ArticleEntities(regex_entities(title, body).cves, "disclosure", victim=victim, actor="lockbit")

    feed.article("outlet_c", "t", BASE + " CVE-2026-0042", hours=2)
    placements = group_new_articles(session, fake_embed, entities=by_body, clock=clock)
    assert layers(placements) == ["gray_zone"]
    assert placements[0].story_id == farther.story_id


def test_victim_and_actor_group_attacks_without_cve(session: Session) -> None:
    feed = Feed(session)
    feed.article("outlet_a", "Gang claims hospital", "A gang claims an attack on a hospital network.")
    feed.article("outlet_b", "Totally different words", OTHER, hours=5)
    assert layers(group_new_articles(session, fake_embed, entities=analyst_entities, clock=clock)) == ["new", "attack"]


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


def test_a_run_that_cannot_take_the_grouping_lock_leaves_the_articles_pending(
    session: Session, migrated_url: str
) -> None:
    Feed(session).article("outlet_a", "Acme firewall flaw", BASE)
    session.commit()
    other = Session(make_engine(migrated_url))
    try:
        other.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": DEDUP_LOCK_KEY})
        assert group_new_articles(session, fake_embed, clock=clock) == []
        assert session.scalar(select(func.count()).select_from(m.Story)) == 0
    finally:
        other.rollback()
        other.close()
    assert layers(group_new_articles(session, fake_embed, clock=clock)) == ["new"]
