"""Keyword filter against the demo inventory (OpenSSL, CVE-2026-10001 with an active finding)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from dbprovision import provisioned_database
from ingestion_support import NOW, Feed
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id
from core.db.seeds import seed
from core.db.session import make_engine
from core.ingestion.keywords import build_keywords, filter_pending_stories

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def migrated_url(postgres_url: str) -> Iterator[str]:
    """This module needs the demo inventory (the shared fixture seeds only the catalogs)."""
    with provisioned_database(postgres_url, "keywords") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        engine = make_engine(db.superuser_url)
        with Session(engine) as session, session.begin():
            seed(session, "demo")
        engine.dispose()
        yield db.superuser_url


@pytest.fixture
def session(migrated_url: str) -> Iterator[Session]:
    """Rolls back and removes only the news rows: the demo inventory (which hangs off other runs) stays."""
    engine = make_engine(migrated_url)
    with Session(engine, expire_on_commit=False) as db_session:
        yield db_session
        db_session.rollback()
    with engine.begin() as conn:
        for statement in (
            "UPDATE raw_article SET story_id = NULL",
            "DELETE FROM story",
            "DELETE FROM raw_article",
            "DELETE FROM source_fetch",
            "DELETE FROM run WHERE kind = 'news'",
            "DELETE FROM source",
        ):
            conn.execute(text(statement))
    engine.dispose()


def story_for(feed: Feed, outlet: str, title: str, body: str) -> m.Story:
    article = feed.article(outlet, title, body)
    story = m.Story(id=new_id(), representative_article_id=article.id, relevance_status="pending", created_at=NOW)
    feed.session.add(story)
    feed.session.flush()
    article.story_id = story.id
    feed.session.flush()
    return story


def test_keywords_come_from_products_cves_sectors_and_peers(session: Session) -> None:
    session.add(m.ProfileSector(sector_code="healthcare", is_primary=True))
    peer = m.PeerCompany(id=new_id(), name="Globex Corp", created_at=NOW)
    session.add(peer)
    session.flush()
    session.add(m.PeerCompanyAlias(peer_company_id=peer.id, alias="Globex"))
    session.flush()
    keywords = build_keywords(session)
    assert {"openssl", "hospital", "salud", "clínica", "globex corp", "globex"} <= keywords.terms
    assert keywords.cves == {"CVE-2026-10001"}
    assert "comercio" not in keywords.terms  # retail is not one of the company's sectors


def test_stories_are_marked_relevant_or_filtered(session: Session) -> None:
    session.add(m.ProfileSector(sector_code="healthcare", is_primary=True))
    feed = Feed(session)
    by_product = story_for(feed, "a", "Critical OpenSSL bug", "Details of the flaw.")
    by_cve = story_for(feed, "b", "Patch Tuesday", "Fixes CVE-2026-10001 among others.")
    by_sector = story_for(feed, "c", "Attack", "A hospital network was hit.")
    unrelated = story_for(feed, "d", "Sports", "The match ended in a draw.")
    decided = story_for(feed, "e", "OpenSSL again", "Already decided before the filter ran.")
    decided.relevance_status = "filtered"
    session.flush()
    result = filter_pending_stories(session)
    assert (result.relevant, result.filtered) == (3, 1)
    status = {s.id: s.relevance_status for s in session.scalars(select(m.Story))}
    assert status[by_product.id] == status[by_cve.id] == status[by_sector.id] == "relevant"
    assert status[unrelated.id] == "filtered"
    assert status[decided.id] == "filtered"  # not pending: left alone


def test_any_article_of_a_story_can_make_it_relevant(session: Session) -> None:
    feed = Feed(session)
    story = story_for(feed, "a", "Unrelated headline", "Nothing here.")
    second = feed.article("b", "Republished", "This one mentions OpenSSL.")
    second.story_id = story.id
    session.flush()
    assert filter_pending_stories(session).relevant == 1
