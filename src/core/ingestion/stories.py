"""Group articles into stories with the dedup layers of ING-05 (D-023).

Layer 1 (canonical URL) already holds at storage time: `raw_article.canonical_url` is unique, so the same URL never
becomes two articles. Here an article without a story goes through, in order:

- layer 2: same set of CVEs and same event type as a story inside the window;
- layer 3: embedding similarity at or above `dedup.similarity` against a story inside the window (pgvector);
- layer 4: same victim and same actor, for attacks without CVE (needs analyst entities; inactive by default);
- layer 5: similarity in the gray zone (`dedup.gray_zone` up to `dedup.similarity`) decided with the analyst entities,
  without another model call; with no analyst entities a gray-zone pair stays as two stories.

A story keeps every URL and takes its date from its oldest article; republications across outlets are one story,
hence one source for the independent-sources rule. A text that matches nothing starts a new story.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.orm import Session, aliased

from core.db import models as m
from core.db.ids import new_id
from core.ingestion.embeddings import EMBEDDING_MODEL, EmbedFn, check_vectors, embedding_input
from core.ingestion.entities import (
    ArticleEntities,
    EntityProvider,
    entities_agree,
    regex_entities,
    same_attack,
    same_event,
)
from core.ingestion.service import Clock, utc_now
from core.ingestion.settings import get_decimal, get_int

log = logging.getLogger("ingestion")

BATCH_LIMIT = 500
DEDUP_LOCK_KEY = 20_260_222  # arbitrary key of the transaction-level advisory lock held while grouping


@dataclass(frozen=True)
class DedupSettings:
    window_hours: int
    similarity: Decimal
    gray_zone: Decimal


@dataclass(frozen=True)
class Placement:
    """Where an article went. `layer` is `new` for a new story, else the layer that grouped it."""

    article_id: uuid.UUID
    story_id: uuid.UUID
    layer: str
    similarity: Decimal | None = None


def load_settings(session: Session) -> DedupSettings:
    return DedupSettings(
        window_hours=get_int(session, "dedup.window_hours"),
        similarity=get_decimal(session, "dedup.similarity"),
        gray_zone=get_decimal(session, "dedup.gray_zone"),
    )


def _window(article: m.RawArticle, settings: DedupSettings) -> tuple[datetime, datetime]:
    span = timedelta(hours=settings.window_hours)
    return article.published_at - span, article.published_at + span


def _window_stories(
    session: Session, article: m.RawArticle, settings: DedupSettings
) -> list[tuple[m.Story, m.RawArticle]]:
    rep = aliased(m.RawArticle)
    low, high = _window(article, settings)
    stmt = (
        select(m.Story, rep)
        .join(rep, rep.id == m.Story.representative_article_id)
        .where(rep.published_at.between(low, high))
        .order_by(rep.published_at, m.Story.id)
    )
    return [(story, rep_article) for story, rep_article in session.execute(stmt)]


GRAY_NEIGHBORS = 10


def _neighbors(
    session: Session, article: m.RawArticle, vector: list[float], settings: DedupSettings
) -> list[tuple[m.Story, Decimal]]:
    """Stories in the window at or above the gray-zone similarity, most similar first."""
    rep = aliased(m.RawArticle)
    low, high = _window(article, settings)
    distance = m.Story.embedding.cosine_distance(vector)
    stmt = (
        select(m.Story, distance)
        .join(rep, rep.id == m.Story.representative_article_id)
        .where(
            m.Story.embedding.is_not(None),
            rep.published_at.between(low, high),
            distance <= float(Decimal(1) - settings.gray_zone),
        )
        .order_by(distance)
        .limit(GRAY_NEIGHBORS)
    )
    return [(story, Decimal(1) - Decimal(str(dist))) for story, dist in session.execute(stmt)]


def join_story(session: Session, article: m.RawArticle, story: m.Story) -> None:
    article.story_id = story.id
    if story.relevance_status == "filtered":
        story.relevance_status = "pending"  # a new article may name something the first one did not: decide again
    representative = session.get(m.RawArticle, story.representative_article_id)
    if representative is not None and article.published_at < representative.published_at:
        story.representative_article_id = article.id  # the story takes its date from its oldest article
    session.flush()


def _new_story(session: Session, article: m.RawArticle, vector: list[float], model: str, clock: Clock) -> m.Story:
    story = m.Story(
        id=new_id(),
        representative_article_id=article.id,
        embedding=vector,
        embedding_model=model,
        relevance_status="pending",
        created_at=clock(),
    )
    session.add(story)
    session.flush()
    article.story_id = story.id
    session.flush()
    return story


@dataclass(frozen=True)
class _Context:
    session: Session
    settings: DedupSettings
    entities: EntityProvider
    model: str
    clock: Clock


def _place(ctx: _Context, article: m.RawArticle, vector: list[float]) -> Placement:
    session = ctx.session
    mine = ctx.entities(article.title, article.clean_text)
    candidates = _window_stories(session, article, ctx.settings)
    cache: dict[uuid.UUID, ArticleEntities] = {}

    def entities_of(story: m.Story, rep: m.RawArticle) -> ArticleEntities:
        if story.id not in cache:
            cache[story.id] = ctx.entities(rep.title, rep.clean_text)
        return cache[story.id]

    for story, rep in candidates:  # layer 2
        if same_event(mine, entities_of(story, rep)):
            join_story(session, article, story)
            return Placement(article.id, story.id, "cve_event")
    neighbors = _neighbors(session, article, vector, ctx.settings)
    if neighbors and neighbors[0][1] >= ctx.settings.similarity:  # layer 3
        join_story(session, article, neighbors[0][0])
        return Placement(article.id, neighbors[0][0].id, "similarity", neighbors[0][1])
    for story, rep in candidates:  # layer 4
        if same_attack(mine, entities_of(story, rep)):
            join_story(session, article, story)
            return Placement(article.id, story.id, "attack")
    by_id = {story.id: rep for story, rep in candidates}
    for story, similarity in neighbors:  # layer 5: gray zone, decided by the entities; every neighbor is checked
        if entities_agree(mine, entities_of(story, by_id[story.id])):
            join_story(session, article, story)
            return Placement(article.id, story.id, "gray_zone", similarity)
    story = _new_story(session, article, vector, ctx.model, ctx.clock)
    return Placement(article.id, story.id, "new")


def group_new_articles(
    session: Session,
    embed: EmbedFn,
    entities: EntityProvider = regex_entities,
    clock: Clock = utc_now,
    embedding_model: str = EMBEDDING_MODEL,
) -> list[Placement]:
    """Assign every article without a story to a story; commits at the end."""
    # One grouping at a time: two runs reading the same pending articles would each open a story for them.
    if not session.scalar(select(func.pg_try_advisory_xact_lock(DEDUP_LOCK_KEY))):
        log.info("dedup: another run is grouping; skipped")
        return []
    settings = load_settings(session)
    pending = list(
        session.scalars(
            select(m.RawArticle)
            .where(m.RawArticle.story_id.is_(None))
            .order_by(m.RawArticle.published_at, m.RawArticle.id)
            .limit(BATCH_LIMIT)
        )
    )
    if not pending:
        return []
    vectors = check_vectors(embed([embedding_input(a.title, a.clean_text) for a in pending]), len(pending))
    ctx = _Context(session, settings, entities, embedding_model, clock)
    placements = [_place(ctx, article, vector) for article, vector in zip(pending, vectors, strict=True)]
    session.commit()
    log.info("dedup: %d articles, %d new stories", len(placements), sum(p.layer == "new" for p in placements))
    return placements
