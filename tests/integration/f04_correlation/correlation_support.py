"""Synthetic stories with analyses for the correlation tests."""

from __future__ import annotations

import itertools
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id

NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
_counter = itertools.count(1)


def _unique(prefix: str) -> str:
    return f"{prefix}{next(_counter)}"


@dataclass
class StorySpec:
    cves: dict[str, str] = field(default_factory=dict)  # CVE id -> exploitation level
    products: list[tuple[str | None, str, str | None]] = field(default_factory=list)  # vendor, product, version
    vectors: list[str] = field(default_factory=list)
    victims: list[dict[str, Any]] = field(default_factory=list)
    actors: list[str] = field(default_factory=list)
    event_types: list[str] = field(default_factory=lambda: ["other"])
    hours_ago: float = 1.0
    source_code: str | None = None
    tier: str = "N3"
    title: str = "Synthetic news"


def add_story(session: Session, **fields: Any) -> m.Story:
    """A relevant story with an analysis, described by the fields of `StorySpec`."""
    spec = StorySpec(**fields)
    code = spec.source_code or _unique("outlet")
    source = session.scalars(select(m.Source).where(m.Source.code == code)).first()
    if source is None:
        source = m.Source(
            id=new_id(),
            code=code,
            name=code,
            kind="rss",
            url=f"https://{code}.example.com/feed",
            trust_tier=spec.tier,
            is_structural=False,
            is_custom=False,
            enabled=True,
            created_at=NOW,
        )
        session.add(source)
        run = m.Run(id=new_id(), kind="news", status="succeeded", progress=100, trigger_reason="manual")
        session.add(run)
        session.flush()
        session.add(
            m.SourceFetch(id=new_id(), source_id=source.id, run_id=run.id, started_at=NOW, status="ok", items_new=0)
        )
        session.flush()
    fetch = session.scalars(select(m.SourceFetch).where(m.SourceFetch.source_id == source.id)).first()
    assert fetch is not None
    article = m.RawArticle(
        id=new_id(),
        source_fetch_id=fetch.id,
        canonical_url=f"https://{code}.example.com/{_unique('n')}",
        title=spec.title,
        clean_text="Synthetic body.",
        published_at=NOW - timedelta(hours=spec.hours_ago),
        captured_at=NOW,
        is_suspicious=False,
    )
    session.add(article)
    session.flush()
    story = m.Story(id=new_id(), representative_article_id=article.id, relevance_status="relevant", created_at=NOW)
    session.add(story)
    session.flush()
    article.story_id = story.id
    review = m.LlmReview(
        id=new_id(),
        agent="news_analyst",
        model="test",
        response_model={},
        prompt_version="1",
        prompt_hash="h",
        schema_version="1",
        schema_hash="h",
        parameters={},
        input_ref=str(story.id),
        calls=[],
        status="applied",
        attempts=1,
        tokens_input=1,
        tokens_cached=0,
        tokens_output=1,
        tokens_reasoning=0,
        cost_usd=Decimal("0.001"),
        latency_ms=1,
        ladder_level=0,
        created_at=NOW,
    )
    session.add(review)
    session.flush()
    cve_levels = spec.cves
    analysis = m.NewsAnalysis(
        id=new_id(),
        story_id=story.id,
        llm_review_id=review.id,
        summary="Resumen sintético.",
        event_type=spec.event_types[0],
        output={
            "event_types": spec.event_types,
            "exploitation_level": "none",
            "cves": [{"cve": cve, "exploitation_level": level, "quote": "q"} for cve, level in cve_levels.items()],
        },
        created_at=NOW,
    )
    session.add(analysis)
    session.flush()
    for cve in cve_levels:
        session.add(m.NewsCveMention(analysis_id=analysis.id, cve_id=cve, quote="q"))
    for vendor, product, version in spec.products:
        session.add(
            m.NewsProductMention(
                id=new_id(), analysis_id=analysis.id, vendor=vendor, product=product, version=version, quote="q"
            )
        )
    for vector in spec.vectors:
        session.add(m.NewsAttackVector(analysis_id=analysis.id, vector_code=vector, quote="q"))
    for victim in spec.victims:
        session.add(m.NewsVictim(id=new_id(), analysis_id=analysis.id, quote="q", **victim))
    for name in spec.actors:
        actor = session.scalars(select(m.Actor).where(m.Actor.name == name)).first()
        if actor is None:
            actor = m.Actor(id=new_id(), name=name)
            session.add(actor)
            session.flush()
        session.add(m.NewsActorMention(analysis_id=analysis.id, actor_id=actor.id, quote="q"))
    session.flush()
    return story


def demo_group(session: Session) -> uuid.UUID:
    return session.scalars(select(m.FindingGroup.id)).one()


def add_group(session: Session, cve_id: str) -> m.FindingGroup:
    """Another active group on the demo product, with a finding on its first CI."""
    session.add(m.Cve(id=cve_id, description="Otra", cvss_score=Decimal("7.5"), cvss_version="3.1", fetched_at=NOW))
    session.flush()
    first = session.scalars(select(m.FindingGroup)).first()
    assert first is not None
    group = m.FindingGroup(id=new_id(), cve_id=cve_id, software_product_id=first.software_product_id, created_at=NOW)
    session.add(group)
    session.flush()
    inst = session.scalars(select(m.InstalledSoftware).order_by(m.InstalledSoftware.itop_instance_id)).first()
    run = session.scalars(select(m.Run).where(m.Run.kind == "scan")).first()
    assert inst is not None
    assert run is not None
    finding = m.Finding(
        id=new_id(), finding_group_id=group.id, installed_software_id=inst.id, match_source="nvd_cpe", created_at=NOW
    )
    session.add(finding)
    session.flush()
    session.add(
        m.FindingStatusChange(
            id=new_id(),
            finding_id=finding.id,
            run_id=run.id,
            status="new",
            observed_version=inst.version,
            changed_at=NOW,
        )
    )
    session.flush()
    return group
