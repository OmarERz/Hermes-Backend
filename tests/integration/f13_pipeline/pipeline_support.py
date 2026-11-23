"""Helpers of the pipeline tests: scripted judge answers and a minimal story (no third-party text)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id
from doubles.llm import LlmDouble, tool_call_completion
from harness.judge import double_llm_client

NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
MASS = {
    "reason_code": "mass_exploitation",
    "direction": "up",
    "points": 10,
    "evidence_id": "news-1",
    "quote": "Researchers observed mass exploitation of CVE-2026-1111",
    "explanation": "Explotación masiva reciente.",
}


def judge_caller(*answers: dict[str, Any]) -> tuple[Any, LlmDouble]:
    """The real strict client on the LLM double with the given scripted completions (never real tokens)."""
    double = LlmDouble()
    double.add_case("case", list(answers))
    double.use("case")
    return double_llm_client(double), double


def one_reason_review() -> list[dict[str, Any]]:
    return [
        tool_call_completion("propose_reason", MASS, call_id="a"),
        tool_call_completion("finalize_review", {"summary": "Resumen.", "mitigation_steps": []}, call_id="f"),
    ]


def make_story(session: Session) -> uuid.UUID:
    """source → fetch → article → story, for the package and alert foreign keys."""
    source = m.Source(
        id=new_id(),
        code=f"synthetic-{uuid.uuid4().hex[:8]}",
        name="Synthetic media",
        kind="rss",
        url="https://media.example.test/feed",
        trust_tier="N3",
        is_structural=False,
        is_custom=False,
        enabled=True,
        created_at=NOW,
    )
    session.add(source)
    session.flush()
    run_id = session.scalars(select(m.Run.id).limit(1)).one()
    fetch = m.SourceFetch(id=new_id(), source_id=source.id, run_id=run_id, started_at=NOW, status="ok", items_new=1)
    session.add(fetch)
    session.flush()
    article = m.RawArticle(
        id=new_id(),
        source_fetch_id=fetch.id,
        canonical_url=f"https://media.example.test/{uuid.uuid4().hex}",
        title="Synthetic advisory",
        published_at=NOW,
        captured_at=NOW,
        is_suspicious=False,
    )
    session.add(article)
    session.flush()
    story = m.Story(id=new_id(), representative_article_id=article.id, relevance_status="relevant", created_at=NOW)
    session.add(story)
    session.flush()
    article.story_id = story.id
    session.flush()
    return story.id
