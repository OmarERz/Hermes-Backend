"""Synthetic stories and recorded model answers for the analyst tests."""

from __future__ import annotations

import copy
import itertools
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id

NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
_counter = itertools.count(1)

ARTICLE_TEXT = (
    "Acme Firewall appliances are being attacked through CVE-2026-1111. The vendor says there is no evidence "
    "of exploitation of CVE-2026-2222. The Lockbit group, also known as ABCD, hit Globex Hospital in Mexico. "
    "Attackers abuse the exposed management service."
)

NEWS_OUTPUT: dict[str, Any] = {
    "news_id": "",
    "event_types": ["active_exploitation", "organization_attack"],
    "exploitation_level": "active",
    "is_retrospective": False,
    "is_roundup": False,
    "cves": [
        {"cve": "CVE-2026-1111", "exploitation_level": "active", "quote": "attacked through CVE-2026-1111"},
        {
            "cve": "CVE-2026-2222",
            "exploitation_level": "denied",
            "quote": "no evidence of exploitation of CVE-2026-2222",
        },
    ],
    "products": [
        {
            "vendor": "Acme",
            "product": "Firewall",
            "candidate_cpe": "acme:firewall",
            "affected_versions": "",
            "quote": "Acme Firewall appliances",
        }
    ],
    "actors": [{"name": "Lockbit", "aliases": ["ABCD"], "quote": "The Lockbit group"}],
    "malware": [],
    "victims": [
        {"name": "Globex Hospital", "sector": "healthcare", "country": "mx", "quote": "hit Globex Hospital in Mexico"}
    ],
    "vector": "Exposed management service",
    "conditions": [],
    "signals": {"public_poc": True, "no_patch": False, "ransomware_use": False, "mass_exploitation": False},
    "out_of_taxonomy": False,
    "summary": "Resumen sintético.",
    "confidence": 0.8,
}


def news_output(story_id: object, **changes: Any) -> dict[str, Any]:
    output = copy.deepcopy(NEWS_OUTPUT)
    output["news_id"] = str(story_id)
    output.update(changes)
    return output


def add_cves(session: Session, *cve_ids: str) -> None:
    for cve_id in cve_ids:
        if session.get(m.Cve, cve_id) is None:
            session.add(m.Cve(id=cve_id, description="synthetic", fetched_at=NOW))
    session.flush()


def add_story(session: Session, text: str | None = ARTICLE_TEXT, relevance: str = "relevant") -> m.Story:
    code = f"outlet{next(_counter)}"
    source = m.Source(
        id=new_id(), code=code, name=code, kind="rss", url=f"https://{code}.example.com/feed", trust_tier="N3",
        is_structural=False, is_custom=False, enabled=True, created_at=NOW,
    )  # fmt: skip
    run = m.Run(id=new_id(), kind="news", status="succeeded", progress=100, trigger_reason="manual")
    session.add_all([source, run])
    session.flush()
    fetch = m.SourceFetch(id=new_id(), source_id=source.id, run_id=run.id, started_at=NOW, status="ok", items_new=1)
    session.add(fetch)
    session.flush()
    article = m.RawArticle(
        id=new_id(),
        source_fetch_id=fetch.id,
        canonical_url=f"https://{code}.example.com/a",
        title="Synthetic headline",
        clean_text=text,
        published_at=NOW,
        captured_at=NOW,
        is_suspicious=False,
    )
    session.add(article)
    session.flush()
    story = m.Story(id=new_id(), representative_article_id=article.id, relevance_status=relevance, created_at=NOW)
    session.add(story)
    session.flush()
    article.story_id = story.id
    session.flush()
    return story
