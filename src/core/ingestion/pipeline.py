"""The ingestion flow end to end (docs/15 F-04): read the sources, then group the new articles into stories."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from core.ingestion.embeddings import EmbedFn
from core.ingestion.entities import EntityProvider, regex_entities
from core.ingestion.fetcher import Fetcher
from core.ingestion.service import Clock, IngestResult, run_news_ingestion, utc_now
from core.ingestion.stories import Placement, group_new_articles


@dataclass(frozen=True)
class PipelineResult:
    ingested: list[IngestResult]
    placements: list[Placement]


@dataclass(frozen=True)
class PipelineOptions:
    trigger_reason: str = "schedule"
    clock: Clock = utc_now
    entities: EntityProvider = regex_entities


def run_news_pipeline(
    session: Session, fetcher: Fetcher, embed: EmbedFn, options: PipelineOptions | None = None
) -> PipelineResult:
    """Hourly and after each scan (ING-02): ingest, then deduplicate before the keyword filter."""
    options = options or PipelineOptions()
    ingested = run_news_ingestion(session, fetcher, options.trigger_reason, options.clock)
    placements = group_new_articles(session, embed, options.entities, options.clock)
    return PipelineResult(ingested=ingested, placements=placements)
