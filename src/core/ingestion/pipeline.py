"""The ingestion flow end to end (docs/15 F-05): read, deduplicate, filter by keywords, check source health."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from sqlalchemy.orm import Session

from core.ingestion.embeddings import EmbedFn
from core.ingestion.entities import EntityProvider, regex_entities
from core.ingestion.fetcher import Fetcher
from core.ingestion.health import HealthAlert, check_source_health
from core.ingestion.keywords import FilterResult, filter_pending_stories
from core.ingestion.service import Clock, IngestResult, run_news_ingestion, utc_now
from core.ingestion.stories import Placement, group_new_articles


@dataclass(frozen=True)
class PipelineResult:
    ingested: list[IngestResult]
    placements: list[Placement]
    filtered: FilterResult
    alerts: list[HealthAlert]
    analyses: Sequence[object] = ()


@dataclass(frozen=True)
class PipelineOptions:
    trigger_reason: str = "schedule"
    clock: Clock = utc_now
    entities: EntityProvider = regex_entities
    analyze: Callable[[Session], Sequence[object]] | None = None  # the news analyst (F-05 step 7)


def run_news_pipeline(
    session: Session, fetcher: Fetcher, embed: EmbedFn, options: PipelineOptions | None = None
) -> PipelineResult:
    """Hourly and after each scan (ING-02): ingest, deduplicate, keyword filter, then source health."""
    options = options or PipelineOptions()
    ingested = run_news_ingestion(session, fetcher, options.trigger_reason, options.clock)
    placements = group_new_articles(session, embed, options.entities, options.clock)
    filtered = filter_pending_stories(session)
    alerts = check_source_health(session, options.clock)
    analyses = options.analyze(session) if options.analyze is not None else ()
    return PipelineResult(ingested=ingested, placements=placements, filtered=filtered, alerts=alerts, analyses=analyses)
