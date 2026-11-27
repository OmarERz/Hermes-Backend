"""F18.1: the static catalogue of the factory sources matches the default source list and the worker's schedule."""

from __future__ import annotations

import pytest

from core.ingestion.catalog import DEFAULT_SOURCES
from core.ingestion.source_info import NEWS_CYCLE_MINUTES, SOURCE_INFO, VULNDATA_REFRESH_MINUTES, source_info
from workers import pipeline_jobs

pytestmark = pytest.mark.unit


def test_every_factory_source_has_a_description_and_a_provider() -> None:
    assert set(SOURCE_INFO) == {source.code for source in DEFAULT_SOURCES}
    assert all(info.description and info.provider for info in SOURCE_INFO.values())


def test_news_feeds_follow_the_news_cycle_and_vulnerability_data_the_daily_refresh() -> None:
    for source in DEFAULT_SOURCES:
        period = SOURCE_INFO[source.code].refresh_interval_minutes
        if source.kind in {"rss", "atom"}:
            assert period == NEWS_CYCLE_MINUTES, source.code
    assert {
        code for code, info in SOURCE_INFO.items() if info.refresh_interval_minutes == VULNDATA_REFRESH_MINUTES
    } == {
        "nvd",
        "kev",
        "epss",
    }


def test_the_periods_are_the_workers_real_schedule() -> None:
    assert pipeline_jobs.NEWS_SECONDS == NEWS_CYCLE_MINUTES * 60
    assert pipeline_jobs.VULNDATA_SECONDS == VULNDATA_REFRESH_MINUTES * 60


def test_an_own_feed_has_no_text_and_the_news_period() -> None:
    info = source_info("my_feed")
    assert info.description is None and info.provider is None
    assert info.refresh_interval_minutes == NEWS_CYCLE_MINUTES
