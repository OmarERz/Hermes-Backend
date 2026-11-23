"""Production steps: the news step reports its run and analyzed stories; the scan step runs a queued request."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from core.analysts.news import NewsResult
from core.db import models as m
from core.ingestion.fetcher import Fetcher
from core.ingestion.pipeline import PipelineResult
from core.pipeline.wiring import inventory_refresh, news_step, refresh_vulndata, scan_step
from core.scan.engine import ScanResult
from doubles.web import FakeWeb

pytestmark = pytest.mark.integration


def fake_embed(texts: Any) -> list[list[float]]:
    return [[0.0] * 383 + [1.0] for _ in texts]


def test_the_news_step_runs_ingestion_and_reports_the_news_run(factory: sessionmaker[Session]) -> None:
    fetcher = Fetcher(transport=FakeWeb().transport(), resolver=lambda _h: ["93.184.216.34"])
    with factory() as session:
        output = news_step(fetcher, fake_embed, None)(session, "schedule")
        latest = session.scalar(select(m.Run.id).where(m.Run.kind == "news").order_by(m.Run.started_at.desc()).limit(1))
        session.rollback()
    assert latest is not None
    assert output.run_id == latest
    assert output.analyzed == []


def test_the_news_step_keeps_only_analyzed_stories(
    factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    analyzed, skipped = uuid.uuid4(), uuid.uuid4()
    seen: list[Any] = []

    def pipeline(session: Session, _fetcher: Any, _embed: Any, options: Any) -> PipelineResult:
        seen.append((options.trigger_reason, options.analyze is not None))
        results = [NewsResult(analyzed, "analyzed"), NewsResult(skipped, "budget"), "other"]
        return PipelineResult(ingested=[], placements=[], filtered=None, alerts=[], analyses=results)

    monkeypatch.setattr("core.pipeline.wiring.run_news_pipeline", pipeline)
    with factory() as session:
        output = news_step(Fetcher(), fake_embed, object())(session, "after_scan")
    assert output.analyzed == [analyzed]
    assert seen == [("after_scan", True)]


def test_the_scan_step_runs_on_the_queued_run(monkeypatch: pytest.MonkeyPatch, factory: sessionmaker[Session]) -> None:
    calls: list[Any] = []
    queued = uuid.uuid4()

    def scan(_factory: Any, options: Any) -> ScanResult:
        calls.append((options.run_id, options.reason, options.reader))
        return ScanResult(queued)

    monkeypatch.setattr("core.pipeline.wiring.run_scan", scan)
    assert scan_step(factory, None)(queued, "manual").run_id == queued
    assert calls == [(queued, "manual", None)]


def test_the_vulnerability_refresh_loads_nvd_kev_and_epss(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr("core.pipeline.wiring.load_nvd", lambda _s, _c: calls.append("nvd") or "n")
    monkeypatch.setattr("core.pipeline.wiring.fetch_catalogue", lambda _src: calls.append("kev-fetch") or [])
    monkeypatch.setattr("core.pipeline.wiring.load_kev", lambda _s, _e: calls.append("kev") or "k")
    monkeypatch.setattr("core.pipeline.wiring.refresh_epss", lambda _s, _src: calls.append("epss") or "e")
    assert refresh_vulndata(object(), object())(object()) == ("n", "k", "e")
    assert calls == ["nvd", "kev-fetch", "kev", "epss"]


def test_the_inventory_refresh_syncs_from_itop(factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Any] = []
    monkeypatch.setattr("core.pipeline.wiring.sync_from_itop", lambda _s, reader: seen.append(reader) or "synced")
    reader = object()
    assert inventory_refresh(factory, reader)() == "synced"
    assert seen == [reader]
