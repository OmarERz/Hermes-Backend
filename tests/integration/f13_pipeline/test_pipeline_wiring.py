"""Production steps: the news step reports its run and analyzed stories; the scan step runs a queued request."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, NamedTuple, cast

import pytest
from pipeline_support import make_story
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from core.analysts.news import NewsResult
from core.db import models as m
from core.ingestion.embeddings import EmbeddingError
from core.ingestion.fetcher import Fetcher
from core.ingestion.pipeline import PipelineResult
from core.inventory.sync import SYNC_LOCK_KEY, EmptyInventoryError
from core.itop.inventory import InventorySnapshot
from core.pipeline.cycles import Pipeline, Steps
from core.pipeline.wiring import cve_step, inventory_refresh, news_step, refresh_vulndata, scan_step
from core.scan.engine import ScanResult
from core.vulndata.epss import EpssResult
from core.vulndata.kev import KevResult
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


class Tracking:
    """A session factory that knows how many sessions are open: downloads must run with none."""

    def __init__(self, factory: sessionmaker[Session]) -> None:
        self.factory, self.kw, self.open = factory, factory.kw, 0

    @contextmanager
    def __call__(self) -> Iterator[Session]:
        with self.factory() as session:
            self.open += 1
            try:
                yield session
            finally:
                self.open -= 1


class Parsed(NamedTuple):
    """What the refresh reads of a parsed NVD record."""

    n: int
    cve_id: str
    last_modified_at: None


def test_the_vulnerability_refresh_downloads_outside_transactions(
    factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    tracking = Tracking(factory)
    calls: list[Any] = []

    class Nvd:
        def iter_published(self, _start: Any, _end: Any) -> Iterator[dict[str, int]]:
            for n in range(5):
                assert tracking.open == 0, "an NVD page is read inside a transaction"
                yield {"n": n}

        def iter_kev(self) -> Iterator[dict[str, int]]:
            for n in (10, 11):
                assert tracking.open == 0, "the NVD KEV page is read inside a transaction"
                yield {"n": n}

        def iter_cve(self, cve_id: str) -> Iterator[dict[str, int]]:
            assert tracking.open == 0, "an NVD record is read inside a transaction"
            calls.append(("by id", cve_id))
            yield from ()

    def download(name: str, result: Any) -> Any:
        def fetch(_source: Any) -> Any:
            assert tracking.open == 0, f"{name} is downloaded inside a transaction"
            calls.append(name)
            return result

        return fetch

    monkeypatch.setattr("core.pipeline.wiring.NVD_BATCH", 2)
    monkeypatch.setattr("core.pipeline.wiring.ROW_BATCH", 2)
    monkeypatch.setattr(
        "core.pipeline.wiring.parse_cve",
        lambda item: None if item["n"] == 2 else Parsed(item["n"], f"CVE-2026-9{item['n']:04d}", None),
    )
    monkeypatch.setattr(
        "core.pipeline.wiring.store_cve", lambda _s, record: calls.append(("cve", tracking.open, record.n))
    )

    def loader(name: str, result: type[Any]) -> Any:
        def load(_session: Session, rows: list[Any], *_known: Any) -> Any:
            calls.append((name, tracking.open, rows))
            return result(stored=len(rows))

        return load

    monkeypatch.setattr("core.pipeline.wiring.fetch_catalogue", download("kev", ["k1", "k2", "k3"]))
    monkeypatch.setattr("core.pipeline.wiring.load_kev", loader("kev-load", KevResult))
    monkeypatch.setattr(
        "core.pipeline.wiring.fetch_daily", download("epss", [{"cve": "CVE-2026-10001"}, {"cve": "CVE-1999-0001"}])
    )
    monkeypatch.setattr("core.pipeline.wiring.load_epss", loader("epss-load", EpssResult))
    monkeypatch.setattr("core.pipeline.wiring._kev_pending", lambda _factory, _today: ["CVE-2026-0777"])
    nvd, kev, epss, kev_records, cve_org = refresh_vulndata(
        cast("sessionmaker[Session]", tracking), cast("Any", Nvd()), cast("Any", None)
    )()
    assert cve_org.fetched == 0  # no mapping has CNA names here: CVE.org is not asked (F15.9)
    assert (nvd.stored, nvd.skipped, kev.stored, epss.stored, epss.skipped) == (4, 1, 3, 1, 1)
    assert kev_records.stored == 2
    assert calls == [
        ("cve", 1, 0),
        ("cve", 1, 1),
        ("cve", 1, 3),
        ("cve", 1, 4),
        "kev",
        ("kev-load", 1, ["k1", "k2"]),
        ("kev-load", 1, ["k3"]),
        ("cve", 1, 10),  # every KEV record NVD holds, whatever its age (ESC-09/10), before EPSS
        ("cve", 1, 11),
        ("by id", "CVE-2026-0777"),  # a CISA entry NVD does not flag yet
        "epss",
        ("epss-load", 1, [{"cve": "CVE-2026-10001"}]),  # only the CVEs of the local catalogue
    ]


def open_transactions(factory: sessionmaker[Session]) -> int:
    with factory() as session:
        return int(
            session.scalar(
                text(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()"
                    " AND state LIKE 'idle in transaction%' AND pid <> pg_backend_pid()"
                )
            )
            or 0
        )


def test_the_inventory_refresh_reads_itop_outside_a_transaction(
    factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Any] = []

    def read(reader: Any) -> str:
        seen.append((reader, open_transactions(factory)))
        return "snapshot"

    monkeypatch.setattr("core.inventory.sync.read_inventory", read)
    monkeypatch.setattr("core.inventory.sync.sync_inventory", lambda _s, snapshot, **_kw: f"synced {snapshot}")
    reader = object()
    assert inventory_refresh(factory, cast("Any", reader))() == "synced snapshot"
    assert seen == [(reader, 0)]
    assert lock_is_free(factory)


def test_the_inventory_refresh_frees_the_lock_on_failure_and_skips_when_busy(
    factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("core.inventory.sync.read_inventory", lambda _r: InventorySnapshot())
    # The real write takes the same key per transaction (re-entrant on the same connection), then refuses to
    # decommission the whole seeded inventory.
    with pytest.raises(EmptyInventoryError):
        inventory_refresh(factory, cast("Any", None))()
    assert lock_is_free(factory)
    with factory.kw["bind"].connect() as other:
        other.execute(select(func.pg_advisory_lock(SYNC_LOCK_KEY)))
        try:
            assert inventory_refresh(factory, cast("Any", None))() is None
        finally:
            other.execute(select(func.pg_advisory_unlock(SYNC_LOCK_KEY)))
            other.commit()


def lock_is_free(factory: sessionmaker[Session]) -> bool:
    with factory.kw["bind"].connect() as conn:
        free = bool(conn.execute(select(func.pg_try_advisory_lock(SYNC_LOCK_KEY))).scalar())
        if free:
            conn.execute(select(func.pg_advisory_unlock(SYNC_LOCK_KEY)))
        conn.commit()
        return free


def test_the_cve_step_runs_the_analyst_with_the_advisory_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Any] = []
    monkeypatch.setattr(
        "core.pipeline.wiring.analyze_pending_cves",
        lambda session, client, options: seen.append((session, client, options.advisory is not None)) or ["done"],
    )
    analyst, session = object(), object()
    assert cve_step(analyst, Fetcher())(session) == ["done"]
    assert seen == [(session, analyst, True)]


def test_with_the_embeddings_service_down_articles_wait_for_the_next_cycle(factory: sessionmaker[Session]) -> None:
    """Fail closed: the article stays stored without a story, and the next cycle with the service up groups it."""
    fetcher = Fetcher(transport=FakeWeb().transport(), resolver=lambda _h: ["93.184.216.34"])
    with factory() as session, session.begin():
        story = session.get_one(m.Story, make_story(session))
        article = session.get_one(m.RawArticle, story.representative_article_id)
        article_id, article.story_id = article.id, None  # stored by the ingestion, not grouped yet

    def down(_texts: Any) -> list[list[float]]:
        raise EmbeddingError("The embeddings service is unavailable: no answer (ConnectError)")

    pipeline = Pipeline(factory, Steps(news=news_step(fetcher, down, None)))
    report = pipeline.news_cycle()
    assert report.failures == 1
    assert report.notes == [
        "news deduplication skipped: The embeddings service is unavailable: no answer (ConnectError)"
    ]
    with factory() as session:
        assert session.get_one(m.RawArticle, article_id).story_id is None
    assert Pipeline(factory, Steps(news=news_step(fetcher, fake_embed, None))).news_cycle().failures == 0
    with factory() as session:
        assert session.get_one(m.RawArticle, article_id).story_id is not None
