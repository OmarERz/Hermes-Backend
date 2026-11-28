"""Production steps of the pipeline (what the worker runs): the services of F1 to F6 behind the `Steps` seams.

Each builder fails closed: without the DeepSeek key there is no analyst and no judge (the cycles still ingest,
correlate and fall back to the base score); without the iTop identity there is no ticket lifecycle. Scoring is
F4.3 (`evaluate_group`, `recalculate_open_groups`, `EngineScorer`).
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from core.analysts.cve import CveOptions, analyze_pending_cves, web_advisory_provider
from core.analysts.news import NewsResult, analyze_pending
from core.correlation.packages import build_dismissal_package
from core.db import models as m
from core.ingestion.embeddings import EmbedFn
from core.ingestion.fetcher import Fetcher
from core.ingestion.pipeline import PipelineOptions, run_news_pipeline
from core.inventory.sync import sync_from_itop_unlocked_read
from core.itop.client import ItopReader
from core.llm import ToolCaller
from core.pipeline.cycles import NewsCycleOutput, ScanCycleOutput, TicketApplier
from core.pipeline.judging import PipelineJudge
from core.scan.engine import ScanOptions, run_scan
from core.scoring.evaluate import (
    EngineScorer,
    EvaluationOptions,
    GroupNotActiveError,
    evaluate_group,
    recalculate_open_groups,
)
from core.scoring.formula_repo import load_active_formula, load_formula
from core.vulndata.cna_discovery import CveOrgResult, Observed, clear_rejected, refresh_cve_org, restore_due
from core.vulndata.cvelist import CveOrgClient
from core.vulndata.epss import EpssResult, fetch_daily, load_epss
from core.vulndata.http import JsonSource
from core.vulndata.kev import KevResult, fetch_catalogue, load_kev
from core.vulndata.nvd import RECENCY_DAYS, LoadResult, NvdClient, parse_cve
from core.vulndata.records import CveRecord
from core.vulndata.store import store_cve

log = logging.getLogger(__name__)


def news_step(
    fetcher: Fetcher, embed: EmbedFn, analyst: ToolCaller | None
) -> Callable[[Session, str], NewsCycleOutput]:
    """F-05 + F-06: ingestion, deduplication, keyword filter, source health, then the analyst on pending stories."""

    def run(session: Session, trigger_reason: str) -> NewsCycleOutput:
        analyze = (lambda db: analyze_pending(db, analyst)) if analyst is not None else None
        result = run_news_pipeline(
            session, fetcher, embed, PipelineOptions(trigger_reason=trigger_reason, analyze=analyze)
        )
        run_id = session.scalar(
            select(m.Run.id).where(m.Run.kind == "news").order_by(m.Run.started_at.desc(), m.Run.id.desc()).limit(1)
        )
        analyzed = [r.story_id for r in result.analyses if isinstance(r, NewsResult) and r.status == "analyzed"]
        return NewsCycleOutput(run_id, analyzed)

    return run


def scan_step(
    factory: sessionmaker[Session], reader: ItopReader | None
) -> Callable[[uuid.UUID | None, str], ScanCycleOutput]:
    """F-02 + F-04: inventory refresh from iTop (when configured) and the simulated scan, on a queued run if given."""

    def run(run_id: uuid.UUID | None, reason: str) -> ScanCycleOutput:
        result = run_scan(factory, ScanOptions(reason=reason, run_id=run_id, reader=reader))
        return ScanCycleOutput(result.run_id)

    return run


def engine_evaluate(
    session: Session, group_id: uuid.UUID, run_id: uuid.UUID, trigger: str, judge: PipelineJudge | None
) -> uuid.UUID | None:
    """F4.3 `evaluate_group` with the pipeline's judge; the assessment to apply tickets with, if any.

    A group with no current finding left (every CI fixed), or whose score did not change, is not assessed again: its
    latest assessment is returned so the ticket lifecycle still applies CI changes and fixes (TIC-05). A group that
    closed while the judge answered keeps the stored review; the caller commits it.
    """
    try:  # a judge call commits the read transaction first and stores its review in a new one (F12.2 #105)
        evaluation = evaluate_group(session, group_id, run_id, trigger, EvaluationOptions(judge=judge))
    except GroupNotActiveError:
        return _latest_assessment(session, group_id)
    # Unchanged scores still go through the ticket rules (new CIs, fixes) with the assessment that stands.
    return evaluation.assessment_id or _latest_assessment(session, group_id)


def _latest_assessment(session: Session, group_id: uuid.UUID) -> uuid.UUID | None:
    return session.scalar(
        select(m.Assessment.id)
        .where(m.Assessment.finding_group_id == group_id)
        .order_by(m.Assessment.assessed_at.desc(), m.Assessment.id.desc())
        .limit(1)
    )


def engine_recalculate(tickets: TicketApplier | None) -> Callable[[Session], object]:
    """F-17 / COR-05: every open group with the formula and the clock, never the judge; tickets follow the scores."""

    def run(session: Session) -> object:
        return recalculate_open_groups(session, "nightly", EvaluationOptions(tickets=tickets))

    return run


def engine_recalculate_queued(tickets: TicketApplier | None) -> Callable[[Session, uuid.UUID], object]:
    """A queued formula-change request (FRO-08): the same recalculation, on the request's own run row, with the
    formula version the save created. A request whose version was replaced by a later save with another engine
    formula is superseded: that save queued its own pass, so this one has nothing left to do. A later save that
    kept the engine formula (a judge-reason switch, FRO-03) queued none, so the request runs with the version now
    active, which scores the same; checked here, after the claim, so a switch saved while the request waited or
    was being claimed never cancels it."""

    def run(session: Session, run_id: uuid.UUID) -> object:
        request = session.get_one(m.Run, run_id)
        try:
            version_id = request.formula_version_id
            active_id, active = load_active_formula(session)
            if version_id is not None and version_id != active_id and load_formula(session, version_id) == active:
                request.formula_version_id = version_id = active_id  # the run carries the version it applies (D-061)
            if version_id is None or version_id != active_id:
                _finish(session, request, "succeeded", 100)
                return None
            # One formula for the whole pass: every assessment of this run carries the run's version (D-061); a save
            # that lands mid-pass queues its own request, which re-evaluates with the newer version afterwards.
            options = EvaluationOptions(tickets=tickets, formula=(version_id, load_formula(session, version_id)))
        except Exception:
            session.rollback()
            _finish(session, session.get_one(m.Run, run_id), "failed", 0)  # never left running (ARQ-04)
            raise
        return recalculate_open_groups(session, "formula_change", options, run_id=run_id)

    return run


def _finish(session: Session, request: m.Run, status: str, progress: int) -> None:
    request.status, request.progress, request.finished_at = status, progress, datetime.now(UTC)
    session.commit()


def engine_dismissal_package(session: Session, story_id: uuid.UUID) -> dict[str, Any]:
    """The mode 2 package of a dismissal candidate, scored with the active formula (F4.3 `EngineScorer`)."""
    _, formula = load_active_formula(session)
    return build_dismissal_package(session, story_id, EngineScorer(formula))


NVD_BATCH = 200  # CVEs stored per transaction while the NVD pages are read
ROW_BATCH = 2_000  # KEV entries or EPSS rows stored per transaction
KEV_RECENT_DAYS = 7  # CISA entries of the last week without an NVD record are looked up by id first
KEV_LAG_MAX = 20  # at most this many lookups by id per refresh (the public NVD limit is 5 requests per 30 s)


def refresh_vulndata(
    factory: sessionmaker[Session], nvd: NvdClient, source: JsonSource, cve_org: CveOrgClient | None = None
) -> Callable[[], tuple[LoadResult, object, object, LoadResult, CveOrgResult]]:
    """ESC-09: the recent NVD publications (recency window), the KEV catalogue, the NVD records of every KEV CVE
    whatever its age (ESC-10: the window does not apply to KEV), today's EPSS scores and, last, the CVE.org records of
    the CVEs NIST has not enriched that may concern a mapped product (F15.9, D-103; `core.vulndata.cna_discovery`).

    No network call runs inside a database transaction: each download finishes first, then a short transaction
    stores it (NVD in batches of `NVD_BATCH`), so no write of the API ever waits on a download.
    """
    cve_org = cve_org or CveOrgClient(source)

    def run() -> tuple[LoadResult, object, object, LoadResult, CveOrgResult]:
        end = datetime.now(UTC)
        held = _held_versions(factory)  # before any write: what CVE.org's cache compares NVD's dates with
        observed = Observed()
        try:
            window = nvd.iter_published(end - timedelta(days=RECENCY_DAYS), end)
            nvd_result = _load_nvd(factory, window, observe=observed)
            kev_result = _in_batches(factory, load_kev, fetch_catalogue(source), KevResult())
            # Before EPSS: an EPSS outage must not keep the ranges of old KEV CVEs out of the next scan.
            kev_records = _load_kev_records(factory, nvd, end.date(), observe=observed)
            epss_result = _load_epss(factory, fetch_daily(source))
        except BaseException:
            # NVD may have re-dated or rejected records already and CVE.org did not run: their CNA records are asked
            # next time, and a CVE NVD rejected keeps no CNA range meanwhile.
            restore_due(factory, observed.sightings, None, held)
            clear_rejected(factory, observed.rejected)
            raise
        # Last: an outage of GitHub keeps CVE.org out of this refresh only (the step stops and logs it).
        cna_result = refresh_cve_org(factory, cve_org, observed, held)
        return nvd_result, kev_result, epss_result, kev_records, cna_result

    return run


def _load_nvd(
    factory: sessionmaker[Session],
    items: Iterable[dict[str, Any]],
    *,
    skip: Callable[[CveRecord], bool] | None = None,
    observe: Observed | None = None,
    in_window: bool = True,
) -> LoadResult:
    """Parse and store NVD entries in batches; `skip` leaves out records that need no write; `observe` collects the
    records without NVD configuration (the CVE.org candidates, F15.9), marked as from the recency window or not, the
    CNA of every record and the rejected ones."""
    result = LoadResult()
    batch: list[CveRecord] = []
    for item in items:
        if observe is not None:
            observe.see(item, in_window=in_window)
        record = parse_cve(item)
        if record is None:
            result.skipped += 1
            continue
        if skip is not None and skip(record):
            result.unchanged += 1
            continue
        batch.append(record)
        if len(batch) >= NVD_BATCH:
            _store_cves(factory, batch, result)
            batch = []
    _store_cves(factory, batch, result)
    return result


def _load_kev_records(
    factory: sessionmaker[Session], nvd: NvdClient, today: date, *, observe: Observed | None = None
) -> LoadResult:
    """The NVD record of every KEV CVE, so the scan can compare its ranges whatever its age (F20 dry run, P0-1).

    One query (`hasKev`, 2,000 records a page; about 1,800 in Nov 2026) brings them all, so the number of requests
    does not grow with the inventory; a record whose `lastModified` we already hold is not written again. Every KEV
    record is kept, not only those of mapped products: a product mapped later then matches at its next scan instead
    of after the next refresh. NVD mirrors CISA with a lag (the two entries CISA added on 27 Nov 2026 were not
    flagged yet that evening), so CISA entries still without an NVD record are looked up by id, at most
    `KEV_LAG_MAX` per refresh, in the order of `lookup_order`.
    """
    held = _held_versions(factory)

    def unchanged(record: CveRecord) -> bool:
        return record.last_modified_at is not None and held.get(record.cve_id) == record.last_modified_at

    result = _load_nvd(factory, nvd.iter_kev(), skip=unchanged, observe=observe, in_window=False)
    for cve_id in _kev_pending(factory, today):
        found = _load_nvd(factory, nvd.iter_cve(cve_id), observe=observe, in_window=False)
        result.stored, result.skipped = result.stored + found.stored, result.skipped + found.skipped
    return result


def _held_versions(factory: sessionmaker[Session]) -> dict[str, datetime]:
    """The `lastModified` of each CVE whose record we already hold (a few tens of thousands of short rows)."""
    with factory() as session:
        rows = session.execute(select(m.Cve.id, m.Cve.last_modified_at).where(m.Cve.fetched_at.is_not(None)))
        return {cve_id: modified for cve_id, modified in rows if modified is not None}


def _kev_pending(factory: sessionmaker[Session], today: date) -> list[str]:
    """The CISA entries without an NVD record to look up by id in this refresh."""
    with factory() as session:
        rows = session.execute(
            select(m.KevEntry.cve_id, m.KevEntry.date_added)
            .join(m.Cve, m.Cve.id == m.KevEntry.cve_id)
            .where(m.Cve.fetched_at.is_(None))
        ).all()
    return lookup_order([(cve_id, added) for cve_id, added in rows], today)


def lookup_order(pending: Sequence[tuple[str, date]], today: date, limit: int = KEV_LAG_MAX) -> list[str]:
    """At most `limit` CVE ids: the entries of the last `KEV_RECENT_DAYS` first (newest first, the usual NVD lag),
    then the older ones, never excluded: they rotate by day, so a stable list of n is fully asked in n / `limit`
    days (a fresh install or an outage can leave old entries NVD does not flag yet)."""
    since = today - timedelta(days=KEV_RECENT_DAYS)
    recent = sorted(((-added.toordinal(), cve) for cve, added in pending if added >= since))
    older = sorted(cve for cve, added in pending if added < since)
    if older:
        start = today.toordinal() * limit % len(older)
        older = older[start:] + older[:start]
    return ([cve for _, cve in recent] + older)[:limit]


class _Counted(Protocol):
    stored: int
    skipped: int


def _in_batches[R: _Counted](
    factory: sessionmaker[Session],
    load: Callable[[Session, list[dict[str, Any]]], R],
    rows: list[dict[str, Any]],
    total: R,
) -> R:
    """Store downloaded rows in short transactions of `ROW_BATCH` (the loaders upsert, so batches are independent)."""
    for start in range(0, len(rows), ROW_BATCH):
        with factory() as session, session.begin():
            part = load(session, rows[start : start + ROW_BATCH])
        total.stored += part.stored
        total.skipped += part.skipped
    return total


def _load_epss(factory: sessionmaker[Session], rows: list[dict[str, Any]]) -> EpssResult:
    """The daily file covers every published CVE: the local catalogue is read once and only its rows are stored."""
    with factory() as session:
        known = set(session.scalars(select(m.Cve.id)))
    ours = [row for row in rows if row.get("cve") in known]
    result = _in_batches(factory, lambda session, part: load_epss(session, part, known), ours, EpssResult())
    result.skipped += len(rows) - len(ours)
    return result


def _store_cves(factory: sessionmaker[Session], records: list[CveRecord], result: LoadResult) -> None:
    if not records:
        return
    with factory() as session, session.begin():
        for record in records:
            store_cve(session, record)
    result.stored += len(records)


def inventory_refresh(factory: sessionmaker[Session], reader: ItopReader) -> Callable[[], object]:
    """ARQ-03: the iTop cache every six hours (the scan refreshes it too); a failure leaves the cache as it was.

    One connection holds the sync lock at session level across the read and the write, so an older read never
    overwrites a newer one; iTop is read with no transaction open and only the write is a (short) transaction. The
    write takes the same key at transaction level, which is re-entrant on the same connection. A refresh that finds
    the lock taken (the scan is syncing) skips this round.
    """

    def run() -> object:
        result = sync_from_itop_unlocked_read(factory, reader, wait=False)
        if result is None:
            log.info("inventory refresh skipped: another inventory sync is running")
        return result

    return run


def cve_step(analyst: ToolCaller, fetcher: Fetcher) -> Callable[[Session], object]:
    """F-04 step 8 (F3.3): the CVE analyst on the pending CVEs of active groups, reading vendor advisories only from
    the allowed domains (`ADVISORY_DOMAINS`, default list in `core.analysts.cve`)."""
    options = CveOptions(advisory=web_advisory_provider(fetcher))

    def run(session: Session) -> object:
        return analyze_pending_cves(session, analyst, options)

    return run
