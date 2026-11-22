"""The simulated scan: match installed software against CVE data and keep the finding lifecycle (ESC-09 to ESC-17).

How a candidate (installed software, CVE) is found:
  - the product has a CPE mapping (ESC-05); unmapped products produce nothing and stay pending (ESC-07);
  - an NVD range (`nvd_cpe`, certainty 1.0) or a CNA range (`cna_affected`, 0.9) of the mapped vendor and product
    contains the installed version, compared locally (ESC-13); a version that cannot be compared is counted as a
    comparison error and never guessed (ESC-12);
  - a CVE in CISA KEV counts whatever its age; the others must be published within the recency window
    (ESC-10, TODO(P-003)) unless a finding for them already exists, so an old finding is never "fixed" by the
    window alone;
  - OSV can discard a candidate whose package version already carries the distribution's patch (ESC-11).
The lifecycle compares each finding with what this scan found (ESC-16): new, persistent, fixed, reopened, no_data
(the CI was not in this scan: never fixed). Only one scan runs at a time (partial unique index, ARQ-04); a scan that
died leaves its row `running` and `fail_stale_scans` closes it.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Collection
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from core.inventory.sync import sync_from_itop
from core.itop.client import ItopReader
from core.scan.versions import in_range
from core.vulndata.http import JsonSource
from core.vulndata.osv import OsvClient
from core.vulndata.records import CNA_AFFECTED, NVD_CPE

RECENCY_DAYS: Final = 90  # TODO(P-003): recency window of the scan (ESC-10), configurable later
STALE_AFTER: Final = timedelta(hours=2)
ACTIVE: Final = frozenset({"new", "persistent", "reopened"})
ONE_SCAN_INDEX: Final = "run_one_running_scan"
SCAN_LOCK_KEY: Final = 7_001_002  # session-level advisory lock held by the live scan
SOURCES: Final = ((NVD_CPE, "nvd_vendor", "nvd_product"), (CNA_AFFECTED, "cna_vendor", "cna_product"))


class ScanAlreadyRunningError(Exception):
    """Another scan is running (ARQ-04)."""


@dataclass
class ScanResult:
    run_id: uuid.UUID
    new: int = 0
    persistent: int = 0
    fixed: int = 0
    reopened: int = 0
    no_data: int = 0
    excluded: int = 0  # candidates discarded by OSV (backported patch)
    unmapped_products: int = 0
    compare_errors: int = 0
    candidates: int = 0


@dataclass
class _Found:
    matches: dict[uuid.UUID, dict[str, str]]  # installed software id -> {cve id: match source}
    evaluable: set[uuid.UUID]  # installs whose product is mapped: only these can be judged fixed
    uncertain: set[tuple[uuid.UUID, str]]  # (install, CVE) whose range could not be compared with the version


@dataclass
class _State:
    session: Session
    run_id: uuid.UUID
    now: datetime
    result: ScanResult
    osv: OsvClient | None
    recency_days: int
    osv_cache: dict[tuple[str, str, str, str], tuple[str, str | None]] = field(default_factory=dict)


def next_status(current: str, last_active: str | None, *, scanned: bool, present: bool) -> str | None:
    """The status a finding moves to after a scan, or None when nothing changes (ESC-16)."""
    if not scanned:
        return "no_data" if current in ACTIVE else None
    if present:
        if current == "fixed" or (current == "no_data" and last_active == "fixed"):
            return "reopened"
        return "persistent"
    return None if current == "fixed" else "fixed"


# --- run rows ------------------------------------------------------------------------------------------
def _create_run(
    factory: sessionmaker[Session], reason: str, triggered_by: uuid.UUID | None, now: datetime
) -> uuid.UUID:
    try:
        with factory() as session, session.begin():
            run = m.Run(
                kind="scan",
                status="running",
                progress=0,
                trigger_reason=reason,
                triggered_by=triggered_by,
                started_at=now,
            )
            session.add(run)
            session.flush()
            return run.id
    except IntegrityError as error:
        if ONE_SCAN_INDEX in str(error.orig):
            raise ScanAlreadyRunningError("a scan is already running") from None
        raise


def _update_run(factory: sessionmaker[Session], run_id: uuid.UUID, **values: Any) -> None:
    with factory() as session, session.begin():
        session.execute(update(m.Run).where(m.Run.id == run_id).values(**values))


def fail_stale_scans(session: Session, *, now: datetime | None = None, older_than: timedelta = STALE_AFTER) -> int:
    """Close scans left `running` by a process that died, so they stop blocking new ones.

    A live scan holds the session-level advisory lock for its whole run, so a row is only closed when the lock
    is free (nobody is running it) and the row is older than `older_than`.
    """
    now = now or datetime.now(UTC)
    if not session.scalar(select(func.pg_try_advisory_lock(SCAN_LOCK_KEY))):
        return 0  # a scan is alive
    try:
        closed = session.scalars(
            update(m.Run)
            .where(m.Run.kind == "scan", m.Run.status == "running", m.Run.started_at < now - older_than)
            .values(status="failed", finished_at=now)
            .returning(m.Run.id)
        )
        return len(closed.all())
    finally:
        session.execute(select(func.pg_advisory_unlock(SCAN_LOCK_KEY)))


@dataclass(frozen=True)
class ScanOptions:
    reason: str = "manual"  # schedule | manual | after_scan | formula_change
    triggered_by: uuid.UUID | None = None
    asset_ids: Collection[uuid.UUID] | None = None  # None = every live CI; the others end up no_data
    osv: OsvClient | None = None  # default: the real OSV API, asked only for packages with distribution data
    recency_days: int = RECENCY_DAYS
    reader: ItopReader | None = None  # refresh the inventory from iTop first (ARQ-03)


def run_scan(
    factory: sessionmaker[Session], options: ScanOptions | None = None, *, now: datetime | None = None
) -> ScanResult:
    """Run one scan, with its run row, progress and final status.

    The scan holds a session-level advisory lock on its own connection from start to finish (ARQ-04), so a crash
    frees it at once; the partial unique index on `run` is the second guard. Findings and the `succeeded` status
    are committed in one transaction: a scan that did not finish leaves no findings behind.
    """
    options = options or ScanOptions()
    started = now or datetime.now(UTC)
    bind = factory.kw["bind"]
    with bind.connect() as guard:
        if not guard.execute(select(func.pg_try_advisory_lock(SCAN_LOCK_KEY))).scalar():
            raise ScanAlreadyRunningError("a scan is already running")
        try:
            return _run_locked(factory, options, started)
        finally:
            guard.execute(select(func.pg_advisory_unlock(SCAN_LOCK_KEY)))


def _run_locked(factory: sessionmaker[Session], options: ScanOptions, started: datetime) -> ScanResult:
    run_id = _create_run(factory, options.reason, options.triggered_by, started)
    result = ScanResult(run_id)
    try:
        if options.reader is not None:
            with factory() as session, session.begin():
                sync_from_itop(session, options.reader, now=started)
        _update_run(factory, run_id, progress=30)
        with factory() as session, session.begin():
            state = _State(session, run_id, started, result, options.osv, options.recency_days)
            scope = set(options.asset_ids) if options.asset_ids is not None else None
            _evaluate(state, scope)
            session.execute(
                update(m.Run)
                .where(m.Run.id == run_id)
                .values(status="succeeded", progress=100, finished_at=datetime.now(UTC))
            )
    except BaseException:
        _update_run(factory, run_id, status="failed", finished_at=datetime.now(UTC))
        raise
    return result


# --- the scan itself -----------------------------------------------------------------------------------
def _evaluate(state: _State, scope: set[uuid.UUID] | None) -> None:
    session = state.session
    live = session.execute(
        select(m.InstalledSoftware, m.Asset)
        .join(m.Asset, m.Asset.id == m.InstalledSoftware.asset_id)
        .where(m.Asset.decommissioned_at.is_(None), m.InstalledSoftware.removed_at.is_(None))
    ).all()
    scanned = [inst for inst, asset in live if scope is None or asset.id in scope]
    existing = _existing_findings(session)
    known = {(f.installed_software_id, g.cve_id) for f, g in existing.values()}
    found = _candidates(state, scanned, known)
    state.result.candidates = sum(len(c) for c in found.matches.values())
    _apply_lifecycle(state, existing, found, scope=scope)
    _create_new(state, found.matches, known, scanned)


def _existing_findings(session: Session) -> dict[uuid.UUID, tuple[m.Finding, m.FindingGroup]]:
    rows = session.execute(select(m.Finding, m.FindingGroup).join(m.FindingGroup)).all()
    return {finding.id: (finding, group) for finding, group in rows}


def _candidates(state: _State, scanned: list[m.InstalledSoftware], existing_keys: set[tuple[uuid.UUID, str]]) -> _Found:
    """What this scan finds, and which installs it was able to judge."""
    session = state.session
    mappings = {row.software_product_id: row for row in session.scalars(select(m.CpeMapping))}
    pairs = {
        (source, str(getattr(row, vendor)).lower(), str(getattr(row, product)).lower())
        for row in mappings.values()
        for source, vendor, product in SOURCES
        if getattr(row, vendor) and getattr(row, product)
    }
    index: dict[tuple[str, str, str], list[tuple[m.CveAffectedRange, datetime | None]]] = defaultdict(list)
    vendors = {vendor for _, vendor, _ in pairs}
    if vendors:
        ranges = session.execute(
            select(m.CveAffectedRange, m.Cve.published_at)
            .join(m.Cve, m.Cve.id == m.CveAffectedRange.cve_id)
            .where(func.lower(m.CveAffectedRange.vendor).in_(vendors))
        )
        for rng, published in ranges:
            key = (rng.source, rng.vendor.lower(), rng.product.lower())
            if key in pairs:
                index[key].append((rng, published))
    kev = set(session.scalars(select(m.KevEntry.cve_id)))
    cutoff = state.now - timedelta(days=state.recency_days)
    found = _Found({}, set(), set())
    unmapped: set[uuid.UUID] = set()
    for inst in scanned:
        mapping = mappings.get(inst.software_product_id)
        if mapping is None:
            unmapped.add(inst.software_product_id)
            continue
        found.evaluable.add(inst.id)
        matches: dict[str, str] = {}
        for source, vendor_col, product_col in SOURCES:
            vendor, product = getattr(mapping, vendor_col), getattr(mapping, product_col)
            if not vendor or not product:
                continue
            for rng, published in index.get((source, vendor.lower(), product.lower()), []):
                recent = published is not None and published >= cutoff
                if not (recent or rng.cve_id in kev or (inst.id, rng.cve_id) in existing_keys):
                    continue  # outside the recency window and not already tracked
                inside = in_range(
                    inst.version, rng.version_start, rng.start_inclusive, rng.version_end, rng.end_inclusive
                )
                if inside is None:
                    state.result.compare_errors += 1
                    found.uncertain.add((inst.id, rng.cve_id))
                    continue
                if not inside:
                    continue
                matches[rng.cve_id] = _prefer(matches.get(rng.cve_id), source, rng.cve_id in kev)
        kept = {cve: src for cve, src in matches.items() if not _backported(state, inst, cve)}
        if kept:
            found.matches[inst.id] = kept
    state.result.unmapped_products = len(unmapped)
    return found


def _prefer(current: str | None, source: str, in_kev: bool) -> str:
    """nvd_cpe over kev over cna_affected (certainty 1.0, 1.0, 0.9)."""
    if NVD_CPE in (current, source):
        return NVD_CPE
    return "kev" if in_kev else CNA_AFFECTED


def _backported(state: _State, inst: m.InstalledSoftware, cve_id: str) -> bool:
    """Ask OSV whether the distribution already fixed this CVE in the installed package version (ESC-11)."""
    if not (inst.package_name and inst.package_ecosystem and inst.package_version):
        return False
    if state.osv is None:
        state.osv = OsvClient(JsonSource())  # the real OSV API; tests always inject a double
    key = (cve_id, inst.package_name, inst.package_ecosystem, inst.package_version)
    if key not in state.osv_cache:
        state.osv_cache[key] = state.osv.backport_evidence(*key)
    status, osv_id = state.osv_cache[key]
    if status != "fixed" or osv_id is None:
        return False
    session = state.session
    known = session.scalar(
        select(m.FindingExclusion.id).where(
            m.FindingExclusion.installed_software_id == inst.id, m.FindingExclusion.cve_id == cve_id
        )
    )
    if known is None:
        session.add(
            m.FindingExclusion(
                installed_software_id=inst.id,
                cve_id=cve_id,
                run_id=state.run_id,
                reason="backported_patch",
                osv_id=osv_id,
                decided_at=state.now,
            )
        )
        state.result.excluded += 1
    return True


def _history(session: Session, finding_ids: list[uuid.UUID]) -> dict[uuid.UUID, list[str]]:
    history: dict[uuid.UUID, list[str]] = defaultdict(list)
    if finding_ids:
        rows = session.execute(
            select(m.FindingStatusChange.finding_id, m.FindingStatusChange.status)
            .where(m.FindingStatusChange.finding_id.in_(finding_ids))
            .order_by(m.FindingStatusChange.changed_at, m.FindingStatusChange.id)
        )
        for finding_id, status in rows:
            history[finding_id].append(status)
    return history


def _record(state: _State, finding: m.Finding, status: str, version: str) -> None:
    state.session.add(
        m.FindingStatusChange(
            finding_id=finding.id, run_id=state.run_id, status=status, observed_version=version, changed_at=state.now
        )
    )
    setattr(state.result, status, getattr(state.result, status) + 1)


def _apply_lifecycle(
    state: _State,
    existing: dict[uuid.UUID, tuple[m.Finding, m.FindingGroup]],
    found: _Found,
    *,
    scope: set[uuid.UUID] | None,
) -> None:
    session = state.session
    history = _history(session, list(existing))
    installs = {
        i.id: (i, a)
        for i, a in session.execute(
            select(m.InstalledSoftware, m.Asset).join(m.Asset, m.Asset.id == m.InstalledSoftware.asset_id)
        )
    }
    for finding_id, (finding, group) in existing.items():
        inst, asset = installs[finding.installed_software_id]
        if asset.decommissioned_at is not None or not history[finding_id]:
            continue  # a decommissioned CI no longer counts (ARQ-03)
        in_scope = scope is None or asset.id in scope
        # an instance that left iTop was in the scan and is simply gone: it ends up fixed
        was_scanned = in_scope and (inst.id in found.evaluable or inst.removed_at is not None)
        present = group.cve_id in found.matches.get(inst.id, {})
        statuses = history[finding_id]
        if was_scanned and not present and (inst.id, group.cve_id) in found.uncertain:
            continue  # a version we could not compare is not evidence that the CVE is gone (ESC-13)
        last_active = next((s for s in reversed(statuses) if s != "no_data"), None)
        new_status = next_status(statuses[-1], last_active, scanned=was_scanned, present=present)
        if new_status is not None:
            _record(state, finding, new_status, inst.version)


def _create_new(
    state: _State,
    candidates: dict[uuid.UUID, dict[str, str]],
    known: set[tuple[uuid.UUID, str]],
    scanned: list[m.InstalledSoftware],
) -> None:
    session = state.session
    groups = {(g.cve_id, g.software_product_id): g for g in session.scalars(select(m.FindingGroup))}
    for inst in scanned:
        for cve_id, source in sorted(candidates.get(inst.id, {}).items()):
            if (inst.id, cve_id) in known:
                continue
            group = groups.get((cve_id, inst.software_product_id))
            if group is None:
                group = m.FindingGroup(
                    cve_id=cve_id, software_product_id=inst.software_product_id, created_at=state.now
                )
                session.add(group)
                session.flush()
                groups[(cve_id, inst.software_product_id)] = group
            finding = m.Finding(
                finding_group_id=group.id, installed_software_id=inst.id, match_source=source, created_at=state.now
            )
            session.add(finding)
            session.flush()
            _record(state, finding, "new", inst.version)
