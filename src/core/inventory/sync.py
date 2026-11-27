"""Save an iTop inventory snapshot into the cache tables, idempotently (ESC-04, ARQ-03).

Rows are matched by their iTop id. Whatever disappears from iTop is soft-deleted (`removed_at`,
`decommissioned_at`) and comes back if it reappears; nothing is hard-deleted, so findings keep their history.
The caller owns the transaction. Fields that are ours and not iTop's are never overwritten:
`team.is_default` (P-020), `installed_software.package_name` and `package_ecosystem` (OSV, F1.4) and the whole
`cpe_mapping`.
Licences (F18.3) link to a product only when it is already known from an installation: a licence never creates a
product, so licensed but uninstalled software does not show up as pending CPE mapping (ESC-07).
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from core.inventory.version import normalize_version
from core.itop.client import ItopReader
from core.itop.inventory import InventorySnapshot, read_inventory

SYNC_LOCK_KEY: Final = 7_001_001  # advisory lock: one inventory sync at a time (ARQ-04 adds the scan locks in F1.4)


class EmptyInventoryError(Exception):
    """iTop returned no CIs and no teams while the cache has live ones: more likely a bad read than an empty CMDB."""


@dataclass
class Counts:
    created: int = 0
    updated: int = 0
    removed: int = 0


@dataclass
class SyncResult:
    teams: Counts = field(default_factory=Counts)
    persons: Counts = field(default_factory=Counts)
    assets: Counts = field(default_factory=Counts)
    products: Counts = field(default_factory=Counts)
    instances: Counts = field(default_factory=Counts)
    licences: Counts = field(default_factory=Counts)
    warnings: list[str] = field(default_factory=list)


@dataclass
class _Run:
    session: Session
    snapshot: InventorySnapshot
    now: datetime
    result: SyncResult


def _soft_delete(rows: Mapping[str, object], seen: set[str], column: str, run: _Run, counts: Counts) -> None:
    for key, row in rows.items():
        if key not in seen and getattr(row, column) is None:
            setattr(row, column, run.now)
            counts.removed += 1


def sync_inventory(
    session: Session, snapshot: InventorySnapshot, *, now: datetime | None = None, allow_empty: bool = False
) -> SyncResult:
    """Apply `snapshot` to the cache. Flushes but does not commit."""
    run = _Run(session, snapshot, now or datetime.now(UTC), SyncResult(warnings=list(snapshot.warnings)))
    _lock(session)
    if not allow_empty and not snapshot.assets and not snapshot.teams:
        live = session.scalar(select(m.Asset.id).where(m.Asset.decommissioned_at.is_(None)).limit(1))
        if live is not None:
            raise EmptyInventoryError("iTop returned an empty inventory; refusing to decommission the whole cache")

    team_ids = _sync_teams(run)
    person_ids = _sync_persons(run)
    asset_ids = _sync_assets(run, person_ids, team_ids)
    installed = _sync_instances(run, asset_ids)
    licences = _sync_licences(run)
    _link_licences(run, installed, licences)
    session.flush()
    return run.result


def _lock(session: Session) -> None:
    """Serialize syncs; transaction-scoped and re-entrant, so taking it twice in one transaction is fine."""
    session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": SYNC_LOCK_KEY})


def sync_from_itop_unlocked_read(
    factory: sessionmaker[Session], reader: ItopReader, *, now: datetime | None = None, wait: bool = True
) -> SyncResult | None:
    """Read iTop with no transaction open, then apply it in a short transaction (pending #106).

    One connection holds the sync lock at session level across the read and the write, so an older read never
    overwrites a newer one, and the slow iTop read keeps no snapshot nor transaction lock in PostgreSQL. The write
    takes the same key at transaction level, which is re-entrant on the same connection. `wait=False` returns None
    at once when another sync holds the lock. An iTop failure raises before anything is written.
    """
    with factory.kw["bind"].connect() as conn:
        if wait:
            conn.execute(select(func.pg_advisory_lock(SYNC_LOCK_KEY)))
            acquired = True
        else:
            acquired = bool(conn.execute(select(func.pg_try_advisory_lock(SYNC_LOCK_KEY))).scalar())
        conn.commit()
        if not acquired:
            return None
        try:
            snapshot = read_inventory(reader)
            with Session(bind=conn) as session:
                result = sync_inventory(session, snapshot, now=now)
                session.commit()
            return result
        finally:
            conn.rollback()
            conn.execute(select(func.pg_advisory_unlock(SYNC_LOCK_KEY)))
            conn.commit()


def sync_from_itop(session: Session, reader: ItopReader, *, now: datetime | None = None) -> SyncResult:
    """Read iTop, then apply it. The lock is taken before reading, so an older read cannot overwrite a newer one.

    An iTop failure raises before anything is written.
    """
    _lock(session)
    return sync_inventory(session, read_inventory(reader), now=now)


def _sync_teams(run: _Run) -> dict[str, uuid.UUID]:
    rows = {t.itop_team_id: t for t in run.session.scalars(select(m.Team))}
    counts = run.result.teams
    for item in run.snapshot.teams:
        row = rows.get(item.itop_id)
        if row is None:
            row = m.Team(itop_team_id=item.itop_id, is_default=False)  # P-020: the default team is chosen elsewhere
            run.session.add(row)
            rows[item.itop_id] = row
            counts.created += 1
        else:
            counts.updated += 1
        row.name, row.synced_at, row.removed_at = item.name, run.now, None
    _soft_delete(rows, {t.itop_id for t in run.snapshot.teams}, "removed_at", run, counts)
    run.session.flush()
    return {key: row.id for key, row in rows.items() if row.removed_at is None}


def _sync_persons(run: _Run) -> dict[str, uuid.UUID]:
    rows = {p.itop_person_id: p for p in run.session.scalars(select(m.Person))}
    counts = run.result.persons
    for item in run.snapshot.persons:
        row = rows.get(item.itop_id)
        if row is None:
            row = m.Person(itop_person_id=item.itop_id)
            run.session.add(row)
            rows[item.itop_id] = row
            counts.created += 1
        else:
            counts.updated += 1
        row.name, row.email, row.synced_at, row.removed_at = item.name, item.email, run.now, None
    _soft_delete(rows, {p.itop_id for p in run.snapshot.persons}, "removed_at", run, counts)
    run.session.flush()
    return {key: row.id for key, row in rows.items() if row.removed_at is None}


def _reference(kind: str, ci_id: str, itop_id: str | None, known: dict[str, uuid.UUID], run: _Run) -> uuid.UUID | None:
    if itop_id is None:
        return None
    if itop_id not in known:
        run.result.warnings.append(f"CI {ci_id}: {kind} {itop_id} is not in the inventory read, left empty")
        return None
    return known[itop_id]


def _sync_assets(run: _Run, person_ids: dict[str, uuid.UUID], team_ids: dict[str, uuid.UUID]) -> dict[str, uuid.UUID]:
    rows = {a.itop_ci_id: a for a in run.session.scalars(select(m.Asset))}
    counts = run.result.assets
    for item in run.snapshot.assets:
        row = rows.get(item.itop_id)
        if row is None:
            row = m.Asset(itop_ci_id=item.itop_id)
            run.session.add(row)
            rows[item.itop_id] = row
            counts.created += 1
        else:
            counts.updated += 1
        row.itop_class, row.name, row.ip, row.os = item.itop_class, item.name, item.ip, item.os
        row.criticality, row.exposed = item.criticality, item.exposed
        row.confidentiality, row.personal_data = item.confidentiality, item.personal_data
        row.owner_person_id = _reference("owner", item.itop_id, item.owner_itop_id, person_ids, run)
        row.custodian_team_id = _reference("custodian", item.itop_id, item.custodian_itop_id, team_ids, run)
        row.description, row.cpu, row.ram = item.description, item.cpu, item.ram
        row.synced_at, row.decommissioned_at = run.now, None
    _soft_delete(rows, {a.itop_id for a in run.snapshot.assets}, "decommissioned_at", run, counts)
    run.session.flush()
    return {key: row.id for key, row in rows.items() if row.decommissioned_at is None}


def _sync_instances(run: _Run, asset_ids: dict[str, uuid.UUID]) -> dict[str, m.InstalledSoftware]:
    """Apply the instances; returns the rows iTop still has, by iTop id (for the licence link)."""
    snapshot, session = run.snapshot, run.session
    catalogue = {s.itop_id: s for s in snapshot.software}
    products = {p.itop_name: p for p in session.scalars(select(m.SoftwareProduct))}
    rows = {i.itop_instance_id: i for i in session.scalars(select(m.InstalledSoftware))}
    seen: set[str] = set()
    written: dict[str, m.InstalledSoftware] = {}
    for item in snapshot.instances:
        software = catalogue.get(item.software_itop_id or "")
        asset_id = asset_ids.get(item.system_itop_id or "")
        if software is None or asset_id is None:
            run.result.warnings.append(f"Software instance {item.itop_id}: no host or product, skipped")
            continue
        product = products.get(software.name)
        if product is None:  # known even without a version, so it shows up as unmapped (ESC-07)
            product = m.SoftwareProduct(itop_name=software.name, first_seen_at=run.now)
            session.add(product)
            products[software.name] = product
            run.result.products.created += 1
            session.flush()
        version = normalize_version(software.version or "")
        row = rows.get(item.itop_id)
        if version is None:
            seen.add(item.itop_id)  # still in iTop: an unknown version is no evidence that it was uninstalled
            run.result.warnings.append(f"Software instance {item.itop_id}: no version, skipped (ESC-12)")
            if row is not None:  # its last version stays, but what iTop says of it now is shown (F18.3)
                row.itop_class, row.status, row.description = item.category, item.status, item.description
                written[item.itop_id] = row
            continue
        if row is None:
            row = m.InstalledSoftware(itop_instance_id=item.itop_id)
            session.add(row)
            rows[item.itop_id] = row
            run.result.instances.created += 1
        else:
            run.result.instances.updated += 1
        row.asset_id = asset_id
        if row.software_product_id != product.id:
            if row.software_product_id is None or not _has_findings(session, row):
                row.software_product_id = product.id
            else:  # the product is locked once findings exist (trigger check_product_locked)
                run.result.warnings.append(f"Software instance {item.itop_id}: product changed in iTop, kept")
        row.version, row.package_version = version.version, version.package_version
        row.itop_class, row.status, row.description = item.category, item.status, item.description
        row.synced_at, row.removed_at = run.now, None
        seen.add(item.itop_id)
        written[item.itop_id] = row
    _soft_delete(rows, seen, "removed_at", run, run.result.instances)
    session.flush()
    return written


def _sync_licences(run: _Run) -> dict[str, m.SoftwareLicence]:
    """Apply the licences; returns the live ones by iTop id. The product comes from the catalogue by name."""
    session, counts = run.session, run.result.licences
    catalogue = {s.itop_id: s.name for s in run.snapshot.software}
    products = {p.itop_name: p.id for p in session.scalars(select(m.SoftwareProduct))}
    rows = {lic.itop_licence_id: lic for lic in session.scalars(select(m.SoftwareLicence))}
    for item in run.snapshot.licences:
        row = rows.get(item.itop_id)
        if row is None:
            row = m.SoftwareLicence(itop_licence_id=item.itop_id)
            session.add(row)
            rows[item.itop_id] = row
            counts.created += 1
        else:
            counts.updated += 1
        row.software_product_id = products.get(catalogue.get(item.software_itop_id or "", ""))
        row.name, row.usage_limit, row.perpetual = item.name, item.usage_limit, item.perpetual
        row.start_date, row.end_date = item.start_date, item.end_date
        row.synced_at, row.removed_at = run.now, None
    _soft_delete(rows, {lic.itop_id for lic in run.snapshot.licences}, "removed_at", run, counts)
    session.flush()
    return {key: row for key, row in rows.items() if row.removed_at is None}


def _link_licences(
    run: _Run, installed: dict[str, m.InstalledSoftware], licences: dict[str, m.SoftwareLicence]
) -> None:
    """Point each written installation at its live licence, as iTop says (X-3); a mismatch is only warned."""
    for item in run.snapshot.instances:
        row = installed.get(item.itop_id)
        if row is None:
            continue
        licence = licences.get(item.licence_itop_id or "")
        if item.licence_itop_id is not None and licence is None:
            run.result.warnings.append(
                f"Software instance {item.itop_id}: licence {item.licence_itop_id} is not in the inventory read, "
                "left empty"
            )
        elif licence is not None and licence.software_product_id not in (None, row.software_product_id):
            run.result.warnings.append(
                f"Software instance {item.itop_id}: licence {item.licence_itop_id} is for another software, kept"
            )
        row.software_licence_id = licence.id if licence is not None else None


def _has_findings(session: Session, instance: m.InstalledSoftware) -> bool:
    found = session.scalar(select(m.Finding.id).where(m.Finding.installed_software_id == instance.id).limit(1))
    return found is not None
