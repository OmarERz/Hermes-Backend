"""Save CVE records into `cve` and its child tables, idempotently.

Two sources write the same CVE: NVD (`origin = "nvd"`) and CVE.org (`"cna"`). Their data lives side by side:
affected ranges are kept per source (`nvd_cpe`, `cna_affected`) and replaced as a whole by the source that owns
them; references, CWEs and tags only grow. For single-valued fields NVD wins (its CVSS and description replace
the CNA's) and the CNA only fills what is empty. The caller owns the transaction.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db import models as m
from core.vulndata.records import CNA_AFFECTED, NVD_CPE, CveRecord, RangeRecord, WorkaroundRecord

RANGE_SOURCE: Final = {"nvd": NVD_CPE, "cna": CNA_AFFECTED}


def store_cve(session: Session, record: CveRecord, *, now: datetime | None = None) -> None:
    now = now or datetime.now(UTC)
    row = session.get(m.Cve, record.cve_id)
    if row is None:
        row = m.Cve(id=record.cve_id)
        session.add(row)
    row.fetched_at = now
    if record.description and (row.description is None or record.origin == "nvd"):
        row.description = record.description
    row.published_at = record.published_at or row.published_at
    if record.last_modified_at and (row.last_modified_at is None or record.last_modified_at > row.last_modified_at):
        row.last_modified_at = record.last_modified_at
    has_cvss = record.cvss_score is not None and record.cvss_source and record.cvss_version
    if has_cvss and (row.cvss_source in {None, record.cvss_source} or record.cvss_source == "nvd"):
        row.cvss_version, row.cvss_vector = record.cvss_version, record.cvss_vector
        row.cvss_score, row.cvss_source = record.cvss_score, record.cvss_source
    session.flush()
    _store_cwes(session, record)
    _store_references(session, record)
    _store_ranges(session, record)
    _store_workarounds(session, record)
    session.flush()


def _store_cwes(session: Session, record: CveRecord) -> None:
    known = set(session.scalars(select(m.CveCwe.cwe_id).where(m.CveCwe.cve_id == record.cve_id)))
    for cwe in dict.fromkeys(record.cwes):
        if cwe not in known:
            session.add(m.CveCwe(cve_id=record.cve_id, cwe_id=cwe))


def _store_references(session: Session, record: CveRecord) -> None:
    existing = {r.url: r for r in session.scalars(select(m.CveReference).where(m.CveReference.cve_id == record.cve_id))}
    for ref in record.references:
        row = existing.get(ref.url)
        if row is None:
            row = m.CveReference(cve_id=record.cve_id, url=ref.url)
            session.add(row)
            session.flush()
            existing[ref.url] = row
        known = set(session.scalars(select(m.CveReferenceTag.tag).where(m.CveReferenceTag.reference_id == row.id)))
        for tag in dict.fromkeys(ref.tags):
            if tag not in known:
                session.add(m.CveReferenceTag(reference_id=row.id, tag=tag))


def _store_ranges(session: Session, record: CveRecord) -> None:
    """Make this source's ranges equal the record's, touching only the rows that differ (stable ids)."""
    source = RANGE_SOURCE[record.origin]
    wanted = set(record.ranges)
    for row in session.scalars(
        select(m.CveAffectedRange).where(
            m.CveAffectedRange.cve_id == record.cve_id, m.CveAffectedRange.source == source
        )
    ):
        key = RangeRecord(
            source, row.vendor, row.product, row.version_start, row.start_inclusive, row.version_end, row.end_inclusive
        )
        if key in wanted:
            wanted.discard(key)
        else:
            session.delete(row)
    for item in wanted:
        session.add(
            m.CveAffectedRange(
                cve_id=record.cve_id,
                source=item.source,
                vendor=item.vendor,
                product=item.product,
                version_start=item.version_start,
                start_inclusive=item.start_inclusive,
                version_end=item.version_end,
                end_inclusive=item.end_inclusive,
            )
        )


def _store_workarounds(session: Session, record: CveRecord) -> None:
    if record.origin != "cna":
        return
    wanted = set(record.workarounds)
    for row in session.scalars(
        select(m.CveWorkaround).where(m.CveWorkaround.cve_id == record.cve_id, m.CveWorkaround.source == "cna")
    ):
        key = WorkaroundRecord(row.text, row.source, row.source_url)
        if key in wanted:
            wanted.discard(key)
        else:
            session.delete(row)
    for item in wanted:
        session.add(
            m.CveWorkaround(cve_id=record.cve_id, text=item.text, source=item.source, source_url=item.source_url)
        )
