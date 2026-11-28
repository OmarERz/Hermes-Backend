"""Grouped views of the vulnerabilities (D-038, FRO-09 to FRO-11): by group, by urgency band and by CI.

The backend resolves the grouping; the front only paints it. A group's score is the highest final among the CIs
that speak for it (the current ones; every one when the group is fixed). A CI's risk is the highest final of its
findings: scores are never summed (FRO-11). Pages are cut with a keyset (the sort values of the last row).

The scored findings are aggregated in memory: one query, then plain Python. It is enough for the prototype's
inventory; a much larger one would move the aggregation into a view.
"""

from __future__ import annotations

import uuid
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import date, datetime
from decimal import Decimal
from typing import Final

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.scoring.engine import cvss_level
from core.views.common import (
    LEVELS,
    ScoredFinding,
    ci_url,
    most_pressing,
    most_restrictive,
    scored_findings,
    speaking,
)

ScoreKey = tuple[int, uuid.UUID]  # (score, id) of the last row of a page, highest score first

_ASSET: Final = text(
    "SELECT a.id, a.itop_ci_id, a.name, a.confidentiality, pe.name AS owner, t.name AS custodian, "
    "a.itop_class, a.description, a.cpu, a.ram, "
    "a.criticality, a.exposed, a.personal_data, a.os, a.service, a.synced_at "
    "FROM asset a LEFT JOIN team t ON t.id = a.custodian_team_id "
    "LEFT JOIN person pe ON pe.id = a.owner_person_id "
    "WHERE a.itop_ci_id = :ci AND a.decommissioned_at IS NULL"
)
# Live installations of a CI with their iTop category, status, description and live licence (F18.3, D-088)
_ASSET_SOFTWARE: Final = text(
    "SELECT p.itop_name AS software, i.version, i.itop_class AS category, i.status, i.description, "
    "l.name AS licence_name, l.usage_limit, l.start_date, l.end_date, l.perpetual "
    "FROM installed_software i JOIN software_product p ON p.id = i.software_product_id "
    "LEFT JOIN software_licence l ON l.id = i.software_licence_id AND l.removed_at IS NULL "
    "WHERE i.asset_id = :asset AND i.removed_at IS NULL "
    "ORDER BY p.itop_name, i.version, i.itop_instance_id"
)


@dataclass(frozen=True)
class Filters:
    """FRO-10 filters; every one optional. Dates bound `last_seen`, both ends included."""

    band: str | None = None
    custodian: str | None = None
    owner: str | None = None
    classification: str | None = None
    exposed: bool | None = None
    in_kev: bool | None = None
    status: str | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None

    def seen_in_range(self, last_seen: datetime) -> bool:
        return (self.date_from is None or last_seen >= self.date_from) and (
            self.date_to is None or last_seen <= self.date_to
        )


@dataclass(frozen=True)
class Group:
    group_id: uuid.UUID
    cve: str
    product: str
    ci_count: int
    custodians: list[str]
    tickets: list[str]
    final: int
    level: str
    in_kev: bool
    owners: list[str]
    classification: str
    exposed: bool
    status: str
    last_seen: datetime
    description: str | None
    cvss: Decimal | None = None  # the CVSS its score used (rehearsal 2 P2-D); None without one
    severity: str | None = None  # ESC-14: critical | high | medium | low | unrated (no CVSS); None for a CVSS of 0.0


@dataclass(frozen=True)
class AssetRisk:
    asset_id: uuid.UUID
    ci_id: str
    name: str
    risk: int
    level: str
    findings_by_level: dict[str, int]
    in_kev: int
    classification: str
    owner: str | None
    custodian: str | None
    exposed: bool
    status: str
    last_seen: datetime


@dataclass(frozen=True)
class AffectedAsset:
    ci_id: str
    name: str
    itop_url: str
    owner: str | None
    custodian: str | None
    criticality: str
    exposed: bool
    classification: str
    classification_at_evaluation: str
    finding_status: str
    score: int
    finding_id: uuid.UUID | None = None  # the scan finding of this CI in the group (GET /api/findings/{id}/history)


@dataclass(frozen=True)
class Licence:
    name: str
    usage_limit: str | None
    start_date: date | None
    end_date: date | None
    perpetual: bool


@dataclass(frozen=True)
class AssetSoftware:
    software: str
    version: str
    category: str | None  # the installation's iTop class; None until synced or for a custom class
    status: str | None  # active | inactive | None (no data); only shown, never filters the scan
    description: str | None
    licence: Licence | None


@dataclass(frozen=True)
class AssetDetail:
    ci_id: str
    name: str
    risk: int
    classification: str
    owner: str | None
    custodian: str | None
    findings: list[Group]  # group fields, with `final`, `level`, `status` and `last_seen` of this CI (D-035)
    # F18.3 (D-088): iTop data, stored and shown as given (free text is data, never instructions)
    itop_class: str | None = None
    description: str | None = None
    cpu: str | None = None
    ram: str | None = None
    software: tuple[AssetSoftware, ...] = ()
    # F18.6: the CI's inventory fields, the same values `GET /api/inventory/assets` gives for it
    criticality: str | None = None
    exposed: bool | None = None
    personal_data: bool | None = None
    os: str | None = None
    service: str | None = None
    synced_at: datetime | None = None
    itop_url: str | None = None


def _top(rows: Sequence[ScoredFinding]) -> ScoredFinding:
    """The highest final; ties go to the CI name so the choice is stable."""
    return max(sorted(rows, key=lambda r: (r.asset_name, str(r.asset_id))), key=lambda r: r.final)


def severity(cvss: Decimal | None) -> str | None:
    """ESC-14 (`schemas/finding.schema.json`): the CVSS level, or `unrated` without a CVSS; None for a CVSS of 0.0,
    which has no level in the scale."""
    if cvss is None:
        return "unrated"
    level = cvss_level(cvss)
    return level if level in LEVELS else None


def _group(rows: Sequence[ScoredFinding]) -> Group:
    voice = speaking(rows)
    top, first = _top(voice), rows[0]
    return Group(
        group_id=first.group_id,
        cve=first.cve,
        product=first.product,
        ci_count=sum(1 for r in rows if r.is_current),
        custodians=sorted({r.custodian for r in voice if r.custodian}),
        tickets=first.tickets,
        final=top.final,
        level=top.level,
        in_kev=first.in_kev,
        owners=sorted({r.owner for r in voice if r.owner}),
        classification=most_restrictive([r.classification for r in voice]),
        exposed=any(r.exposed for r in voice),
        status=most_pressing([r.status for r in rows]),
        last_seen=max(r.last_seen for r in rows),
        description=first.description,
        cvss=top.cvss,
        severity=severity(top.cvss),
    )


def _asset_risk(rows: Sequence[ScoredFinding]) -> AssetRisk:
    voice = speaking(rows)
    top, first = _top(voice), rows[0]
    return AssetRisk(
        asset_id=first.asset_id,
        ci_id=first.ci_id,
        name=first.asset_name,
        risk=top.final,
        level=top.level,
        findings_by_level=dict.fromkeys(LEVELS, 0) | dict(Counter(r.level for r in voice)),
        in_kev=sum(1 for r in voice if r.in_kev),
        classification=first.classification,
        owner=first.owner,
        custodian=first.custodian,
        exposed=first.exposed,
        status=most_pressing([r.status for r in rows]),
        last_seen=max(r.last_seen for r in rows),
    )


def _by[K](rows: Iterable[ScoredFinding], key: Callable[[ScoredFinding], K]) -> list[list[ScoredFinding]]:
    buckets: dict[K, list[ScoredFinding]] = defaultdict(list)
    for row in rows:
        buckets[key(row)].append(row)
    return list(buckets.values())


def _group_matches(g: Group, f: Filters) -> bool:
    return (
        (f.band is None or g.level == f.band)
        and (f.custodian is None or f.custodian in g.custodians)
        and (f.owner is None or f.owner in g.owners)
        and (f.classification is None or g.classification == f.classification)
        and (f.exposed is None or g.exposed == f.exposed)
        and (f.in_kev is None or g.in_kev == f.in_kev)
        and (f.status is None or g.status == f.status)
        and f.seen_in_range(g.last_seen)
    )


def _asset_matches(a: AssetRisk, f: Filters) -> bool:
    return (
        (f.band is None or a.level == f.band)
        and (f.custodian is None or a.custodian == f.custodian)
        and (f.owner is None or a.owner == f.owner)
        and (f.classification is None or a.classification == f.classification)
        and (f.exposed is None or a.exposed == f.exposed)
        and (f.in_kev is None or (a.in_kev > 0) == f.in_kev)
        and (f.status is None or a.status == f.status)
        and f.seen_in_range(a.last_seen)
    )


def page_by_score[T](
    items: Iterable[T], key: Callable[[T], ScoreKey], after: ScoreKey | None, limit: int
) -> tuple[list[T], ScoreKey | None]:
    """Highest score first, ties by id; resume after `after`; the next key is the last row kept, if more remain."""

    def order(item: T) -> tuple[int, uuid.UUID]:
        score, ident = key(item)
        return -score, ident

    ordered = sorted(items, key=order)
    if after is not None:
        start = (-after[0], after[1])
        ordered = [item for item in ordered if order(item) > start]
    kept = ordered[:limit]
    return kept, (key(kept[-1]) if len(ordered) > limit else None)


def filtered_groups(session: Session, filters: Filters) -> list[Group]:
    groups = [_group(rows) for rows in _by(scored_findings(session), lambda r: r.group_id)]
    return [g for g in groups if _group_matches(g, filters)]


def list_groups(
    session: Session, filters: Filters, *, after: ScoreKey | None, limit: int
) -> tuple[list[Group], ScoreKey | None, dict[str, int]]:
    """A page of groups by final (highest first), the next key, and the group count per band of the whole result."""
    groups = filtered_groups(session, filters)
    counts = dict.fromkeys(LEVELS, 0) | dict(Counter(g.level for g in groups))
    page, next_key = page_by_score(groups, lambda g: (g.final, g.group_id), after, limit)
    return page, next_key, counts


def list_assets(
    session: Session, filters: Filters, *, after: ScoreKey | None, limit: int
) -> tuple[list[AssetRisk], ScoreKey | None]:
    """A page of CIs by risk (highest first) and the next key."""
    assets = [_asset_risk(rows) for rows in _by(scored_findings(session), lambda r: r.asset_id)]
    matching = [a for a in assets if _asset_matches(a, filters)]
    return page_by_score(matching, lambda a: (a.risk, a.asset_id), after, limit)


def group_detail(
    session: Session, group_id: uuid.UUID, itop_base_url: str | None
) -> tuple[Group, list[AffectedAsset]] | None:
    """A group with every scored CI, highest score first; None if the group has no scored finding."""
    rows = scored_findings(session, group_id=group_id)
    if not rows:
        return None
    ordered = sorted(rows, key=lambda r: (-r.final, r.asset_name, str(r.asset_id)))
    assets = [
        AffectedAsset(
            ci_id=r.ci_id,
            name=r.asset_name,
            itop_url=ci_url(itop_base_url, r.itop_class, r.ci_id),
            owner=r.owner,
            custodian=r.custodian,
            criticality=r.criticality,
            exposed=r.exposed,
            classification=r.classification,
            classification_at_evaluation=r.snap_confidentiality,
            finding_status=r.status,
            score=r.final,
            finding_id=r.finding_id,
        )
        for r in ordered
    ]
    return _group(rows), assets


def asset_detail(session: Session, itop_ci_id: str, itop_base_url: str | None = None) -> AssetDetail | None:
    """A live CI with its scored findings, highest score first; None if the CI is unknown or decommissioned.

    Its inventory fields and link to iTop are the ones the inventory list gives (F18.6)."""
    if "\x00" in itop_ci_id:  # PostgreSQL text cannot hold it, so no CI has it
        return None
    asset = session.execute(_ASSET, {"ci": itop_ci_id}).one_or_none()
    if asset is None:
        return None
    own = scored_findings(session, asset_id=asset.id)
    findings: list[Group] = []
    for row in own:
        group = _group(scored_findings(session, group_id=row.group_id))
        findings.append(
            replace(
                group,
                final=row.final,
                level=row.level,
                status=row.status,
                last_seen=row.last_seen,
                cvss=row.cvss,  # the CVSS of this CI's own assessment, the one its score comes from
                severity=severity(row.cvss),
            )
        )
    findings.sort(key=lambda g: (-g.final, g.cve, str(g.group_id)))
    return AssetDetail(
        ci_id=asset.itop_ci_id,
        name=asset.name,
        risk=_top(speaking(own)).final if own else 0,
        classification=asset.confidentiality,
        owner=asset.owner,
        custodian=asset.custodian,
        findings=findings,
        itop_class=asset.itop_class,
        description=asset.description,
        cpu=asset.cpu,
        ram=asset.ram,
        software=asset_software(session, asset.id),
        criticality=asset.criticality,
        exposed=asset.exposed,
        personal_data=asset.personal_data,
        os=asset.os,
        service=asset.service,
        synced_at=asset.synced_at,
        itop_url=ci_url(itop_base_url, asset.itop_class, asset.itop_ci_id),
    )


def asset_software(session: Session, asset_id: uuid.UUID) -> tuple[AssetSoftware, ...]:
    """The CI's live installations, by product and version (F18.3)."""
    return tuple(
        AssetSoftware(
            software=r.software,
            version=r.version,
            category=r.category,
            status=r.status,
            description=r.description,
            licence=None
            if r.licence_name is None
            else Licence(r.licence_name, r.usage_limit, r.start_date, r.end_date, r.perpetual),
        )
        for r in session.execute(_ASSET_SOFTWARE, {"asset": asset_id})
    )
