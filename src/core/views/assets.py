"""Inventory for the front (D-088, IN-1, IN-2, AC-1 to AC-10, AS-2, ST-1, ST-4, ST-6): the iTop cache, read only.

Every live CI is listed, with or without findings (`GET /api/vulnerabilities?view=asset` lists only the ones with
scored findings). Editing the inventory belongs to iTop (D-003): the front links to the CI there.

A CI's open findings are its current scored findings (not fixed, D-035); its risk is the highest final among them,
never a sum (FRO-11). Software counts only installations not removed, on live CIs. A version is known unless iTop
left it empty or with a placeholder (`UNKNOWN_VERSIONS`). The inventory is aggregated in memory, like the grouped
views: one query per table, then plain Python, enough for the prototype's inventory.

The iTop fields of F18.3 (D-088) are shown as iTop gives them: the CI's description, CPU and RAM, and each
installation's category (its iTop class), status, description and live licence. The catalogue shows, per product,
the categories of its live installations (user decision 1 of the F18.3 proposal).
"""

from __future__ import annotations

import uuid
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.cpe.candidates import cpe_uri
from core.views.common import LEVELS, ci_url, scored_findings
from core.views.groups import Licence

NameKey = tuple[str, str]  # (case-folded name, id) of the last row of a page, alphabetical
UNKNOWN_VERSIONS: Final = frozenset(
    {"", "-", "*", "?", "n/a", "na", "none", "unknown", "desconocida", "desconocido", "sin versión", "sin version"}
)
MAX_VERSIONS: Final = 20

_ASSETS: Final = text(
    """
    SELECT a.id, a.itop_ci_id, a.itop_class, a.name, a.criticality, a.exposed, a.confidentiality, a.personal_data,
           a.service, a.os, a.description, a.cpu, a.ram, a.synced_at, pe.name AS owner, t.name AS custodian
      FROM asset a
      LEFT JOIN person pe ON pe.id = a.owner_person_id
      LEFT JOIN team t ON t.id = a.custodian_team_id
     WHERE a.decommissioned_at IS NULL
       AND (CAST(:ci AS text) IS NULL OR a.itop_ci_id = CAST(:ci AS text))
    """
)
_INSTALLS: Final = text(
    """
    SELECT i.asset_id, i.software_product_id AS product_id, p.itop_name AS product, i.version,
           i.itop_class AS category, i.status, i.description,
           l.name AS licence_name, l.usage_limit, l.start_date, l.end_date, l.perpetual,
           c.nvd_vendor, c.nvd_product, c.cna_vendor, c.cna_product
      FROM installed_software i
      JOIN asset a ON a.id = i.asset_id AND a.decommissioned_at IS NULL
      JOIN software_product p ON p.id = i.software_product_id
      LEFT JOIN software_licence l ON l.id = i.software_licence_id AND l.removed_at IS NULL
      LEFT JOIN cpe_mapping c ON c.software_product_id = p.id
     WHERE i.removed_at IS NULL
       AND (CAST(:asset AS uuid) IS NULL OR i.asset_id = CAST(:asset AS uuid))
    """
)


def version_known(version: str | None) -> bool:
    return version is not None and version.strip().casefold() not in UNKNOWN_VERSIONS


def _worst(levels: Iterable[str]) -> str | None:
    found = set(levels)
    return next((level for level in LEVELS if level in found), None)


def _cpe(row: Any) -> str | None:
    if row.nvd_vendor and row.nvd_product:
        return cpe_uri(row.nvd_vendor, row.nvd_product)
    if row.cna_vendor and row.cna_product:
        return cpe_uri(row.cna_vendor, row.cna_product)
    return None


def _licence(row: Any) -> Licence | None:
    """The live iTop licence of an installation row, or None (a removed licence is not shown)."""
    if row.licence_name is None:
        return None
    return Licence(row.licence_name, row.usage_limit, row.start_date, row.end_date, row.perpetual)


@dataclass
class _Findings:
    """The current scored findings, by CI and by product: (group, level, in KEV) of each."""

    by_asset: dict[uuid.UUID, list[tuple[uuid.UUID, str, bool, int]]] = field(default_factory=lambda: defaultdict(list))
    by_product: dict[str, list[tuple[uuid.UUID, str, uuid.UUID]]] = field(default_factory=lambda: defaultdict(list))


def _findings(session: Session) -> _Findings:
    found = _Findings()
    for row in scored_findings(session):
        if not row.is_current:
            continue
        found.by_asset[row.asset_id].append((row.group_id, row.level, row.in_kev, row.final))
        found.by_product[row.product].append((row.group_id, row.level, row.asset_id))
    return found


@dataclass(frozen=True)
class InventoryAsset:
    ci_id: str
    name: str
    itop_class: str
    criticality: str
    exposed: bool | None
    classification: str
    personal_data: bool | None
    owner: str | None
    custodian: str | None
    service: str | None
    os: str | None
    itop_url: str
    synced_at: datetime
    open_findings: int
    kev_findings: int
    risk: int | None
    level: str | None
    software_count: int
    # F18.3 (D-088): iTop free text, shown as given (data, never instructions); None without data in iTop
    description: str | None = None
    cpu: str | None = None
    ram: str | None = None


@dataclass(frozen=True)
class AssetQuery:
    q: str | None = None
    itop_class: str | None = None
    criticality: str | None = None
    exposed: bool | None = None
    classification: str | None = None
    owner: str | None = None
    custodian: str | None = None
    with_findings: bool | None = None

    def matches(self, a: InventoryAsset) -> bool:
        text_ok = self.q is None or self.q.casefold() in f"{a.name}\n{a.ci_id}".casefold()
        checks = (
            (self.itop_class, a.itop_class),
            (self.criticality, a.criticality),
            (self.exposed, a.exposed),
            (self.classification, a.classification),
            (self.owner, a.owner),
            (self.custodian, a.custodian),
            (self.with_findings, a.open_findings > 0),
        )
        return text_ok and all(wanted is None or wanted == value for wanted, value in checks)


def _assets(session: Session, itop_base_url: str | None, ci: str | None = None) -> list[InventoryAsset]:
    findings = _findings(session)
    software: Counter[uuid.UUID] = Counter(row.asset_id for row in session.execute(_INSTALLS, {"asset": None}))
    out: list[InventoryAsset] = []
    for row in session.execute(_ASSETS, {"ci": ci}):
        current = findings.by_asset.get(row.id, [])
        risk = max((final for _g, _l, _k, final in current), default=None)
        out.append(
            InventoryAsset(
                ci_id=row.itop_ci_id,
                name=row.name,
                itop_class=row.itop_class,
                criticality=row.criticality,
                exposed=row.exposed,
                classification=row.confidentiality,
                personal_data=row.personal_data,
                owner=row.owner,
                custodian=row.custodian,
                service=row.service,
                os=row.os,
                itop_url=ci_url(itop_base_url, row.itop_class, row.itop_ci_id),
                synced_at=row.synced_at,
                open_findings=len({group for group, _l, _k, _f in current}),
                kev_findings=len({group for group, _l, kev, _f in current if kev}),
                risk=risk,
                level=_worst(level for _g, level, _k, _f in current),
                software_count=software.get(row.id, 0),
                description=row.description,
                cpu=row.cpu,
                ram=row.ram,
            )
        )
    return out


def page_by_name[T](
    items: Iterable[T], key: Callable[[T], NameKey], after: NameKey | None, limit: int
) -> tuple[list[T], NameKey | None]:
    """Alphabetical (case-folded name, then id); resume after `after`; the next key is the last row kept."""
    ordered = sorted(items, key=key)
    if after is not None:
        ordered = [item for item in ordered if key(item) > after]
    kept = ordered[:limit]
    return kept, (key(kept[-1]) if len(ordered) > limit else None)


def asset_key(a: InventoryAsset) -> NameKey:
    return a.name.casefold(), a.ci_id


def list_assets(
    session: Session, query: AssetQuery, itop_base_url: str | None, *, after: NameKey | None, limit: int
) -> tuple[list[InventoryAsset], NameKey | None]:
    """Every live CI that matches, alphabetical; the second value keys the next page."""
    return page_by_name((a for a in _assets(session, itop_base_url) if query.matches(a)), asset_key, after, limit)


# --- software ------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class SoftwareItem:
    id: uuid.UUID
    name: str
    versions: list[str]
    version_known: bool
    instances: int
    ci_count: int
    cpe: str | None
    open_vulnerabilities: int
    worst_level: str | None
    categories: list[str] = field(default_factory=list)  # distinct iTop classes of its live installations, sorted


@dataclass(frozen=True)
class SoftwareQuery:
    q: str | None = None
    has_cpe: bool | None = None
    worst_level: str | None = None
    with_vulnerabilities: bool | None = None
    category: str | None = None  # the product counts when any of its live installations has it

    def matches(self, s: SoftwareItem) -> bool:
        return (
            (self.q is None or self.q.casefold() in s.name.casefold())
            and (self.has_cpe is None or self.has_cpe == (s.cpe is not None))
            and (self.worst_level is None or self.worst_level == s.worst_level)
            and (self.with_vulnerabilities is None or self.with_vulnerabilities == (s.open_vulnerabilities > 0))
            and (self.category is None or self.category in s.categories)
        )


def _software(session: Session) -> list[SoftwareItem]:
    findings = _findings(session)
    rows: dict[uuid.UUID, list[Any]] = defaultdict(list)
    for row in session.execute(_INSTALLS, {"asset": None}):
        rows[row.product_id].append(row)
    out: list[SoftwareItem] = []
    for product_id, installs in rows.items():
        first = installs[0]
        current = findings.by_product.get(first.product, [])
        known = sorted({r.version for r in installs if version_known(r.version)})
        out.append(
            SoftwareItem(
                id=product_id,
                name=first.product,
                versions=known[:MAX_VERSIONS],
                version_known=bool(known),
                instances=len(installs),
                ci_count=len({r.asset_id for r in installs}),
                cpe=_cpe(first),
                open_vulnerabilities=len({group for group, _l, _a in current}),
                worst_level=_worst(level for _g, level, _a in current),
                categories=sorted({r.category for r in installs if r.category is not None}),
            )
        )
    return out


def software_key(s: SoftwareItem) -> NameKey:
    return s.name.casefold(), str(s.id)


def list_software(
    session: Session, query: SoftwareQuery, *, after: NameKey | None, limit: int
) -> tuple[list[SoftwareItem], NameKey | None]:
    """Software installed on live CIs, alphabetical; the second value keys the next page."""
    return page_by_name((s for s in _software(session) if query.matches(s)), software_key, after, limit)


@dataclass(frozen=True)
class InstalledItem:
    software_id: uuid.UUID
    name: str
    version: str
    version_known: bool
    cpe: str | None
    open_vulnerabilities: int
    worst_level: str | None
    # F18.3 (D-088): the installation as iTop has it; None until synced (category also for a custom class)
    category: str | None = None
    status: str | None = None  # active | inactive; only shown, an inactive installation is still scanned
    description: str | None = None
    licence: Licence | None = None


def asset_software(session: Session, ci_id: str) -> list[InstalledItem] | None:
    """The software installed on a live CI, alphabetical; None when the CI is not in the live inventory."""
    asset_id = session.execute(
        text("SELECT id FROM asset WHERE itop_ci_id = :ci AND decommissioned_at IS NULL"), {"ci": ci_id}
    ).scalar()
    if asset_id is None:
        return None
    findings = _findings(session)
    groups_here = {group: level for group, level, _k, _f in findings.by_asset.get(asset_id, [])}
    out: list[InstalledItem] = []
    for row in session.execute(_INSTALLS, {"asset": asset_id}):
        current = [
            (group, level)
            for group, level, asset in findings.by_product.get(row.product, [])
            if asset == asset_id and group in groups_here
        ]
        out.append(
            InstalledItem(
                software_id=row.product_id,
                name=row.product,
                version=row.version,
                version_known=version_known(row.version),
                cpe=_cpe(row),
                open_vulnerabilities=len({group for group, _l in current}),
                worst_level=_worst(level for _g, level in current),
                category=row.category,
                status=row.status,
                description=row.description,
                licence=_licence(row),
            )
        )
    return sorted(out, key=lambda i: (i.name.casefold(), i.version, str(i.software_id)))


# --- summary ----------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class SoftwareHealth:
    total: int
    with_cpe: int
    with_known_version: int
    without_critical: int


@dataclass(frozen=True)
class Summary:
    total_assets: int
    by_class: dict[str, int]
    by_criticality: dict[str, int]
    by_exposure: dict[str, int]
    by_classification: dict[str, int]
    owners: int
    without_owner: int
    custodians: int
    with_open_findings: int
    with_kev_findings: int
    last_sync_at: datetime | None
    software: SoftwareHealth


def _counts(values: Sequence[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def summary(session: Session) -> Summary:
    """Totals of the live inventory and the health of its software (D-088)."""
    assets = _assets(session, None)
    software = _software(session)
    exposure = ["exposed" if a.exposed else "internal" if a.exposed is False else "unknown" for a in assets]
    return Summary(
        total_assets=len(assets),
        by_class=_counts([a.itop_class for a in assets]),
        by_criticality=_counts([a.criticality for a in assets]),
        by_exposure=_counts(exposure),
        by_classification=_counts([a.classification for a in assets]),
        owners=len({a.owner for a in assets if a.owner}),
        without_owner=sum(1 for a in assets if not a.owner),
        custodians=len({a.custodian for a in assets if a.custodian}),
        with_open_findings=sum(1 for a in assets if a.open_findings),
        with_kev_findings=sum(1 for a in assets if a.kev_findings),
        last_sync_at=max((a.synced_at for a in assets), default=None),
        software=SoftwareHealth(
            total=len(software),
            with_cpe=sum(1 for s in software if s.cpe is not None),
            with_known_version=sum(1 for s in software if s.version_known),
            without_critical=sum(1 for s in software if s.worst_level != "critical"),
        ),
    )
