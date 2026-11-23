"""Export of STIX 2.1 bundles from the database by scope (STX-02, STX-03, STX-06, docs/plans/f7.md).

Sharing scope. A bundle carries threat intelligence about the CVEs that touch the company, not the company's
inventory: it holds the CVE, the affected product, indicators, malware families, actors, sectors, the news reports
and scores, plus aggregates (how many CIs, the highest classification). It never carries CI names, addresses,
descriptions, owners, custodian teams, iTop identifiers, victim names or the text of news (SEG-01).
TLP (P-021) follows the most sensitive CI included: public TLP:CLEAR, classified TLP:AMBER, highly classified
TLP:RED, personal data at least TLP:AMBER; `exclude_ultra_classified` removes the highly classified CIs first.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any, Final, Literal

import stix2
import stix2validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.stix import builders
from core.stix.ids import stix_id

CVE_ID: Final = re.compile(r"^CVE-\d{4}-\d{4,}$")
IOC_SOURCES: Final = ("threatfox", "urlhaus")
# Order of sensitivity. An unclassified CI is "not classified yet", not "public": it fails closed to AMBER, like any
# value we do not know (P-021 does not cover it; the choice is reported in the PR).
ORDER: Final = ("public", "unclassified", "classified", "highly_classified")
TLP_OF_RANK: Final = {0: 0, 1: 1, 2: 1, 3: 2}
UNKNOWN_RANK: Final = 1
MARKINGS: Final = {0: ("TLP:CLEAR", stix2.TLP_WHITE), 1: ("TLP:AMBER", stix2.TLP_AMBER), 2: ("TLP:RED", stix2.TLP_RED)}
AMBER: Final = 1
HIGHLY_CLASSIFIED: Final = ORDER.index("highly_classified")


class StixExportError(Exception):
    """The request cannot be exported (bad scope data) or the bundle did not validate."""


@dataclass(frozen=True)
class ExportScope:
    kind: Literal["vulnerability", "run", "date_range"]
    vulnerability_id: str | None = None  # a CVE id or a finding group id
    run_id: str | None = None
    date_from: str | None = None
    date_to: str | None = None


@dataclass(frozen=True)
class ExportOptions:
    exclude_ultra_classified: bool = False


@dataclass
class ExportResult:
    bundle: dict[str, Any]
    tlp: str
    warnings: list[str] = field(default_factory=list)
    skipped_groups: int = 0  # groups left out because every CI they touch was excluded


# --- scope ---------------------------------------------------------------------------------------------
def _parse_uuid(raw: str | None, what: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(raw))
    except ValueError:
        raise StixExportError(f"{what} is not a valid identifier") from None


def _moment(raw: str | None, *, end: bool) -> datetime:
    try:
        if raw and len(raw) == len("2026-01-01"):
            day = datetime.combine(date.fromisoformat(raw), datetime.min.time(), tzinfo=UTC)
            return day + timedelta(days=1) if end else day
        parsed = datetime.fromisoformat(str(raw))
    except (ValueError, OverflowError):
        raise StixExportError("the date range needs ISO dates") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _group_ids(session: Session, scope: ExportScope) -> list[uuid.UUID]:
    if scope.kind == "vulnerability":
        if scope.vulnerability_id and CVE_ID.match(scope.vulnerability_id):
            rows = session.execute(
                text("SELECT id FROM finding_group WHERE cve_id = :c ORDER BY id"), {"c": scope.vulnerability_id}
            )
        else:
            rows = session.execute(
                text("SELECT id FROM finding_group WHERE id = :g"),
                {"g": _parse_uuid(scope.vulnerability_id, "vulnerability_id")},
            )
    elif scope.kind == "run":
        rows = session.execute(
            text(
                "SELECT DISTINCT f.finding_group_id FROM finding f JOIN finding_status_change c ON c.finding_id = f.id "
                "WHERE c.run_id = :r"
            ),
            {"r": _parse_uuid(scope.run_id, "run_id")},
        )
    else:
        start, end = _moment(scope.date_from, end=False), _moment(scope.date_to, end=True)
        if end <= start:
            raise StixExportError("the date range is empty")
        rows = session.execute(
            text(
                "SELECT DISTINCT f.finding_group_id FROM finding f JOIN finding_status_change c ON c.finding_id = f.id "
                "WHERE c.changed_at >= :a AND c.changed_at < :b"
            ),
            {"a": start, "b": end},
        )
    return sorted(r[0] for r in rows)


# --- data of one group ---------------------------------------------------------------------------------
@dataclass
class _Assets:
    count: int = 0
    rank: int = 0  # position in ORDER of the most sensitive CI
    personal: bool = False
    asset_ids: list[uuid.UUID] = field(default_factory=list)
    products: dict[tuple[str, str | None], tuple[str | None, str | None]] = field(default_factory=dict)
    excluded: int = 0


def _assets(session: Session, group_id: uuid.UUID, options: ExportOptions) -> _Assets:
    rows = session.execute(
        text(
            "SELECT a.id, a.confidentiality, a.personal_data, p.itop_name, i.version, m.nvd_vendor, m.nvd_product "
            "FROM finding f JOIN finding_current c ON c.finding_id = f.id "
            "JOIN installed_software i ON i.id = f.installed_software_id "
            "JOIN asset a ON a.id = i.asset_id JOIN software_product p ON p.id = i.software_product_id "
            "LEFT JOIN cpe_mapping m ON m.software_product_id = p.id "
            "WHERE f.finding_group_id = :g AND c.status IN ('new', 'persistent', 'reopened', 'no_data') "
            "AND a.decommissioned_at IS NULL ORDER BY a.id, i.version"
        ),
        {"g": group_id},
    )
    result = _Assets()
    seen: set[uuid.UUID] = set()
    for asset_id, confidentiality, personal, product, version, vendor, nvd_product in rows:
        rank = ORDER.index(confidentiality) if confidentiality in ORDER else UNKNOWN_RANK
        if options.exclude_ultra_classified and rank == HIGHLY_CLASSIFIED:
            result.excluded += 1
            continue
        if asset_id not in seen:
            seen.add(asset_id)
            result.asset_ids.append(asset_id)
            result.rank = max(result.rank, rank)
            result.personal = result.personal or bool(personal)
        result.products[(product, version)] = (vendor, nvd_product)
    result.count = len(seen)
    return result


def _scores(session: Session, group_id: uuid.UUID, asset_ids: list[uuid.UUID]) -> dict[str, Any]:
    row = session.execute(
        text(
            "SELECT a.id, a.llm_review_id, a.judge_adjustment, max(s.base), max(s.final) FROM assessment a "
            "JOIN asset_score s ON s.assessment_id = a.id AND s.asset_id = ANY(:assets) "
            "WHERE a.finding_group_id = :g GROUP BY a.id ORDER BY a.assessed_at DESC, a.id DESC LIMIT 1"
        ),
        {"g": group_id, "assets": asset_ids},
    ).first()
    if row is None:
        return {}
    reasons = (
        session.scalars(
            text(
                "SELECT DISTINCT reason_code FROM judge_reason WHERE llm_review_id = :r AND status = 'accepted' "
                "AND (asset_id IS NULL OR asset_id = ANY(:assets)) ORDER BY reason_code"
            ),
            {"r": row[1], "assets": asset_ids},
        ).all()
        if row[1]
        else []
    )
    return {"base": row[3], "adjustment": row[2], "final": row[4], "reasons": tuple(reasons)}


def _news(session: Session, cve_id: str) -> list[dict[str, Any]]:
    articles = session.execute(
        text(
            "SELECT DISTINCT ON (r.canonical_url) r.canonical_url, r.title, r.published_at, n.id "
            "FROM news_cve_mention nc JOIN news_analysis n ON n.id = nc.analysis_id "
            "JOIN story s ON s.id = n.story_id JOIN raw_article r ON r.id = s.representative_article_id "
            "WHERE nc.cve_id = :c ORDER BY r.canonical_url, n.id"
        ),
        {"c": cve_id},
    ).all()
    found: list[dict[str, Any]] = []
    for url, title, published, analysis_id in articles:
        actors = session.execute(
            text(
                "SELECT a.id, a.name FROM news_actor_mention m JOIN actor a ON a.id = m.actor_id "
                "WHERE m.analysis_id = :n ORDER BY a.name"
            ),
            {"n": analysis_id},
        ).all()
        sectors = session.execute(
            text(
                "SELECT DISTINCT s.code, s.name FROM news_victim v JOIN sector s ON s.code = v.sector_code "
                "WHERE v.analysis_id = :n ORDER BY s.code"
            ),
            {"n": analysis_id},
        ).all()
        aliases = {
            actor_id: tuple(
                session.scalars(
                    text("SELECT alias FROM actor_alias WHERE actor_id = :a ORDER BY alias"), {"a": actor_id}
                )
            )
            for actor_id, _ in actors
        }
        found.append(
            {
                "report": builders.ReportRecord(url, title, published),
                "actors": [builders.ActorRecord(name, aliases[actor_id]) for actor_id, name in actors],
                "sectors": [(code, name) for code, name in sectors],
            }
        )
    return found


def _indicators(session: Session, cve_id: str) -> list[builders.IndicatorRecord]:
    rows = session.execute(
        text(
            "SELECT i.ioc_type, i.value, i.first_seen_at, i.last_seen_at, i.malware_family FROM ioc_cve ic "
            "JOIN ioc i ON i.id = ic.ioc_id JOIN source s ON s.id = i.source_id "
            "WHERE ic.cve_id = :c AND s.code = ANY(:codes) ORDER BY i.ioc_type, i.value"
        ),
        {"c": cve_id, "codes": list(IOC_SOURCES)},
    )
    return [builders.IndicatorRecord(*row) for row in rows]


# --- assembly --------------------------------------------------------------------------------------------
@dataclass
class _GroupData:
    cve_id: str
    created: datetime
    modified: datetime
    description: str | None
    assets: _Assets
    scores: dict[str, Any]
    tickets: tuple[str, ...]
    indicators: list[builders.IndicatorRecord]
    news: list[dict[str, Any]]


def _gather(session: Session, group_id: uuid.UUID, options: ExportOptions) -> _GroupData | None:
    """The data of one group, or None when every CI it touches was excluded."""
    cve_id, group_created, description, published, modified = session.execute(
        text(
            "SELECT g.cve_id, g.created_at, c.description, c.published_at, c.last_modified_at "
            "FROM finding_group g JOIN cve c ON c.id = g.cve_id WHERE g.id = :g"
        ),
        {"g": group_id},
    ).one()
    assets = _assets(session, group_id, options)
    if assets.excluded and not assets.count:
        return None
    created = published or group_created
    tickets = session.scalars(
        text(
            "SELECT DISTINCT t.status FROM ticket t WHERE t.finding_group_id = :g AND (:all_assets OR EXISTS ("
            "SELECT 1 FROM ticket_finding tf JOIN finding f ON f.id = tf.finding_id "
            "JOIN installed_software i ON i.id = f.installed_software_id "
            "WHERE tf.ticket_id = t.id AND tf.removed_at IS NULL AND i.asset_id = ANY(:assets))) ORDER BY t.status"
        ),
        {"g": group_id, "all_assets": not assets.excluded, "assets": assets.asset_ids},
    ).all()
    return _GroupData(
        cve_id=cve_id,
        created=created,
        modified=max(created, modified or created),
        description=description,
        assets=assets,
        scores=_scores(session, group_id, assets.asset_ids) if assets.asset_ids else {},
        tickets=tuple(tickets),
        indicators=_indicators(session, cve_id),
        news=_news(session, cve_id),
    )


def _merge(groups: list[_GroupData]) -> _GroupData:
    """One CVE can live in several groups (one per product): the vulnerability object sums them up."""
    first = groups[0]
    if len(groups) == 1:
        return first
    assets = _Assets()
    for g in groups:
        assets.excluded += g.assets.excluded
        assets.rank = max(assets.rank, g.assets.rank)
        assets.personal = assets.personal or g.assets.personal
        assets.asset_ids += g.assets.asset_ids
        assets.products.update(g.assets.products)
    assets.asset_ids = sorted(set(assets.asset_ids))
    assets.count = len(assets.asset_ids)
    scored = [g.scores for g in groups if g.scores]
    top = max(scored, key=lambda sc: (sc["final"], sc["base"]), default={})
    scores = (
        {
            "base": max(sc["base"] for sc in scored),
            "final": max(sc["final"] for sc in scored),
            "adjustment": top["adjustment"],
            "reasons": tuple(sorted({r for sc in scored for r in sc["reasons"]})),
        }
        if scored
        else {}
    )
    return _GroupData(
        cve_id=first.cve_id,
        created=min(g.created for g in groups),
        modified=max(g.modified for g in groups),
        description=first.description,
        assets=assets,
        scores=scores,
        tickets=tuple(sorted({t for g in groups for t in g.tickets})),
        indicators=first.indicators,
        news=first.news,
    )


def _tlp_level(groups: list[_GroupData]) -> int:
    level = max((TLP_OF_RANK[g.assets.rank] for g in groups), default=0)
    if any(g.assets.personal for g in groups):
        level = max(level, AMBER)
    return level


def _build_group(group: _GroupData, out: dict[str, Any], marking: str) -> None:
    def add(obj: Any) -> Any:
        return out.setdefault(obj.id, obj)

    vuln = add(
        builders.vulnerability(
            builders.VulnerabilityRecord(
                cve_id=group.cve_id,
                created=group.created,
                modified=group.modified,
                description=group.description,
                base_score=group.scores.get("base"),
                judge_adjustment=group.scores.get("adjustment"),
                final_score=group.scores.get("final"),
                reasons=group.scores.get("reasons", ()),
                ticket_status=group.tickets,
                classification=ORDER[group.assets.rank] if group.assets.count else None,
                affected_assets=group.assets.count,
            ),
            marking,
        )
    )
    for (name, version), (vendor, product) in sorted(
        group.assets.products.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")
    ):
        record = builders.SoftwareRecord(name, vendor, version, vendor, product)
        item = add(builders.software(record, marking))
        add(builders.relationship("has", item.id, vuln.id, group.created, marking))
    families: dict[str, Any] = {}
    for ioc in group.indicators:
        indicator = builders.indicator(ioc, marking)
        if indicator is None:
            continue
        add(indicator)
        if ioc.malware_family and ioc.malware_family.strip():
            key = ioc.malware_family.strip().lower()
            families.setdefault(key, add(builders.malware(ioc.malware_family, ioc.first_seen, marking)))
            add(builders.relationship("indicates", indicator.id, families[key].id, ioc.first_seen, marking))
            add(builders.relationship("exploits", families[key].id, vuln.id, ioc.first_seen, marking))
    for item in group.news:
        record = item["report"]
        refs = [vuln.id, *(f.id for f in families.values())]
        actors = [add(builders.intrusion_set(a, record.published, marking)) for a in item["actors"]]
        sectors = [
            add(builders.sector_identity(code, name, record.published, marking)) for code, name in item["sectors"]
        ]
        for actor in actors:
            add(builders.relationship("targets", actor.id, vuln.id, record.published, marking))
            for sector in sectors:
                add(builders.relationship("targets", actor.id, sector.id, record.published, marking))
        refs += [o.id for o in (*actors, *sectors)]
        add(builders.report(record, refs, marking))


@dataclass(frozen=True)
class ValidationOutcome:
    errors: list[str]
    warnings: list[str]


def validate_bundle(serialized: str) -> ValidationOutcome:
    """Validate with the OASIS validator (STX-03). Errors block the export; warnings are returned."""
    results = stix2validator.validate_string(serialized, stix2validator.ValidationOptions(version="2.1"))
    return ValidationOutcome([str(e) for e in results.errors], [str(w) for w in results.warnings])


def export_bundle(session: Session, scope: ExportScope, options: ExportOptions | None = None) -> ExportResult:
    """The STIX bundle of the scope. Raises `StixExportError` for bad scope data or a bundle that fails validation."""
    options = options or ExportOptions()
    group_ids = _group_ids(session, scope)
    found = [g for gid in group_ids if (g := _gather(session, gid, options)) is not None]
    skipped = len(group_ids) - len(found)
    by_cve: dict[str, list[_GroupData]] = {}
    for item in found:
        by_cve.setdefault(item.cve_id, []).append(item)
    gathered = [_merge(by_cve[cve]) for cve in sorted(by_cve)]
    level = _tlp_level(gathered)
    label, marking = MARKINGS[level]
    objects: dict[str, Any] = {}
    for group in gathered:
        _build_group(group, objects, marking.id)
    if objects:
        objects[marking.id] = marking  # the marking definition travels with the objects that cite it
    ordered = [objects[key] for key in sorted(objects)]
    bundle = stix2.Bundle(id=stix_id("bundle", *sorted(objects)), objects=ordered, allow_custom=True)
    serialized = bundle.serialize(sort_keys=True)
    outcome = validate_bundle(serialized)
    if outcome.errors:
        raise StixExportError("the bundle did not validate: " + "; ".join(outcome.errors[:3]))
    document = json.loads(serialized)
    document.setdefault("objects", [])  # the API contract always carries the list, empty or not
    return ExportResult(bundle=document, tlp=label, warnings=outcome.warnings, skipped_groups=skipped)
