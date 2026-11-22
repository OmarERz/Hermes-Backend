"""Review packages (COR-06, COR-07): the unit of work the correlation engine hands to the judge.

Three kinds, as in `schemas/review_package.schema.json`: a finding package (a group with its context and the base of
each CI), an alert package (a news item with R2, R3 or R4 and no group) and a dismissal candidate (a security event
that crossed with nothing). The fingerprint covers the group, the linked news and the profile version, and **not** the
weights or the factor levels (D-033): changing the formula recalculates the base by code and keeps the judge's review.

The base scores come from the scoring engine (F4.2) through `BaseScorer`; this module only places them.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Protocol

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.correlation.engine import GroupCtx, StoryFacts, load_story_facts
from core.correlation.keys import MatchType
from core.db import models as m
from core.db.ids import new_id
from core.ingestion.settings import get_int

SCHEMA_VERSION = "1"
CONTRACT_MATCH = {"cve_exact": "exact_cve"}  # the database code and the contract name differ for this key only


@dataclass(frozen=True)
class ScoredGroup:
    """What the scoring engine returns for a group: the group `base` block and the base of each CI by asset id."""

    base: dict[str, Any]  # S, P, T, A, D, (E), score, details, floor_applicable (relevance is added here)
    per_ci: dict[uuid.UUID, dict[str, Any]]  # A, D, score, floor_applicable


class BaseScorer(Protocol):
    def score_group(self, session: Session, group: GroupCtx, matches: list[NewsMatch]) -> ScoredGroup: ...

    def score_story(self, session: Session, facts: StoryFacts, asset_ids: list[uuid.UUID]) -> dict[str, Any]:
        """The `base` block of an alert or a dismissal candidate (no group)."""
        ...


@dataclass(frozen=True)
class NewsMatch:
    story_id: uuid.UUID
    match: MatchType
    relevance: str | None


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def fingerprint(content: dict[str, Any]) -> str:
    """Hash of what the judge's review depends on; never of weights, levels, factors or base scores."""
    return hashlib.sha256(_canonical(content).encode()).hexdigest()


def profile_version(session: Session) -> str:
    stamp = session.scalar(select(m.CompanyProfile.updated_at).where(m.CompanyProfile.id == 1))
    return stamp.isoformat() if stamp else "none"


def weights_version(session: Session) -> str:
    number = session.scalar(select(m.FormulaVersion.version_no).where(m.FormulaVersion.status == "active"))
    return f"v{number}" if number is not None else "none"


def _profile_summary(session: Session, stack: bool) -> dict[str, Any]:
    sector = session.scalar(
        select(m.Sector.name)
        .join(m.ProfileSector, m.ProfileSector.sector_code == m.Sector.code)
        .order_by(m.ProfileSector.is_primary.desc(), m.Sector.code)
        .limit(1)
    )
    summary: dict[str, Any] = {
        "sector": sector or "",
        "countries": sorted(session.scalars(select(m.ProfileCountry.country_code))),
        "peer_companies": sorted(session.scalars(select(m.PeerCompany.name))),
        "stack_summary": [],
    }
    if stack:
        rows = session.execute(
            select(m.SoftwareProduct.itop_name, m.InstalledSoftware.version)
            .join(m.InstalledSoftware, m.InstalledSoftware.software_product_id == m.SoftwareProduct.id)
            .where(m.InstalledSoftware.removed_at.is_(None))
            .distinct()
            .order_by(m.SoftwareProduct.itop_name, m.InstalledSoftware.version)
        )
        summary["stack_summary"] = [f"{name} {version}" for name, version in rows]
    return summary


def _news_block(session: Session, matches: list[NewsMatch], limit: int) -> tuple[list[dict[str, Any]], list[str]]:
    """COR-04: the strongest and most recent `limit` stories in full; the others only as URLs."""
    dated: list[tuple[NewsMatch, datetime]] = []
    for match in matches:
        newest = session.scalar(
            select(func.max(m.RawArticle.published_at)).where(m.RawArticle.story_id == match.story_id)
        )
        dated.append((match, newest or datetime.fromtimestamp(0, UTC)))
    dated.sort(key=lambda item: (-item[0].match.strength, -item[1].timestamp(), str(item[0].story_id)))
    items: list[dict[str, Any]] = []
    extra_urls: list[str] = []
    for _match, _newest in dated[limit:]:
        extra_urls += list(
            session.scalars(
                select(m.RawArticle.canonical_url)
                .where(m.RawArticle.story_id == _match.story_id)
                .order_by(m.RawArticle.published_at)
            )
        )
    for index, (match, _newest) in enumerate(dated[:limit], start=1):
        story = session.get(m.Story, match.story_id)
        analysis = session.scalars(select(m.NewsAnalysis).where(m.NewsAnalysis.story_id == match.story_id)).first()
        articles = list(
            session.scalars(
                select(m.RawArticle).where(m.RawArticle.story_id == match.story_id).order_by(m.RawArticle.published_at)
            )
        )
        if story is None or analysis is None or not articles:
            continue
        representative = next((a for a in articles if a.id == story.representative_article_id), articles[0])
        source = session.execute(
            select(m.Source.code, m.Source.trust_tier)
            .join(m.SourceFetch, m.SourceFetch.source_id == m.Source.id)
            .where(m.SourceFetch.id == representative.source_fetch_id)
        ).one()
        items.append(
            {
                "element_id": f"N{index}",
                "story_id": str(match.story_id),
                "title": representative.title,
                "source": source[0],
                "source_level": source[1],
                "date": articles[0].published_at.isoformat(),
                "urls": [a.canonical_url for a in articles],
                "summary": analysis.summary,
                "event_types": list(analysis.output.get("event_types", [])),
                "exploitation_level": analysis.output.get("exploitation_level", "unknown"),
                "match": {
                    "type": CONTRACT_MATCH.get(match.match.code, match.match.code),
                    "strength": float(match.match.strength),
                },
                "suspicious": any(a.is_suspicious for a in articles),
            }
        )
    return items, extra_urls


def _cve_block(session: Session, cve_id: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    cve = session.get(m.Cve, cve_id)
    if cve is None:
        raise LookupError(cve_id)
    ranges = [
        f"{r.vendor}:{r.product} {'[' if r.start_inclusive else '('}{r.version_start or ''},"
        f"{r.version_end or ''}{']' if r.end_inclusive else ')'}"
        for r in session.scalars(select(m.CveAffectedRange).where(m.CveAffectedRange.cve_id == cve_id))
    ]
    references = []
    for ref in session.scalars(select(m.CveReference).where(m.CveReference.cve_id == cve_id)):
        tags = sorted(session.scalars(select(m.CveReferenceTag.tag).where(m.CveReferenceTag.reference_id == ref.id)))
        references.append({"url": ref.url, "tags": tags})
    analysis = session.scalars(select(m.CveAnalysis).where(m.CveAnalysis.cve_id == cve_id)).first()
    output = analysis.output if analysis else {}
    cwe = session.scalar(select(m.CveCwe.cwe_id).where(m.CveCwe.cve_id == cve_id).order_by(m.CveCwe.cwe_id).limit(1))
    data = {
        "element_id": "cve",
        "description": cve.description or "",
        "cvss": float(cve.cvss_score) if cve.cvss_score is not None else None,
        "vector": cve.cvss_vector,
        "cvss_source": cve.cvss_source,
        "cwe": cwe,
        "affected_ranges": sorted(ranges),
        "fixed_version": None,
        "references": references,
        "conditions": list(output.get("conditions", [])),
        "components": list(output.get("components", [])),
    }
    kev_row = session.get(m.KevEntry, cve_id)
    kev = {
        "listed": kev_row is not None,
        "date": kev_row.date_added.isoformat() if kev_row else None,
        "required_action": kev_row.required_action if kev_row else None,
        "known_ransomware": bool(kev_row and kev_row.known_ransomware_use),
    }
    latest = session.scalars(
        select(m.EpssScore).where(m.EpssScore.cve_id == cve_id).order_by(m.EpssScore.score_date.desc()).limit(1)
    ).first()
    epss = (
        {"score": float(latest.epss), "percentile": float(latest.percentile), "date": latest.score_date.isoformat()}
        if latest
        else None
    )
    return data, kev, epss


def _tickets(session: Session, group_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = session.execute(
        select(m.Ticket, m.Team.name)
        .join(m.Team, m.Team.id == m.Ticket.custodian_team_id)
        .where(m.Ticket.finding_group_id == group_id, m.Ticket.itop_ticket_id.is_not(None))
        .order_by(m.Team.name)
    )
    return [
        {
            "itop_id": ticket.itop_ticket_id,
            "custodian": team,
            "current_urgency": ticket.current_urgency or 3,
            "last_change_by_human": ticket.last_human_change_at is not None,
            "suggestions_enabled": ticket.suggestions_enabled,
        }
        for ticket, team in rows
    ]


def _cis_block(session: Session, group: GroupCtx, scored: ScoredGroup) -> list[dict[str, Any]]:
    cis: list[dict[str, Any]] = []
    for index, ci in enumerate(group.cis, start=1):
        asset = session.get(m.Asset, ci.asset_id)
        if asset is None:
            continue
        custodian = session.get(m.Team, asset.custodian_team_id) if asset.custodian_team_id else None
        status = session.execute(
            select(m.FindingStatusChange.status)
            .join(m.Finding, m.Finding.id == m.FindingStatusChange.finding_id)
            .where(m.Finding.finding_group_id == group.id, m.Finding.installed_software_id == ci.installed_software_id)
            .order_by(m.FindingStatusChange.changed_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        cis.append(
            {
                "element_id": f"CI{index}",
                "ci_id": asset.itop_ci_id,
                "name": asset.name,
                "service": asset.service,
                "criticality": asset.criticality,
                "exposed": bool(asset.exposed),
                "confidentiality": asset.confidentiality,
                "personal_data": asset.personal_data,
                "custodian": custodian.name if custodian else None,
                "status": status or "new",
                "description": asset.description,
                "base": scored.per_ci[asset.id],
            }
        )
    return cis


def _finding_fingerprint(package: dict[str, Any], linked_story_ids: list[uuid.UUID]) -> str:
    group = package["group"]
    stable_cis = [{k: v for k, v in ci.items() if k not in ("base", "element_id")} for ci in group["cis"]]
    return fingerprint(
        {
            "kind": "finding",
            "cve": group["cve"],
            "product": group["product"],
            "cpe": group["cpe"],
            "cis": sorted(stable_cis, key=lambda ci: ci["ci_id"]),
            "stories": sorted(str(s) for s in linked_story_ids),
            "profile": package["versions"]["profile"],
        }
    )


def build_finding_package(
    session: Session, group: GroupCtx, matches: list[NewsMatch], scorer: BaseScorer
) -> dict[str, Any]:
    scored = scorer.score_group(session, group, matches)
    cve_data, kev, epss = _cve_block(session, group.cve_id)
    product = session.scalar(
        select(m.SoftwareProduct.itop_name)
        .join(m.FindingGroup, m.FindingGroup.software_product_id == m.SoftwareProduct.id)
        .where(m.FindingGroup.id == group.id)
    )
    relevance = sorted({m_.relevance for m_ in matches if m_.relevance})
    news, extra_urls = _news_block(session, matches, get_int(session, "top_news_per_package"))
    package: dict[str, Any] = {
        "package_id": str(group.id),
        "type": "finding",
        "versions": {
            "profile": profile_version(session),
            "weights": weights_version(session),
            "schema": SCHEMA_VERSION,
        },
        "group": {
            "group_id": str(group.id),
            "cve": group.cve_id,
            "product": product or "",
            "cpe": ":".join(group.vendor_products[0]) if group.vendor_products else None,
            "cis": _cis_block(session, group, scored),
        },
        "cve_data": cve_data,
        "kev": kev,
        "epss": epss,
        "base": {**scored.base, "relevance": relevance},
        "news": news,
        "additional_urls": extra_urls,
        "iocs": [
            {"type": ioc.ioc_type, "value": ioc.value, "malware_family": ioc.malware_family}
            for ioc in session.scalars(
                select(m.Ioc)
                .join(m.IocCve, m.IocCve.ioc_id == m.Ioc.id)
                .where(m.IocCve.cve_id == group.cve_id)
                .order_by(m.Ioc.ioc_type, m.Ioc.value)
            )
        ],
        "tickets": _tickets(session, group.id),
        "profile_summary": _profile_summary(session, stack=False),
    }
    package["fingerprint"] = _finding_fingerprint(package, [m_.story_id for m_ in matches])
    return package


NO_MATCH = MatchType("none", Decimal(0), 99)


@dataclass(frozen=True)
class _Touch:
    asset_ids: list[uuid.UUID]
    relevances: set[str]


def _story_package(session: Session, kind: str, facts: StoryFacts, scorer: BaseScorer, touch: _Touch) -> dict[str, Any]:
    """An alert or a dismissal candidate: no group, no CVE data; the news item is the whole subject."""
    base = {**scorer.score_story(session, facts, touch.asset_ids), "relevance": sorted(touch.relevances)}
    package: dict[str, Any] = {
        "package_id": str(facts.story_id),
        "type": kind,
        "versions": {
            "profile": profile_version(session),
            "weights": weights_version(session),
            "schema": SCHEMA_VERSION,
        },
        "group": None,
        "cve_data": None,
        "kev": {"listed": False, "date": None, "required_action": None, "known_ransomware": False},
        "epss": None,
        "base": base,
        "news": _news_block(session, [NewsMatch(facts.story_id, NO_MATCH, None)], 1)[0],
        "iocs": [],
        "tickets": [],
        "profile_summary": _profile_summary(session, stack=True),
    }
    package["fingerprint"] = fingerprint(
        {
            "kind": kind,
            "story": str(facts.story_id),
            "assets": sorted(str(a) for a in touch.asset_ids),
            "profile": package["versions"]["profile"],
        }
    )
    return package


def build_alert_package(session: Session, alert_id: uuid.UUID, scorer: BaseScorer) -> dict[str, Any]:
    alert = session.get(m.Alert, alert_id)
    if alert is None:
        raise LookupError(alert_id)
    facts = load_story_facts(session, alert.story_id)
    if facts is None:
        raise LookupError(alert.story_id)
    assets = list(session.scalars(select(m.AlertAsset.asset_id).where(m.AlertAsset.alert_id == alert_id)))
    package = _story_package(session, "alert", facts, scorer, _Touch(assets, {alert.relevance}))
    package["package_id"] = str(alert_id)
    return package


def build_dismissal_package(session: Session, story_id: uuid.UUID, scorer: BaseScorer) -> dict[str, Any]:
    facts = load_story_facts(session, story_id)
    if facts is None:
        raise LookupError(story_id)
    return _story_package(session, "dismissal_candidate", facts, scorer, _Touch([], set()))


def store_package(session: Session, package: dict[str, Any], now: datetime) -> m.ReviewPackage:
    """Persist the package as handed to the judge. The same fingerprint for the same subject is stored once, so a
    package whose fingerprint did not change reuses the judge's review (COR-06)."""
    kind = {"finding": "finding", "alert": "alert", "dismissal_candidate": "dismissal"}[package["type"]]
    subject = uuid.UUID(package["package_id"])
    references = {
        "finding": {"finding_group_id": subject},
        "alert": {"alert_id": subject},
        "dismissal": {"story_id": subject},
    }[kind]
    column = next(iter(references))
    existing = session.scalars(
        select(m.ReviewPackage).where(
            m.ReviewPackage.kind == kind,
            getattr(m.ReviewPackage, column) == subject,
            m.ReviewPackage.fingerprint == package["fingerprint"],
        )
    ).first()
    if existing is not None:
        return existing
    row = m.ReviewPackage(
        id=new_id(), kind=kind, fingerprint=package["fingerprint"], content=package, built_at=now, **references
    )
    session.add(row)
    session.flush()
    return row
