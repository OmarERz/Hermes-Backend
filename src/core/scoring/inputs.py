"""Factor inputs of a finding group, read from the database (docs/06 §3, EVA-09, EVA-14).

S, P and T belong to the group (CVE + product): CVSS and EPSS and KEV from the vulnerability data, the exploitation
grade and the threat context from the news correlated with the group. A and D belong to each CI (D-035).
Nothing here calls an LLM; the analyses it reads were produced earlier and are stored.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.correlation.engine import GroupCtx, StoryFacts, load_story_facts, story_relevances
from core.correlation.keys import normalize_name
from core.db import models as m
from core.scoring.cvss import base_score as cvss_base_score
from core.scoring.engine import (
    CONFIRMED_GRADES,
    Confidentiality,
    Criticality,
    ExploitationGrade,
    Formula,
    SeverityOrigin,
    ThreatEvidence,
    asset_level,
    data_sensitivity,
    exploitation_level,
    severity,
    trend_level,
)

TREND_DAYS = 7
GRADE_RANK = {
    ExploitationGrade.NONE: 0,
    ExploitationGrade.DENIED: 1,
    ExploitationGrade.ATTEMPTED: 2,
    ExploitationGrade.LIMITED: 3,
    ExploitationGrade.ACTIVE: 4,
    ExploitationGrade.MASS: 5,
}
EXPLOIT_TAG = "Exploit"


@dataclass(frozen=True)
class GroupInputs:
    cve_id: str
    cvss: Decimal | None
    cvss_version: str | None
    inferred_cvss: Decimal | None
    in_kev: bool
    grade: ExploitationGrade
    public_poc: bool
    epss: Decimal | None
    epss_percentile: Decimal | None
    evidence: tuple[ThreatEvidence, ...]


@dataclass(frozen=True)
class GroupFactors:
    s: Decimal
    s_origin: SeverityOrigin
    p: Decimal
    p_level: str


def parse_grade(value: object) -> ExploitationGrade:
    """The analyst's grade; `unknown` and anything unrecognized count as no evidence."""
    try:
        return ExploitationGrade(str(value))
    except ValueError:
        return ExploitationGrade.NONE


def _grade_for(facts: StoryFacts, cve_id: str) -> ExploitationGrade:
    return parse_grade(facts.cve_levels.get(cve_id))


def _story_evidence(
    session: Session, facts: StoryFacts, cve_id: str, newest: datetime, now: datetime
) -> list[ThreatEvidence]:
    """Threat levels one correlated story supports (docs/06 §3 T): every correlated story already names a product
    present in the stack, so the "with vector" levels apply."""
    peers = {
        normalize_name(name)
        for name in [
            *session.scalars(select(m.PeerCompany.name)),
            *session.scalars(select(m.PeerCompanyAlias.alias)),
        ]
    }
    peer_ids = set(session.scalars(select(m.PeerCompany.id)))
    sectors = set(session.scalars(select(m.ProfileSector.sector_code)))
    countries = set(session.scalars(select(m.ProfileCountry.country_code)))
    age = max(0, (now - newest).days)
    exploited = _grade_for(facts, cve_id) in CONFIRMED_GRADES or "active_exploitation" in facts.event_types
    levels: set[str] = set()
    if any(v.peer_company_id in peer_ids or normalize_name(v.name) in peers for v in facts.victims):
        levels.add("peer_exploited_with_vector" if exploited else "peer_attacked")
    same_sector = any(v.sector_code in sectors for v in facts.victims if v.sector_code)
    same_region = any(v.country_code in countries for v in facts.victims if v.country_code)
    if same_sector and same_region:
        levels.add("sector_region_with_vector")
    elif same_sector:
        levels.add("sector_only")
    if "R4" in story_relevances(session, facts):
        levels.add("sector_region_with_vector")
    return [ThreatEvidence(level, age) for level in sorted(levels)]


def load_group_inputs(session: Session, group: GroupCtx, story_ids: list[uuid.UUID], now: datetime) -> GroupInputs:
    cve = session.get(m.Cve, group.cve_id)
    cvss = cve.cvss_score if cve else None
    inferred_vector = session.scalar(
        select(m.CveAnalysis.inferred_cvss_vector).where(m.CveAnalysis.cve_id == group.cve_id)
    )
    inferred = cvss_base_score(inferred_vector) if inferred_vector else None
    latest_epss = session.scalars(
        select(m.EpssScore).where(m.EpssScore.cve_id == group.cve_id).order_by(m.EpssScore.score_date.desc()).limit(1)
    ).first()
    exploit_reference = (
        session.scalars(
            select(m.CveReferenceTag.tag)
            .join(m.CveReference, m.CveReference.id == m.CveReferenceTag.reference_id)
            .where(m.CveReference.cve_id == group.cve_id, m.CveReferenceTag.tag == EXPLOIT_TAG)
            .limit(1)
        ).first()
        is not None
    )
    grade = ExploitationGrade.NONE
    public_poc = exploit_reference
    evidence: list[ThreatEvidence] = []
    sources: set[uuid.UUID] = set()
    for story_id in story_ids:
        facts = load_story_facts(session, story_id)
        if facts is None:
            continue
        story_grade = _grade_for(facts, group.cve_id)
        if GRADE_RANK[story_grade] > GRADE_RANK[grade]:
            grade = story_grade
        analysis = session.get(m.NewsAnalysis, facts.analysis_id)
        if analysis is not None and analysis.output.get("signals", {}).get("public_poc") is True:
            public_poc = True
        dates = list(
            session.execute(
                select(m.RawArticle.published_at, m.Source.id)
                .join(m.SourceFetch, m.SourceFetch.id == m.RawArticle.source_fetch_id)
                .join(m.Source, m.Source.id == m.SourceFetch.source_id)
                .where(m.RawArticle.story_id == story_id)
            )
        )
        if not dates:
            continue
        newest = max(published for published, _ in dates)
        evidence += _story_evidence(session, facts, group.cve_id, newest, now)
        sources |= {source for published, source in dates if published >= now - timedelta(days=TREND_DAYS)}
    trend = trend_level(len(sources))
    if trend is not None:
        evidence.append(ThreatEvidence(trend, 0))
    return GroupInputs(
        cve_id=group.cve_id,
        cvss=cvss,
        cvss_version=cve.cvss_version if cve else None,
        inferred_cvss=inferred,
        in_kev=session.get(m.KevEntry, group.cve_id) is not None,
        grade=grade,
        public_poc=public_poc,
        epss=latest_epss.epss if latest_epss else None,
        epss_percentile=latest_epss.percentile if latest_epss else None,
        evidence=tuple(evidence),
    )


def group_factors(formula: Formula, inputs: GroupInputs) -> GroupFactors:
    s, origin = severity(formula, inputs.cvss, inputs.inferred_cvss)
    level = exploitation_level(
        in_kev=inputs.in_kev,
        grade=inputs.grade,
        public_poc=inputs.public_poc,
        epss_percentile=inputs.epss_percentile,
    )
    return GroupFactors(s=s, s_origin=origin, p=formula.level("P", level), p_level=level)


def asset_factors(formula: Formula, asset: m.Asset) -> tuple[Decimal, Decimal]:
    """A and D of one CI from its cached iTop fields (unknown values take the documented neutral levels)."""
    try:
        criticality = Criticality(asset.criticality)
    except ValueError:
        criticality = Criticality.UNKNOWN
    try:
        confidentiality = Confidentiality(asset.confidentiality)
    except ValueError:
        confidentiality = Confidentiality.UNCLASSIFIED
    a = formula.level("A", asset_level(criticality, asset.exposed))
    return a, data_sensitivity(formula, confidentiality, asset.personal_data)
