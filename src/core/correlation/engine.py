"""Correlation of news analyses with finding groups (COR-01 to COR-05) and the relevance of R1 to R4.

For one story with an analysis it finds the groups it touches with the strongest key that matches, keeps at most
`max_matches_per_news` of them (strongest first), stores one `correlation` row per group and story, and decides
what is left over: an `alert` when the story has no group but is relevant (R2, R3 or R4), or a dismissal
candidate when it reports a security event and crossed with nothing.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from core.correlation.keys import (
    SECURITY_EVENT_TYPES,
    MatchType,
    best_match,
    highest_relevance,
    is_r1,
    is_r2,
    is_r3,
    is_r4,
    keep_strongest,
    normalize_name,
    os_matches,
    same_product,
    vector_matches,
)
from core.db import models as m
from core.db.ids import new_id
from core.ingestion.settings import get_int
from core.scan.versions import compare_versions, in_range

log = logging.getLogger("correlation")


@dataclass(frozen=True)
class Ci:
    installed_software_id: uuid.UUID
    asset_id: uuid.UUID
    asset_os: str | None
    version: str


@dataclass(frozen=True)
class GroupCtx:
    id: uuid.UUID
    cve_id: str
    product_names: frozenset[str]  # iTop name and CPE product names, to compare attack vectors
    vendor_products: tuple[tuple[str, str], ...]  # (vendor, product) pairs of the CPE mapping (NVD and CNA)
    cis: tuple[Ci, ...]


@dataclass(frozen=True)
class ProductMention:
    vendor: str | None
    product: str
    version: str | None


@dataclass(frozen=True)
class StoryFacts:
    story_id: uuid.UUID
    analysis_id: uuid.UUID
    event_types: frozenset[str]
    cve_levels: dict[str, str | None]  # CVE -> exploitation level of that CVE in this story
    products: tuple[ProductMention, ...]
    vectors: tuple[str, ...]
    victims: tuple[m.NewsVictim, ...]
    actor_ids: tuple[uuid.UUID, ...]


@dataclass(frozen=True)
class Placed:
    group_id: uuid.UUID
    match_code: str
    relevance: str | None


@dataclass
class StoryOutcome:
    story_id: uuid.UUID
    matches: list[Placed] = field(default_factory=list)
    relevances: set[str] = field(default_factory=set)
    alert_id: uuid.UUID | None = None
    dismissal_candidate: bool = False
    dropped: int = 0


def load_match_types(session: Session) -> dict[str, MatchType]:
    rows = session.scalars(select(m.CorrelationMatchType))
    return {r.code: MatchType(r.code, r.strength, r.priority) for r in rows}


def load_active_groups(session: Session, only: set[uuid.UUID] | None = None) -> list[GroupCtx]:
    """Groups whose status is `active` (docs/datos/modelo-v1 §11) with the CIs that currently have the finding."""
    query = text(
        "SELECT g.id, g.cve_id, p.itop_name, c.nvd_vendor, c.nvd_product, c.cna_vendor, c.cna_product "
        "FROM finding_group g JOIN finding_group_status s ON s.finding_group_id = g.id AND s.status = 'active' "
        "JOIN software_product p ON p.id = g.software_product_id "
        "LEFT JOIN cpe_mapping c ON c.software_product_id = p.id ORDER BY g.id"
    )
    groups: list[GroupCtx] = []
    for gid, cve_id, itop_name, nvd_v, nvd_p, cna_v, cna_p in session.execute(query):
        if only is not None and gid not in only:
            continue
        pairs = tuple((v, p) for v, p in ((nvd_v, nvd_p), (cna_v, cna_p)) if v and p)
        names = frozenset({itop_name, *(p for _, p in pairs)})
        cis = session.execute(
            text(
                "SELECT i.id, a.id, a.os, coalesce(fc.observed_version, i.version) "
                "FROM finding f JOIN finding_current fc ON fc.finding_id = f.id AND fc.status <> 'fixed' "
                "JOIN installed_software i ON i.id = f.installed_software_id "
                "JOIN asset a ON a.id = i.asset_id AND a.decommissioned_at IS NULL "
                "WHERE f.finding_group_id = :g ORDER BY a.itop_ci_id"
            ),
            {"g": gid},
        )
        groups.append(GroupCtx(gid, cve_id, names, pairs, tuple(Ci(*row) for row in cis)))
    return groups


def load_story_facts(session: Session, story_id: uuid.UUID) -> StoryFacts | None:
    """The analysis of a story, or None when the analyst has not run on it yet."""
    analysis = session.scalars(select(m.NewsAnalysis).where(m.NewsAnalysis.story_id == story_id)).first()
    if analysis is None:
        return None
    output: dict[str, Any] = analysis.output
    levels = {c["cve"]: c.get("exploitation_level") for c in output.get("cves", [])}
    for mention in session.scalars(select(m.NewsCveMention).where(m.NewsCveMention.analysis_id == analysis.id)):
        levels.setdefault(mention.cve_id, None)
    products = tuple(
        ProductMention(p.vendor, p.product, p.version)
        for p in session.scalars(select(m.NewsProductMention).where(m.NewsProductMention.analysis_id == analysis.id))
    )
    vectors = tuple(
        session.scalars(select(m.NewsAttackVector.vector_code).where(m.NewsAttackVector.analysis_id == analysis.id))
    )
    victims = tuple(session.scalars(select(m.NewsVictim).where(m.NewsVictim.analysis_id == analysis.id)))
    actors = tuple(
        session.scalars(select(m.NewsActorMention.actor_id).where(m.NewsActorMention.analysis_id == analysis.id))
    )
    return StoryFacts(
        story_id, analysis.id, frozenset(output.get("event_types", [])), levels, products, vectors, victims, actors
    )


def _ranges(session: Session, cve_id: str) -> list[m.CveAffectedRange]:
    return list(session.scalars(select(m.CveAffectedRange).where(m.CveAffectedRange.cve_id == cve_id)))


def _product_key(session: Session, facts: StoryFacts, group: GroupCtx) -> str | None:
    """`product_version` when a CI is inside the affected range of the CVE (NVD or CNA, never the news text);
    `product` when the product matches but there is no range data or the version cannot be compared; None when the
    product matches and every CI is known to be outside the range (the CVE does not touch it)."""
    pairs = [
        (vendor, product)
        for mention in facts.products
        for vendor, product in group.vendor_products
        if same_product(mention.vendor, mention.product, vendor, product)
    ]
    if not pairs:
        return None
    ranges = [
        r
        for r in _ranges(session, group.cve_id)
        if any(
            normalize_name(r.vendor) == normalize_name(v) and normalize_name(r.product) == normalize_name(p)
            for v, p in pairs
        )
    ]
    if not ranges:
        return "product"
    verdicts = [
        in_range(ci.version, r.version_start, r.start_inclusive, r.version_end, r.end_inclusive)
        for ci in group.cis
        for r in ranges
    ]
    if any(v is True for v in verdicts):
        return "product_version"
    return "product" if any(v is None for v in verdicts) else None


def match_group(session: Session, facts: StoryFacts, group: GroupCtx) -> set[str]:
    """Every key that matches this story and group (the caller keeps the strongest)."""
    keys: set[str] = set()
    if group.cve_id in facts.cve_levels:
        keys.add("cve_exact")
    product_key = _product_key(session, facts, group)
    if product_key:
        keys.add(product_key)
    if any(os_matches(p.product, p.version, ci.asset_os) for p in facts.products for ci in group.cis):
        keys.add("os")
    if any(vector_matches(v, set(group.product_names)) for v in facts.vectors):
        keys.add("vector")
    return keys


def _relevance_of(match_code: str, facts: StoryFacts, group: GroupCtx) -> str | None:
    found = set()
    if is_r1(match_code, facts.cve_levels.get(group.cve_id)):
        found.add("R1")
    if is_r2(match_code):
        found.add("R2")
    if is_r3(False, False, match_code == "vector"):
        found.add("R3")
    return highest_relevance(found)


def _profile_sectors(session: Session) -> set[str]:
    return set(session.scalars(select(m.ProfileSector.sector_code)))


def _peer_names(session: Session) -> tuple[set[str], set[uuid.UUID]]:
    names: set[str] = set()
    ids: set[uuid.UUID] = set()
    for peer_id, name in session.execute(select(m.PeerCompany.id, m.PeerCompany.name)):
        names.add(normalize_name(name))
        ids.add(peer_id)
    for (alias,) in session.execute(select(m.PeerCompanyAlias.alias)):
        names.add(normalize_name(alias))
    return names, ids


@dataclass(frozen=True)
class PresentProduct:
    """A product running on a live CI, with the names it can be recognized by."""

    installed_software_id: uuid.UUID
    asset_id: uuid.UUID
    version: str
    itop_name: str
    vendor_products: tuple[tuple[str, str], ...]


def _present_products(session: Session) -> list[PresentProduct]:
    rows = session.execute(
        text(
            "SELECT i.id, i.asset_id, i.version, p.itop_name, c.nvd_vendor, c.nvd_product, c.cna_vendor, c.cna_product "
            "FROM installed_software i JOIN software_product p ON p.id = i.software_product_id "
            "LEFT JOIN cpe_mapping c ON c.software_product_id = p.id JOIN asset a ON a.id = i.asset_id "
            "WHERE i.removed_at IS NULL AND a.decommissioned_at IS NULL ORDER BY i.id"
        )
    )
    return [
        PresentProduct(
            inst_id,
            asset_id,
            version,
            itop_name,
            tuple((v, p) for v, p in ((nvd_v, nvd_p), (cna_v, cna_p)) if v and p),
        )
        for inst_id, asset_id, version, itop_name, nvd_v, nvd_p, cna_v, cna_p in rows
    ]


def _mentioned(mention: ProductMention, present: PresentProduct) -> bool:
    """COR-02 again: the news product is present only when vendor and product both match its CPE mapping."""
    return any(same_product(mention.vendor, mention.product, v, p) for v, p in present.vendor_products)


def _actor_history(session: Session, facts: StoryFacts) -> bool:
    """R4: an actor of this story has history in the database (other stories) against the profile's sector or region."""
    if not facts.actor_ids:
        return False
    sectors = _profile_sectors(session)
    countries = set(session.scalars(select(m.ProfileCountry.country_code)))
    if not sectors and not countries:
        return False
    query = (
        select(m.NewsVictim.id)
        .join(m.NewsActorMention, m.NewsActorMention.analysis_id == m.NewsVictim.analysis_id)
        .where(m.NewsActorMention.actor_id.in_(facts.actor_ids), m.NewsVictim.analysis_id != facts.analysis_id)
        .where((m.NewsVictim.sector_code.in_(sectors)) | (m.NewsVictim.country_code.in_(countries)))
        .limit(1)
    )
    return session.scalars(query).first() is not None


def _names_of(item: PresentProduct) -> set[str]:
    return {item.itop_name, *(p for _, p in item.vendor_products)}


def story_relevances(session: Session, facts: StoryFacts) -> set[str]:
    """R2 (a product or OS of the news is in iTop), R3 (peer victim, same sector or vector in iTop) and R4."""
    relevances: set[str] = set()
    present = _present_products(session)
    if any(_mentioned(mention, item) for mention in facts.products for item in present):
        relevances.add("R2")
    peer_names, peer_ids = _peer_names(session)
    sectors = _profile_sectors(session)
    peer = any(v.peer_company_id in peer_ids or normalize_name(v.name) in peer_names for v in facts.victims)
    same_sector = any(v.sector_code in sectors for v in facts.victims if v.sector_code)
    if is_r3(
        peer,
        same_sector,
        any(vector_matches(v, {n for item in present for n in _names_of(item)}) for v in facts.vectors),
    ):
        relevances.add("R3")
    if is_r4(_actor_history(session, facts)):
        relevances.add("R4")
    return relevances


def _upsert_correlation(
    session: Session, group_id: uuid.UUID, placed: Placed, story_id: uuid.UUID, now: datetime
) -> None:
    row = session.scalars(
        select(m.Correlation).where(m.Correlation.finding_group_id == group_id, m.Correlation.story_id == story_id)
    ).first()
    if row is None:
        session.add(
            m.Correlation(
                id=new_id(),
                finding_group_id=group_id,
                story_id=story_id,
                match_type=placed.match_code,
                relevance=placed.relevance,
                correlated_at=now,
            )
        )
    else:
        row.match_type, row.relevance, row.correlated_at = placed.match_code, placed.relevance, now


def _ensure_alert(session: Session, story_id: uuid.UUID, relevance: str, now: datetime) -> uuid.UUID:
    existing = session.scalars(select(m.Alert).where(m.Alert.story_id == story_id)).first()
    if existing is not None:
        return existing.id
    alert = m.Alert(id=new_id(), story_id=story_id, relevance=relevance, status="open", created_at=now)
    session.add(alert)
    session.flush()
    return alert.id


def _alert_assets(session: Session, alert_id: uuid.UUID, facts: StoryFacts) -> None:
    """The CIs an alert touches: those running a product the news names. `version_confirmed` when versions agree."""
    known = set(session.scalars(select(m.AlertAsset.asset_id).where(m.AlertAsset.alert_id == alert_id)))
    for item in _present_products(session):
        for mention in facts.products:
            if item.asset_id in known or not _mentioned(mention, item):
                continue
            confirmed = mention.version is not None and compare_versions(item.version, mention.version) == 0
            session.add(
                m.AlertAsset(
                    alert_id=alert_id,
                    asset_id=item.asset_id,
                    installed_software_id=item.installed_software_id,
                    version_confirmed=confirmed,
                )
            )
            known.add(item.asset_id)


def correlate_story(
    session: Session, story_id: uuid.UUID, now: datetime, groups: list[GroupCtx] | None = None
) -> StoryOutcome | None:
    """Correlate one analyzed story; None when it has no analysis yet. Flushes, the caller commits."""
    facts = load_story_facts(session, story_id)
    if facts is None:
        return None
    types = load_match_types(session)
    limit = get_int(session, "max_matches_per_news")
    outcome = StoryOutcome(story_id)
    found: list[tuple[MatchType, str]] = []
    by_group: dict[str, GroupCtx] = {}
    for group in groups if groups is not None else load_active_groups(session):
        best = best_match(match_group(session, facts, group), types)
        if best is not None:
            found.append((best, str(group.id)))
            by_group[str(group.id)] = group
    kept, cut = keep_strongest(found, limit)
    if cut:
        log.warning("story %s crossed with %d groups; kept the %d strongest", story_id, len(found), limit)
    outcome.dropped = cut
    for match_type, gid in kept:
        group = by_group[gid]
        placed = Placed(group.id, match_type.code, _relevance_of(match_type.code, facts, group))
        _upsert_correlation(session, group.id, placed, story_id, now)
        outcome.matches.append(placed)
        if placed.relevance:
            outcome.relevances.add(placed.relevance)
    session.flush()
    if not outcome.matches:
        relevances = story_relevances(session, facts)
        outcome.relevances = relevances
        top = highest_relevance(relevances - {"R1"})
        if top is not None:
            outcome.alert_id = _ensure_alert(session, story_id, top, now)
            _alert_assets(session, outcome.alert_id, facts)
        else:
            outcome.dismissal_candidate = bool(facts.event_types & SECURITY_EVENT_TYPES)
    session.flush()
    return outcome


def correlate_stories(session: Session, story_ids: list[uuid.UUID], now: datetime) -> list[StoryOutcome]:
    """New news (COR-05): correlate each story against the active groups; commits."""
    groups = load_active_groups(session)
    outcomes = [o for sid in story_ids if (o := correlate_story(session, sid, now, groups)) is not None]
    session.commit()
    return outcomes


def correlate_new_groups(
    session: Session, group_ids: set[uuid.UUID], now: datetime, lookback: timedelta = timedelta(days=7)
) -> list[StoryOutcome]:
    """New scan (COR-05): the groups that are new or changed against the recent analyzed stories; commits.

    The per-news cap applies to the groups of this call; older matches of the same story stay as they are.
    """
    groups = load_active_groups(session, only=group_ids)
    if not groups:
        return []
    story_ids = list(
        session.scalars(
            select(m.NewsAnalysis.story_id)
            .join(m.Story, m.Story.id == m.NewsAnalysis.story_id)
            .where(m.Story.relevance_status == "relevant", m.NewsAnalysis.created_at >= now - lookback)
            .order_by(m.NewsAnalysis.created_at)
        )
    )
    outcomes = [o for sid in story_ids if (o := correlate_story(session, sid, now, groups)) is not None]
    session.commit()
    return outcomes
