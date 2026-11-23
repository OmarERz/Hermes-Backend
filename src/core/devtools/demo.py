"""`make demo`: demo data plus one full cycle, with no network and no tokens (docs/12 F13, docs/15 F-01 and F-02).

    python -m core.devtools.demo

It loads the `demo` inventory on a database that already has its factory values, adds synthetic CVE ranges,
a second vulnerable product, news with their analyses and an indicator, and then runs once, in this order:

1. the simulated scan (findings, lifecycle, one scan at a time);
2. the correlation of the news with the groups (matches, alerts);
3. the scoring of every group with the deterministic engine; the judge is a **stand-in**: where a news item ties a
   KEV CVE to the group it records one accepted reason of +8 points, citing the demo news, as an `llm_review` of
   the model `demo-double`. No LLM client is created and no key is read, so a demo can never spend tokens;
4. the ticket rules, which write the iTop operations to the outbox and the notification events. The operations are
   saved as `failed` ("demo data: never sent to iTop") in the same transaction, so the outbox worker, which only
   claims pending rows, can never send them even when iTop is configured. The tickets get the demo ids DEMO-1,
   DEMO-2... (open), which stands in for iTop's answer so that the tickets view has something to show.

It refuses to run when the database holds assets other than the demo ones, so it cannot mix fake CIs into a real
CMDB. The notification events are real rows: do not switch the consumer to Slack on a demo installation.

Every step is idempotent: running it again adds an assessment per group but no duplicate data, ticket or event.
It runs as the migrator role (MIGRATION_DATABASE_URL and the migrator_db_password secret), like `seed`.
"""

from __future__ import annotations

import sys
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from core.correlation.engine import correlate_stories
from core.db import models as m
from core.db.seeds import seed_demo_inventory
from core.db.session import make_engine
from core.devtools.admin import AdminError, _url
from core.ingestion.catalog import sync_default_sources
from core.scan.engine import ScanOptions, run_scan
from core.scoring.engine import (
    Confidentiality,
    Criticality,
    ExploitationGrade,
    Factors,
    ThreatEvidence,
    asset_level,
    base_score,
    data_sensitivity,
    exploitation_level,
    final_score,
    floor_eligible,
    severity,
    threat,
    trend_level,
)
from core.scoring.formula_repo import load_active_formula
from core.tickets.content import ItopIdentity
from core.tickets.lifecycle import TicketLifecycle

DEMO_REASON = "mass_exploitation"
DEMO_ADJUSTMENT = 8
DEMO_MODEL = "demo-double"
DEMO_CIS = ("CI-1", "CI-2", "CI-3")
PARKED_REASON = "demo data: never sent to iTop"
_LIVE = text(
    "SELECT i.asset_id FROM finding_current fc JOIN installed_software i ON i.id = fc.installed_software_id "
    "JOIN asset a ON a.id = i.asset_id WHERE fc.finding_group_id = :group_id "
    "AND fc.status IN ('new', 'persistent', 'reopened', 'no_data') AND a.decommissioned_at IS NULL"
)
NEWS_SOURCE = "demo_news"
CVE_STORIES = 2  # the first two stories tie CVE-2026-10001 to the inventory
NEWS: tuple[tuple[str, str, str], ...] = (  # the third names a CMDB product with no known CVE (R2 alert)
    (
        "https://news.example.test/openssl-exploited",
        "Explotan una falla de OpenSSL en ataques dirigidos",
        "Atacantes aprovechan CVE-2026-10001 en OpenSSL 3.0.7 contra servidores expuestos.",
    ),
    (
        "https://news.example.test/openssl-patch",
        "Parche urgente para OpenSSL 3.0",
        "Se publicó OpenSSL 3.0.8 para corregir CVE-2026-10001, ya explotada.",
    ),
    (
        "https://news.example.test/redis-campaign",
        "Campaña de escaneo contra servidores Redis expuestos",
        "Un grupo escanea servidores Redis 7.0 expuestos a internet en busca de fallas sin parche.",
    ),
)
ITOP_ORG = "1"  # demo identity: nothing is sent to iTop, the outbox only stores the operations
ITOP_CALLER = "1"


@dataclass
class DemoReport:
    scan_new: int = 0
    scan_persistent: int = 0
    stories: int = 0
    matches: int = 0
    alerts: int = 0
    assessments: int = 0
    tickets: int = 0
    outbox: int = 0
    parked: int = 0
    events: int = 0
    notes: list[str] = field(default_factory=list)


# --- data ------------------------------------------------------------------------------------------------------------
def _team(session: Session, itop_id: str) -> m.Team:
    return session.scalars(select(m.Team).where(m.Team.itop_team_id == itop_id)).one()


def _ensure_product(session: Session, name: str, vendor: str, now: datetime) -> m.SoftwareProduct:
    product = session.scalars(select(m.SoftwareProduct).where(m.SoftwareProduct.itop_name == name)).first()
    if product is None:
        product = m.SoftwareProduct(itop_name=name, first_seen_at=now)
        session.add(product)
        session.flush()
    if session.get(m.CpeMapping, product.id) is None:
        session.add(
            m.CpeMapping(
                software_product_id=product.id,
                nvd_vendor=vendor,
                nvd_product=name.lower(),
                origin="manual",
                mapped_at=now,
            )
        )
    return product


def _range(session: Session, cve_id: str, name: tuple[str, str], start: str | None, end: str) -> None:
    vendor, product = name
    exists = session.scalar(
        select(m.CveAffectedRange.id).where(m.CveAffectedRange.cve_id == cve_id, m.CveAffectedRange.product == product)
    )
    if exists is None:
        session.add(
            m.CveAffectedRange(
                cve_id=cve_id,
                source="nvd_cpe",
                vendor=vendor,
                product=product,
                version_start=start,
                start_inclusive=None if start is None else True,
                version_end=end,
                end_inclusive=False,
            )
        )


def _second_vulnerability(session: Session, now: datetime) -> None:
    """A web server with an exposed, public-data CI of the default team and a CVE with no KEV entry."""
    if session.get(m.Cve, "CVE-2026-10002") is not None:
        return
    product = _ensure_product(session, "nginx", "f5", now)
    session.add(
        m.Cve(
            id="CVE-2026-10002",
            description="Desbordamiento de memoria en el módulo de HTTP/3 (dato sintético de la demo)",
            published_at=now - timedelta(days=5),
            last_modified_at=now - timedelta(days=4),
            cvss_version="3.1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            cvss_score=Decimal("7.5"),
            cvss_source="nvd",
            fetched_at=now,
        )
    )
    session.flush()
    session.add(
        m.EpssScore(cve_id="CVE-2026-10002", score_date=now.date(), epss=Decimal("0.42"), percentile=Decimal("0.88"))
    )
    _range(session, "CVE-2026-10002", ("f5", "nginx"), "1.20.0", "1.25.3")
    web = m.Asset(
        itop_ci_id="CI-3",
        itop_class="Server",
        name="srv-web-03",
        criticality="medium",
        exposed=True,
        confidentiality="public",
        personal_data=False,
        custodian_team_id=_team(session, "T-1").id,
        synced_at=now,
    )
    session.add(web)
    session.flush()
    redis = _ensure_product(session, "Redis", "redis", now)
    for instance, software, version in (("SI-3", product, "1.24.0"), ("SI-4", redis, "7.0.5")):
        session.add(
            m.InstalledSoftware(
                itop_instance_id=instance,
                asset_id=web.id,
                software_product_id=software.id,
                version=version,
                synced_at=now,
            )
        )


def _news(session: Session, now: datetime) -> list[uuid.UUID]:
    """Two analysed stories about CVE-2026-10001, with an actor and a product mention; returns the story ids."""
    source = session.scalars(select(m.Source).where(m.Source.code == NEWS_SOURCE)).first()
    if source is None:
        source = m.Source(
            code=NEWS_SOURCE,
            name="Noticias de la demo",
            kind="rss",
            url="https://news.example.test/feed",
            trust_tier="N3",
            is_structural=False,
            is_custom=True,
            enabled=False,
            created_at=now,
        )
        session.add(source)
        session.flush()
    run = session.scalars(select(m.Run).where(m.Run.kind == "news").limit(1)).first()
    if run is None:
        run = m.Run(kind="news", status="succeeded", progress=100, trigger_reason="manual", started_at=now)
        session.add(run)
    session.flush()
    fetch = m.SourceFetch(source_id=source.id, run_id=run.id, started_at=now, status="ok", items_new=len(NEWS))
    ids: list[uuid.UUID] = []
    fresh = False
    for index, (url, title, quote) in enumerate(NEWS):
        existing = session.scalars(select(m.RawArticle).where(m.RawArticle.canonical_url == url)).first()
        if existing is not None and existing.story_id is not None:
            ids.append(existing.story_id)
            continue
        if not fresh:
            session.add(fetch)
            session.flush()
            fresh = True
        article = m.RawArticle(
            source_fetch_id=fetch.id,
            canonical_url=url,
            title=title,
            published_at=now - timedelta(hours=6 * (index + 1)),
            captured_at=now,
            is_suspicious=False,
        )
        session.add(article)
        session.flush()
        story = m.Story(representative_article_id=article.id, relevance_status="relevant", created_at=now)
        session.add(story)
        session.flush()
        article.story_id = story.id
        _analysis(session, story.id, quote, index, now)
        ids.append(story.id)
    return ids


def _analysis(session: Session, story_id: uuid.UUID, quote: str, index: int, now: datetime) -> None:
    review = m.LlmReview(
        agent="news_analyst",
        model=DEMO_MODEL,
        response_model={"demo": True},
        prompt_version="demo",
        prompt_hash="demo",
        schema_version="demo",
        schema_hash="demo",
        parameters={},
        input_ref=f"demo-story-{index}",
        calls=[],
        status="applied",
        attempts=1,
        tokens_input=0,
        tokens_cached=0,
        tokens_output=0,
        tokens_reasoning=0,
        cost_usd=Decimal(0),
        latency_ms=0,
        ladder_level=0,
        created_at=now,
    )
    session.add(review)
    session.flush()
    with_cve = index < CVE_STORIES
    output = {
        "event_types": ["exploitation" if with_cve else "campaign"],
        "cves": [{"cve": "CVE-2026-10001", "exploitation_level": "active"}] if with_cve else [],
    }
    analysis = m.NewsAnalysis(
        story_id=story_id,
        llm_review_id=review.id,
        summary=quote,
        event_type="exploitation" if with_cve else "campaign",
        output=output,
        created_at=now,
    )
    session.add(analysis)
    session.flush()
    actor = session.scalars(select(m.Actor).where(m.Actor.name == "Grupo Demo")).first()
    if actor is None:
        actor = m.Actor(name="Grupo Demo")
        session.add(actor)
        session.flush()
    if with_cve:
        session.add(m.NewsCveMention(analysis_id=analysis.id, cve_id="CVE-2026-10001", quote=quote))
    session.add(m.NewsActorMention(analysis_id=analysis.id, actor_id=actor.id, quote=quote))
    vendor, product, version = ("openssl", "openssl", "3.0.7") if with_cve else ("redis", "redis", "7.0.5")
    session.add(
        m.NewsProductMention(analysis_id=analysis.id, vendor=vendor, product=product, version=version, quote=quote)
    )
    session.flush()


def _indicator(session: Session, now: datetime) -> None:
    source = session.scalars(select(m.Source).where(m.Source.code == "threatfox")).first()
    if source is None or session.scalar(select(m.Ioc.id).where(m.Ioc.value == "demo-c2.example.test")) is not None:
        return
    ioc = m.Ioc(
        ioc_type="domain",
        value="demo-c2.example.test",
        malware_family="DemoLoader",
        source_id=source.id,
        first_seen_at=now - timedelta(days=2),
        last_seen_at=now,
    )
    session.add(ioc)
    session.flush()
    session.add(m.IocCve(ioc_id=ioc.id, cve_id="CVE-2026-10001"))


def load_demo_data(session: Session, now: datetime) -> list[uuid.UUID]:
    """The demo data, each part only if missing. Returns the story ids."""
    sync_default_sources(session, now)
    seed_demo_inventory(session)
    _range(session, "CVE-2026-10001", ("openssl", "openssl"), "3.0.0", "3.0.8")
    _second_vulnerability(session, now)
    _indicator(session, now)
    stories = _news(session, now)
    session.flush()
    return stories


# --- the cycle ---------------------------------------------------------------------------------------------
def _grade(session: Session, cve_id: str) -> ExploitationGrade:
    """The strongest exploitation grade the analysed news give this CVE."""
    grades = {
        ExploitationGrade(level)
        for (output,) in session.execute(
            select(m.NewsAnalysis.output)
            .join(m.NewsCveMention, m.NewsCveMention.analysis_id == m.NewsAnalysis.id)
            .where(m.NewsCveMention.cve_id == cve_id)
        )
        for item in output.get("cves", [])
        if item["cve"] == cve_id and (level := item.get("exploitation_level"))
    }
    for grade in (ExploitationGrade.MASS, ExploitationGrade.ACTIVE, ExploitationGrade.LIMITED, ExploitationGrade.NONE):
        if grade in grades:
            return grade
    return ExploitationGrade.NONE


def _news_evidence(
    session: Session, group_id: uuid.UUID, now: datetime
) -> tuple[list[ThreatEvidence], int, uuid.UUID | None]:
    """T evidence from the stories correlated to the group: the trend of distinct sources and the newest age."""
    rows = session.execute(
        select(m.RawArticle.published_at, m.SourceFetch.source_id, m.NewsAnalysis.id)
        .join(m.Story, m.Story.representative_article_id == m.RawArticle.id)
        .join(m.Correlation, m.Correlation.story_id == m.Story.id)
        .join(m.NewsAnalysis, m.NewsAnalysis.story_id == m.Story.id)
        .join(m.SourceFetch, m.SourceFetch.id == m.RawArticle.source_fetch_id)
        .where(m.Correlation.finding_group_id == group_id)
        .order_by(m.RawArticle.published_at.desc())
    ).all()
    if not rows:
        return [], 0, None
    sources = {row[1] for row in rows}
    code = trend_level(len(sources))
    age = max(0, (now - rows[0][0]).days)
    return ([ThreatEvidence(code, age)] if code else []), len(rows), rows[0][2]


def _judge_double(session: Session, analysis_id: uuid.UUID, now: datetime) -> m.LlmReview:
    review = m.LlmReview(
        agent="judge",
        mode="scoring",
        model=DEMO_MODEL,
        response_model={"demo": True},
        prompt_version="demo",
        prompt_hash="demo",
        schema_version="demo",
        schema_hash="demo",
        parameters={},
        input_ref="demo",
        calls=[],
        status="applied",
        attempts=1,
        tokens_input=0,
        tokens_cached=0,
        tokens_output=0,
        tokens_reasoning=0,
        cost_usd=Decimal(0),
        latency_ms=0,
        ladder_level=0,
        created_at=now,
    )
    session.add(review)
    session.flush()
    session.add(
        m.JudgeReason(
            llm_review_id=review.id,
            seq=1,
            reason_code=DEMO_REASON,
            points=DEMO_ADJUSTMENT,
            element_id=str(analysis_id),
            quote=NEWS[0][2],
            status="accepted",
        )
    )
    return review


def score_group(session: Session, group: m.FindingGroup, run_id: uuid.UUID, now: datetime) -> uuid.UUID | None:
    """Assess one group with the deterministic engine (S, P, T per group; A, D per CI); the judge is the double."""
    version_id, formula = load_active_formula(session)
    cve = session.get_one(m.Cve, group.cve_id)
    live = session.execute(_LIVE, {"group_id": group.id}).all()
    if not live:
        return None
    in_kev = session.get(m.KevEntry, cve.id) is not None
    epss = session.scalars(
        select(m.EpssScore).where(m.EpssScore.cve_id == cve.id).order_by(m.EpssScore.score_date.desc())
    ).first()
    poc = (
        session.scalar(
            select(m.CveReferenceTag.tag)
            .join(m.CveReference, m.CveReference.id == m.CveReferenceTag.reference_id)
            .where(m.CveReference.cve_id == cve.id, m.CveReferenceTag.tag == "Exploit")
        )
        is not None
    )
    s_value, _ = severity(formula, cve.cvss_score)
    p_level = exploitation_level(
        in_kev=in_kev, grade=_grade(session, cve.id), public_poc=poc, epss_percentile=epss.percentile if epss else None
    )
    evidence, _count, analysis_id = _news_evidence(session, group.id, now)
    t_value = threat(formula, evidence)
    review = _judge_double(session, analysis_id, now) if (in_kev and analysis_id is not None) else None
    adjustment = DEMO_ADJUSTMENT if review is not None else None
    assessment = m.Assessment(
        finding_group_id=group.id,
        run_id=run_id,
        formula_version_id=version_id,
        llm_review_id=review.id if review else None,
        trigger="manual",
        factor_s=s_value,
        factor_p=formula.level("P", p_level),
        factor_t=t_value,
        judge_adjustment=adjustment or 0,
        raw_cvss_score=cve.cvss_score,
        raw_cvss_version=cve.cvss_version,
        raw_epss=epss.epss if epss else None,
        raw_epss_percentile=epss.percentile if epss else None,
        raw_in_kev=in_kev,
        assessed_at=now,
    )
    session.add(assessment)
    session.flush()
    for (asset_id,) in {(row.asset_id,) for row in live}:
        asset = session.get_one(m.Asset, asset_id)
        a_value = formula.level("A", asset_level(Criticality(asset.criticality), asset.exposed))
        d_value = data_sensitivity(formula, Confidentiality(asset.confidentiality), asset.personal_data)
        factors = Factors(s_value, formula.level("P", p_level), t_value, a_value, d_value)
        base = base_score(formula, factors)
        final = final_score(
            formula, base, judge_adjustment=adjustment, floor=floor_eligible(in_kev=in_kev, exposed=asset.exposed)
        )
        session.add(
            m.AssetScore(
                assessment_id=assessment.id,
                asset_id=asset.id,
                factor_a=a_value,
                factor_d=d_value,
                version_factor=Decimal(1),
                base=base,
                ci_adjustment=0,
                final=final.final,
                snap_criticality=asset.criticality,
                snap_exposed=asset.exposed,
                snap_confidentiality=asset.confidentiality,
                snap_personal_data=asset.personal_data,
                snap_owner_person_id=asset.owner_person_id,
                snap_custodian_team_id=asset.custodian_team_id,
            )
        )
    session.flush()
    return assessment.id


def refuse_over_real_data(session: Session) -> None:
    """The demo only runs where there is nothing but demo data (it would mix fake CIs into a real CMDB)."""
    foreign = session.scalar(select(func.count()).select_from(m.Asset).where(m.Asset.itop_ci_id.not_in(DEMO_CIS)))
    if foreign:
        raise AdminError("the database holds assets that are not demo data; the demo only runs on a clean installation")


def park_demo_operations(session: Session) -> int:
    """Mark the demo's iTop operations as never to be sent: the outbox worker only claims pending rows."""
    parked = session.scalars(
        update(m.ItopOutbox)
        .where(m.ItopOutbox.status == "pending")
        .values(status="failed", next_attempt_at=None, last_error=PARKED_REASON)
        .returning(m.ItopOutbox.id)
    ).all()
    return len(parked)


_CONFIRM_TICKETS = text(
    "UPDATE ticket SET status = 'open', itop_ticket_id = 'DEMO-' || (s.n + s.base), "
    "itop_ref = 'DEMO-' || (s.n + s.base), itop_created_at = :now "
    "FROM (SELECT id, row_number() OVER (ORDER BY created_at, id) AS n, "
    "(SELECT count(*) FROM ticket WHERE itop_ticket_id LIKE 'DEMO-%') AS base "
    "FROM ticket WHERE status = 'pending_creation') s WHERE ticket.id = s.id"
)


def confirm_demo_tickets(session: Session, now: datetime) -> None:
    """Stand in for iTop's answer: the tickets view lists what iTop already holds, so give them a demo id."""
    session.execute(_CONFIRM_TICKETS, {"now": now})


def run_cycle(factory: sessionmaker[Session], now: datetime | None = None) -> DemoReport:
    """Load the demo data and run the cycle once; the report counts what exists afterwards."""
    now = now or datetime.now(UTC)
    report = DemoReport()
    with factory() as session, session.begin():
        refuse_over_real_data(session)
        stories = load_demo_data(session, now)
    scan = run_scan(factory, ScanOptions(reason="manual"), now=now)
    report.scan_new, report.scan_persistent = scan.new, scan.persistent
    with factory() as session:
        outcomes = correlate_stories(session, stories, now)  # commits
        report.stories = len(outcomes)
        report.matches = sum(len(o.matches) for o in outcomes)
        report.alerts = sum(1 for o in outcomes if o.alert_id is not None)
    with factory() as session, session.begin():
        lifecycle = TicketLifecycle(ItopIdentity(ITOP_ORG, ITOP_CALLER), None, lambda: now)
        for group in session.scalars(select(m.FindingGroup).order_by(m.FindingGroup.created_at, m.FindingGroup.id)):
            assessment_id = score_group(session, group, scan.run_id, now)
            if assessment_id is None:
                continue
            report.assessments += 1
            lifecycle.apply(session, assessment_id)
        confirm_demo_tickets(session, now)
        report.parked = park_demo_operations(session)  # same transaction: the worker never sees them pending
    with factory() as session:
        report.tickets = int(session.scalar(select(func.count()).select_from(m.Ticket)) or 0)
        report.outbox = int(session.scalar(select(func.count()).select_from(m.ItopOutbox)) or 0)
        report.events = int(session.scalar(select(func.count()).select_from(m.NotificationEvent)) or 0)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    try:
        engine = make_engine(_url("MIGRATION_DATABASE_URL", "migrator_db_password"))
    except AdminError as error:
        sys.stderr.write(f"error: {error}\n")
        return 2
    try:
        report = run_cycle(sessionmaker(engine, expire_on_commit=False))
    finally:
        engine.dispose()
    sys.stdout.write(
        "demo ready: "
        f"scan {report.scan_new} new and {report.scan_persistent} persistent finding(s); "
        f"{report.stories} stories correlated ({report.matches} match(es), {report.alerts} alert(s)); "
        f"{report.assessments} assessment(s); {report.tickets} ticket(s), {report.outbox} iTop operation(s) "
        f"parked in the outbox (never sent) and {report.events} notification event(s)\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
