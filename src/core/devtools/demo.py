"""`make demo`: demo data plus one full cycle, with no network and no tokens (docs/12 F13, docs/15 F-01 and F-02).

    python -m core.devtools.demo

It loads the `demo` inventory on a database that already has its factory values, adds synthetic CVE ranges,
a second vulnerable product, news with their analyses and an indicator, and then runs once, in this order:

1. the simulated scan (findings, lifecycle, one scan at a time);
2. the correlation of the news with the groups (matches, alerts);
3. the scoring of every group through the real path (`evaluate_group`: engine, assessment, per-CI scores); the judge
   is a **stand-in**: for the group of CVE-2026-10001 it records one accepted reason of +8 points, citing the demo
   news, as an `llm_review` of the model `demo-double`.
   No LLM client is created and no key is read, so a demo can never spend tokens;
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
from typing import Any

from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from core.correlation.engine import correlate_stories
from core.correlation.packages import store_package
from core.db import models as m
from core.db.seeds import seed_demo_inventory
from core.db.session import make_engine
from core.devtools.admin import AdminError, database_url_from_env
from core.ingestion.catalog import sync_default_sources
from core.scan.engine import ScanOptions, run_scan
from core.scoring.evaluate import EvaluationOptions, GroupNotActiveError, JudgeFn, JudgeVerdict, evaluate_group
from core.tickets.content import ItopIdentity
from core.tickets.lifecycle import TicketLifecycle

DEMO_REASON = "mass_exploitation"
DEMO_ADJUSTMENT = 8
DEMO_MODEL = "demo-double"
DEMO_CIS = ("CI-1", "CI-2", "CI-3")
PARKED_REASON = "demo data: never sent to iTop"
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
                nvd_part="a",
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
def _judge_double(session: Session, now: datetime) -> JudgeFn:
    """A stand-in for the judge: +8 for the group of CVE-2026-10001 (news about its exploitation), 0 for the rest.
    It records its review and reason like the real one but creates no LLM client and reads no key."""

    def judge(package: dict[str, Any]) -> JudgeVerdict:
        exploited = package["group"]["cve"] == "CVE-2026-10001" and bool(package["news"])
        adjustment = DEMO_ADJUSTMENT if exploited else 0
        stored = store_package(session, package, now)
        review = m.LlmReview(
            agent="judge",
            review_package_id=stored.id,
            mode="scoring",
            model=DEMO_MODEL,
            response_model={"demo": True},
            prompt_version="demo",
            prompt_hash="demo",
            schema_version="demo",
            schema_hash="demo",
            parameters={},
            input_ref=package["package_id"],
            calls=[],
            status="applied",
            attempts=1,
            proposed_adjustment=adjustment,
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
        if exploited:
            analysis_id = session.scalars(
                select(m.NewsAnalysis.id)
                .join(m.NewsCveMention, m.NewsCveMention.analysis_id == m.NewsAnalysis.id)
                .where(m.NewsCveMention.cve_id == "CVE-2026-10001")
                .order_by(m.NewsAnalysis.created_at, m.NewsAnalysis.id)
            ).first()
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
            session.flush()
        return JudgeVerdict(adjustment, review.id)

    return judge


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
        options = EvaluationOptions(judge=_judge_double(session, now), tickets=lifecycle, now=now)
        for group in session.scalars(select(m.FindingGroup).order_by(m.FindingGroup.created_at, m.FindingGroup.id)):
            try:
                evaluation = evaluate_group(session, group.id, scan.run_id, "manual", options)
            except GroupNotActiveError:
                continue
            report.assessments += evaluation.assessment_id is not None
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
        engine = make_engine(database_url_from_env("MIGRATION_DATABASE_URL", "migrator_db_password"))
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
