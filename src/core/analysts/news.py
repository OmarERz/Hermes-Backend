"""News analyst (docs/05 §2, ANA-01 to ANA-07): one run per relevant story, stored once, never repeated.

Flow: the story must be `relevant` and without an analysis; the budget must allow the call; the model answers with
`submit_news_analysis` (strict tool), the output is validated in layers (schema, then content with verbatim quotes)
with the retry policy; an accepted output is stored as `news_analysis` and normalized into the `news_*` tables and
`claim` so the correlation never reads inside the JSON. A failed story waits in `error_queue` (PRE-01) and the
code still correlates it by CVE and product with reduced certainty (docs/09 §4). The analyst never receives iTop data.

No transaction is open while the model answers (F12.2 #105): a read transaction loads everything the call and its
validation need (the article, the model, which cited CVEs exist) and is committed; then the model answers; then a
short write transaction takes the story's lock, re-checks that the story is still relevant, still has the same
article and still has no analysis, and only then stores the result. The review is stored either way (its tokens
were paid); a stale answer is not applied and the story is analyzed again in the next run.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.analysts import prompt as prompts
from core.analysts.runner import (
    Request,
    ReviewInfo,
    RunResult,
    Seams,
    default_seams,
    record_review,
    run_analyst,
)
from core.correlation.keys import normalize_name, same_product
from core.db import models as m
from core.db.ids import new_id
from core.ingestion.settings import get_decimal, get_setting
from core.llm.client import LlmClient
from core.llm.tools import ToolDefinition, default_schemas_dir, load_tools
from core.validation.budget import BudgetConfig, can_start
from core.validation.budget import spent_on as spent_on_day
from core.validation.content import check_news_analysis, cve_candidates
from core.validation.queue import QueueRef, enqueue_failure, resolve
from core.validation.schema import ToolSchema, validate_schema
from core.validation.violations import Violation

log = logging.getLogger("analysts")

AGENT = "news_analyst"
TOOL_NAME = "submit_news_analysis"
SCHEMA_FILE = "news_analysis_tool.json"
SCHEMA_VERSION = "1"
ESTIMATED_CALL_USD = Decimal("0.01")  # budget gate before a call: a news analysis is a few thousand tokens
ISO_ALPHA2 = 2
# Priority of the event types when a story has several: the analysis keeps the most serious one as `event_type`.
EVENT_PRIORITY = (
    "active_exploitation",
    "organization_attack",
    "actor_campaign",
    "new_vulnerability",
    "public_poc",
    "patch_advisory",
    "other",
    "not_security",
)
# The analyst's sector vocabulary (schemas/news_analysis_tool.json) against the profile catalog (`sector.code`).
SECTOR_MAP = {
    "transportation": "transportation",
    "financial-services": "fintech",
    "retail": "retail",
    "healthcare": "healthcare",
    "government": "government",
}
EXPLOITED = {"limited": "exploited", "active": "exploited", "mass": "exploited", "denied": "not_exploited"}
_SLUG = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class NewsOptions:
    now: datetime | None = None
    seams: Seams | None = None


@dataclass(frozen=True)
class NewsResult:
    story_id: uuid.UUID
    status: str  # analyzed | exists | not_relevant | no_text | budget | queued | stale
    analysis_id: uuid.UUID | None = None
    reason: str | None = None


STALE = "stale"  # the story changed while the model answered: the answer is not applied


def _tool() -> ToolDefinition:
    return load_tools()[TOOL_NAME]


def _schema() -> ToolSchema:
    return ToolSchema.load(SCHEMA_FILE, SCHEMA_VERSION, default_schemas_dir())


def _article(session: Session, story: m.Story) -> tuple[m.RawArticle, str] | None:
    """The representative article and its source code; None when the text was already purged by retention."""
    article = session.get(m.RawArticle, story.representative_article_id)
    if article is None or not article.clean_text:
        return None
    code = session.scalar(
        select(m.Source.code)
        .join(m.SourceFetch, m.SourceFetch.source_id == m.Source.id)
        .where(m.SourceFetch.id == article.source_fetch_id)
    )
    return article, code or ""


def _cve_lookup(session: Session, text: str) -> Callable[[str], bool]:
    """VAL-03.cve_exists without a query while the model answers: the CVEs a verbatim quote of the text could name
    are looked up once, before the call. Any other identifier fails VAL-03.cve_in_quote or the quote rule whether it
    exists or not, so it is let through here and that rule is the one reported (the same as before #105 when the CVE
    exists)."""
    candidates = cve_candidates(text)
    known = frozenset(session.scalars(select(m.Cve.id).where(m.Cve.id.in_(candidates)))) if candidates else frozenset()
    return lambda cve: cve in known or cve not in candidates


def _allowed(session: Session, estimate: Decimal) -> bool:
    config = BudgetConfig(
        daily_usd=get_decimal(session, "daily_budget_usd"), critical_reserve=get_decimal(session, "critical_reserve")
    )
    spent = spent_on_day(session, datetime.now(UTC).date())
    return can_start(config, spent, estimate, critical=False)


def primary_event_type(event_types: list[str]) -> str:
    for code in EVENT_PRIORITY:
        if code in event_types:
            return code
    return "other"


def analyze_story(
    session: Session, client: LlmClient, story_id: uuid.UUID, options: NewsOptions | None = None
) -> NewsResult:
    """Analyze one story. Commits twice: the read transaction before the model call (with anything the caller's
    session already held) and the write transaction after it. Idempotent: a story with an analysis is not analyzed
    again."""
    options = options or NewsOptions()
    now = options.now or datetime.now(UTC)
    prepared = _prepare(session, story_id, now)
    session.commit()  # no transaction stays open while the model answers (an early exit may have queued the story)
    if isinstance(prepared, NewsResult):
        return prepared
    result = run_analyst(client, prepared.request, options.seams or default_seams())
    outcome = _finish(session, prepared, result, now)
    session.commit()
    return outcome


@dataclass(frozen=True)
class _Prepared:
    """What the model call and the write need, read in the first transaction (plain values, no ORM rows)."""

    story_id: uuid.UUID
    article_id: uuid.UUID
    source_fetch_id: uuid.UUID
    published_at: datetime
    request: Request
    info: ReviewInfo


def _lock(session: Session, story_id: uuid.UUID) -> None:
    session.execute(select(func.pg_advisory_xact_lock(func.hashtextextended(f"news-analyst:{story_id}", 0))))


def _prepare(session: Session, story_id: uuid.UUID, now: datetime) -> _Prepared | NewsResult:
    """The read step: the checks that end without a call, then everything the call and its validation need."""
    story = session.get(m.Story, story_id)
    if story is None or story.relevance_status != "relevant":
        return NewsResult(story_id, "not_relevant")
    if session.scalar(select(m.NewsAnalysis.id).where(m.NewsAnalysis.story_id == story_id)) is not None:
        return NewsResult(story_id, "exists")
    found = _article(session, story)
    if found is None:
        return NewsResult(story_id, "no_text")
    article, source_code = found
    if not _allowed(session, ESTIMATED_CALL_USD):
        _lock(session, story_id)
        enqueue_failure(session, QueueRef(AGENT, story_id=story_id), "budget", now)
        return NewsResult(story_id, "budget", reason="budget")
    schema = _schema()
    text = f"{article.title}\n{article.clean_text}"
    exists = _cve_lookup(session, text)

    def validate(output: dict[str, Any]) -> list[Violation]:
        return validate_schema(output, schema) or check_news_analysis(output, text, str(story_id), exists)

    request = Request(
        model=str(get_setting(session, "analyst_model")),
        tool=_tool(),
        system=prompts.NEWS_SYSTEM,
        user=prompts.news_user_message(
            str(story_id), source_code, article.published_at.isoformat(), article.title, article.clean_text or ""
        ),
        validate=validate,
    )
    versions = prompts.fingerprint(prompts.NEWS_PROMPT_VERSION, prompts.NEWS_SYSTEM, schema.version, schema.hash)
    return _Prepared(
        story_id=story_id,
        article_id=article.id,
        source_fetch_id=article.source_fetch_id,
        published_at=article.published_at,
        request=request,
        info=ReviewInfo(AGENT, request, versions, str(story_id)),
    )


def _recheck(session: Session, prepared: _Prepared) -> str | None:
    """Under the story's lock: None when the story is as it was read, else the status that applies now."""
    story = session.get(m.Story, prepared.story_id, populate_existing=True)
    if story is None or story.relevance_status != "relevant":
        return "not_relevant"
    if session.scalar(select(m.NewsAnalysis.id).where(m.NewsAnalysis.story_id == prepared.story_id)) is not None:
        return "exists"
    if story.representative_article_id != prepared.article_id:
        return STALE  # deduplication picked another article: the quotes were checked against the old one
    return None


def _finish(session: Session, prepared: _Prepared, result: RunResult, now: datetime) -> NewsResult:
    """The write step: store the review (paid either way), then the analysis only if the story did not change."""
    story_id = prepared.story_id
    _lock(session, story_id)
    changed = _recheck(session, prepared)
    if changed is not None:
        record_review(session, prepared.info, result if result.failure else replace(result, failure=STALE), now)
        log.info("news analyst: story changed while the model answered (%s); answer not applied", changed)
        return NewsResult(story_id, changed, reason=STALE)
    review = record_review(session, prepared.info, result, now)
    if result.failure is not None or result.outcome is None or result.outcome.output is None:
        enqueue_failure(session, QueueRef(AGENT, story_id=story_id), result.failure or "failed", now)
        return NewsResult(story_id, "queued", reason=result.failure)
    analysis = _store(session, _Subject(prepared, review.id, now), result.outcome.output)
    for row in session.scalars(
        select(m.ErrorQueue).where(m.ErrorQueue.story_id == story_id, m.ErrorQueue.status == "pending")
    ):
        resolve(session, row)  # a retry that works closes its queue item in the same transaction
    return NewsResult(story_id, "analyzed", analysis.id)


@dataclass(frozen=True)
class _Subject:
    prepared: _Prepared
    review_id: uuid.UUID
    now: datetime


def _store(session: Session, subject: _Subject, output: dict[str, Any]) -> m.NewsAnalysis:
    analysis = m.NewsAnalysis(
        id=new_id(),
        story_id=subject.prepared.story_id,
        llm_review_id=subject.review_id,
        summary=output["summary"],
        event_type=primary_event_type(output["event_types"]),
        output=output,
        created_at=subject.now,
    )
    session.add(analysis)
    session.flush()
    _normalize(session, analysis, subject.prepared, output)
    session.flush()
    return analysis


def _country(value: str) -> str | None:
    code = value.strip().upper()
    return code if len(code) == ISO_ALPHA2 and code.isalpha() else None


def _actor(session: Session, name: str, aliases: list[str]) -> uuid.UUID:
    wanted = normalize_name(name)
    for actor in session.scalars(select(m.Actor)):
        known = {normalize_name(actor.name)} | {
            normalize_name(a)
            for a in session.scalars(select(m.ActorAlias.alias).where(m.ActorAlias.actor_id == actor.id))
        }
        if wanted in known:
            actor_id = actor.id
            break
    else:
        actor_id = new_id()
        session.add(m.Actor(id=actor_id, name=name.strip()))
        session.flush()
    have = set(session.scalars(select(m.ActorAlias.alias).where(m.ActorAlias.actor_id == actor_id)))
    for alias in aliases:
        clean = alias.strip()
        if not clean or clean in have:
            continue
        try:
            with session.begin_nested():  # the database keeps aliases unique after normalization
                session.add(m.ActorAlias(actor_id=actor_id, alias=clean))
                session.flush()
        except IntegrityError:
            log.info("alias already belongs to another actor; skipped")
        else:
            have.add(clean)
    return actor_id


def _peer_id(session: Session, name: str) -> uuid.UUID | None:
    wanted = normalize_name(name)
    for peer in session.scalars(select(m.PeerCompany)):
        aliases = session.scalars(select(m.PeerCompanyAlias.alias).where(m.PeerCompanyAlias.peer_company_id == peer.id))
        if wanted in {normalize_name(peer.name), *(normalize_name(a) for a in aliases)}:
            return peer.id
    return None


def _software_product_id(session: Session, vendor: str, product: str) -> uuid.UUID | None:
    rows = session.execute(
        select(m.CpeMapping.software_product_id, m.CpeMapping.nvd_vendor, m.CpeMapping.nvd_product,
               m.CpeMapping.cna_vendor, m.CpeMapping.cna_product)
    )  # fmt: skip
    for product_id, nvd_v, nvd_p, cna_v, cna_p in rows:
        if same_product(vendor, product, nvd_v, nvd_p) or same_product(vendor, product, cna_v, cna_p):
            return uuid.UUID(str(product_id))
    return None


def _normalize(session: Session, analysis: m.NewsAnalysis, prepared: _Prepared, output: dict[str, Any]) -> None:
    for item in output["cves"]:
        if session.get(m.NewsCveMention, (analysis.id, item["cve"])) is None:
            session.add(m.NewsCveMention(analysis_id=analysis.id, cve_id=item["cve"], quote=item["quote"]))
    for item in output["products"]:
        session.add(
            m.NewsProductMention(
                id=new_id(),
                analysis_id=analysis.id,
                vendor=item["vendor"] or None,
                product=item["product"],
                version=item["affected_versions"] or None,
                software_product_id=_software_product_id(session, item["vendor"], item["product"]),
                quote=item["quote"],
            )
        )
    seen_actors: set[uuid.UUID] = set()
    for item in output["actors"]:
        actor_id = _actor(session, item["name"], item["aliases"])
        if actor_id not in seen_actors:
            seen_actors.add(actor_id)
            session.add(m.NewsActorMention(analysis_id=analysis.id, actor_id=actor_id, quote=item["quote"]))
    for item in output["victims"]:
        session.add(
            m.NewsVictim(
                id=new_id(),
                analysis_id=analysis.id,
                name=item["name"],
                peer_company_id=_peer_id(session, item["name"]),
                sector_code=SECTOR_MAP.get(item["sector"]),
                country_code=_country(item["country"]),
                quote=item["quote"],
            )
        )
    vector = _SLUG.sub("_", output["vector"].strip().casefold()).strip("_")
    if vector:
        session.add(m.NewsAttackVector(analysis_id=analysis.id, vector_code=vector, quote=output["vector"].strip()))
    _claims(session, analysis, prepared, output)


def _claims(session: Session, analysis: m.NewsAnalysis, prepared: _Prepared, output: dict[str, Any]) -> None:
    """ANA-06: every verifiable claim is also a `claim`, so the nightly job can confirm or refute it (docs/09 §2)."""
    source_id = session.scalar(select(m.SourceFetch.source_id).where(m.SourceFetch.id == prepared.source_fetch_id))
    if source_id is None:
        return
    single = output["cves"][0]["cve"] if len(output["cves"]) == 1 else None
    claims: list[tuple[str, str | None]] = [
        (EXPLOITED[c["exploitation_level"]], c["cve"]) for c in output["cves"] if c["exploitation_level"] in EXPLOITED
    ]
    claims += [(f"requires_{c['type']}", single) for c in output["conditions"] if c["type"] in ("authentication",)]
    claims += [("local_access", single) for c in output["conditions"] if c["type"] == "local_access"]
    if output["signals"]["public_poc"] and single is not None:  # without one CVE the claim cannot be resolved
        claims.append(("public_poc", single))
    if "patch_advisory" in output["event_types"] and single:
        claims.append(("patched", single))
    for claim_type, cve_id in dict.fromkeys(claims):
        session.add(
            m.Claim(
                id=new_id(),
                analysis_id=analysis.id,
                source_id=source_id,
                claim_type=claim_type,
                cve_id=cve_id,
                claimed_at=prepared.published_at,
                status="pending",
            )
        )


def pending_stories(session: Session, limit: int = 50) -> list[uuid.UUID]:
    """Relevant stories without an analysis, oldest first (ANA-01)."""
    stmt = (
        select(m.Story.id)
        .where(m.Story.relevance_status == "relevant")
        .where(~select(m.NewsAnalysis.id).where(m.NewsAnalysis.story_id == m.Story.id).exists())
        .where(  # a story that used up its automatic retries waits for a person (PRE-01), it does not fill the batch
            ~select(m.ErrorQueue.id)
            .where(
                m.ErrorQueue.story_id == m.Story.id,
                m.ErrorQueue.component == AGENT,
                m.ErrorQueue.status == "pending",
                m.ErrorQueue.next_attempt_at.is_(None),
            )
            .exists()
        )
        .order_by(m.Story.created_at, m.Story.id)
        .limit(limit)
    )
    return list(session.scalars(stmt))


def analyze_pending(
    session: Session, client: LlmClient, options: NewsOptions | None = None, limit: int = 50
) -> list[NewsResult]:
    """Analyze the pending stories one by one; a failing story never stops the next one. Commits per story (each
    story is a read transaction and a write transaction, with the model call between them)."""
    options = options or NewsOptions()
    shared = replace(options, seams=options.seams or default_seams())  # one circuit breaker for the whole batch
    results = []
    for story_id in pending_stories(session, limit):
        results.append(analyze_story(session, client, story_id, shared))
    log.info("news analyst: %d stories, %d analyzed", len(results), sum(r.status == "analyzed" for r in results))
    return results
