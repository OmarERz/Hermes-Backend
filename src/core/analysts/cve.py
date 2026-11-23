"""CVE analyst (docs/05 §3, ANA-10 to ANA-15): conditions, components and, only when no CVSS exists, an inferred vector.

One run per CVE, stored once. The material is the CVE description, its CWE, its references and, when the code could
download it from an allowed domain (D-014), the vendor advisory text. The model never gives a score: the vector is
validated for CVSS 3.1 syntax and the **code** computes the score (`core.scoring.cvss`); the scoring engine marks
that S as estimated (ANA-14). The analyst does not write mitigations (D-017).

No transaction is open while the advisory downloads or the model answers (F12.2 #105): a read transaction loads the
CVE, its CWEs and its references, and is committed; then the advisory is downloaded and the
model answers; then a short write transaction takes the CVE's lock and re-checks that the CVE still exists with the
same description and CVSS and still has no analysis before storing it. The review is stored either way (its tokens
were paid); a stale answer is not applied and the CVE is analyzed again in the next run.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Protocol
from urllib.parse import urlsplit

from sqlalchemy import func, select, text
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
from core.db import models as m
from core.db.ids import new_id
from core.ingestion.article import extract_article
from core.ingestion.cleaning import clean_html, clean_plain
from core.ingestion.fetcher import ARTICLE_CONTENT_TYPES, Fetcher, FetchError
from core.ingestion.settings import get_decimal, get_setting
from core.llm.client import ToolCaller
from core.llm.tools import ToolDefinition, default_schemas_dir, load_tools
from core.scoring.cvss import base_score
from core.validation.budget import BudgetConfig, can_start
from core.validation.budget import spent_on as spent_on_day
from core.validation.content import check_cve_analysis
from core.validation.queue import QueueRef, enqueue_failure, resolve
from core.validation.schema import ToolSchema, validate_schema
from core.validation.violations import Violation

log = logging.getLogger("analysts")

AGENT = "cve_analyst"
TOOL_NAME = "submit_cve_analysis"
SCHEMA_FILE = "cve_analysis_tool.json"
SCHEMA_VERSION = "1"
ESTIMATED_CALL_USD = Decimal("0.01")
MAX_REFERENCES = 30
# D-014 level 2: advisory pages are downloaded only from domains on an allowlist. The default is the list of
# official vendor and distribution advisory sites approved by the user (docs/02 section 4). The environment variable
# ADVISORY_DOMAINS (comma-separated host names) replaces it; set to an empty value it disables the downloads, and
# the analyst then works from the CVE record alone.
ADVISORY_DOMAINS_ENV = "ADVISORY_DOMAINS"
DEFAULT_ADVISORY_DOMAINS: tuple[str, ...] = (
    "access.redhat.com",
    "debian.org",
    "fortiguard.com",
    "helpx.adobe.com",
    "kb.vmware.com",
    "msrc.microsoft.com",
    "openssl.org",
    "oracle.com",
    "sec.cloudapps.cisco.com",
    "security.debian.org",
    "security.paloaltonetworks.com",
    "support.apple.com",
    "support.broadcom.com",
    "ubuntu.com",
)


def advisory_domains() -> tuple[str, ...]:
    raw = os.environ.get(ADVISORY_DOMAINS_ENV)
    if raw is None:
        return DEFAULT_ADVISORY_DOMAINS
    return tuple(sorted({d.strip().lower().lstrip(".") for d in raw.split(",") if d.strip()}))


class AdvisoryProvider(Protocol):
    def __call__(self, urls: list[str]) -> str | None: ...


def web_advisory_provider(fetcher: Fetcher, allowed: tuple[str, ...] | None = None) -> AdvisoryProvider:
    """Download the first `Vendor Advisory` page whose host is an allowed domain (or a subdomain of one)."""

    domains = advisory_domains() if allowed is None else allowed

    def host_allowed(host: str) -> bool:
        name = host.lower()
        return any(name == d or name.endswith("." + d) for d in domains)

    def provide(urls: list[str]) -> str | None:
        for url in urls:
            if not host_allowed(urlsplit(url).hostname or ""):
                continue
            try:
                page = fetcher.get(url, ARTICLE_CONTENT_TYPES, host_allowed)  # every redirect hop is checked too
            except FetchError as exc:
                log.info("advisory not downloaded: %s", exc)
                continue
            article = extract_article(page.body.decode("utf-8", errors="replace"))
            if article is not None and article.text:
                return article.text
        return None

    return provide


@dataclass(frozen=True)
class CveOptions:
    now: datetime | None = None
    seams: Seams | None = None
    advisory: AdvisoryProvider | None = None


@dataclass(frozen=True)
class CveResult:
    cve_id: str
    status: str  # analyzed | exists | no_cve | budget | queued | stale
    analysis_id: object | None = None
    reason: str | None = None
    inferred_score: Decimal | None = None


def _tool() -> ToolDefinition:
    return load_tools()[TOOL_NAME]


STALE = "stale"  # the CVE changed while the model answered: the answer is not applied


@dataclass(frozen=True)
class Material:
    """What the model receives, and the part of it a quote may come from (description and advisory, as sent)."""

    text: str
    quotable: str


@dataclass(frozen=True)
class CveFacts:
    """The CVE as the read transaction saw it: everything the material and the validation need, as plain values."""

    cve_id: str
    cvss_score: Decimal | None
    description: str | None
    cwes: tuple[str, ...]
    references: tuple[tuple[str, tuple[str, ...]], ...]  # (url, tags), at most MAX_REFERENCES
    advisory_urls: tuple[str, ...]


def _facts(session: Session, cve: m.Cve) -> CveFacts:
    cwes = tuple(sorted(session.scalars(select(m.CveCwe.cwe_id).where(m.CveCwe.cve_id == cve.id))))
    references = []
    for ref in session.scalars(select(m.CveReference).where(m.CveReference.cve_id == cve.id).limit(MAX_REFERENCES)):
        tags = sorted(session.scalars(select(m.CveReferenceTag.tag).where(m.CveReferenceTag.reference_id == ref.id)))
        references.append((ref.url, tuple(tags)))
    return CveFacts(
        cve.id, cve.cvss_score, cve.description, cwes, tuple(references), tuple(_advisory_urls(session, cve.id))
    )


def _material(facts: CveFacts, advisory: str | None) -> Material:
    """External text is cleaned first (SEG-01). Order: header, description, advisory, then references, so that the
    cut at the context limit falls on the references and never on text a quote may cite."""
    header = "\n".join(
        [
            f"CVE: {facts.cve_id}",
            f"CVSS: {facts.cvss_score if facts.cvss_score is not None else 'ninguno'}",
            f"CWE: {', '.join(clean_plain(c).text for c in facts.cwes) if facts.cwes else 'ninguno'}",
        ]
    )
    description = clean_html(facts.description or "").text
    body = description
    if advisory:
        body += "\nAviso del fabricante:\n" + clean_html(advisory).text
    room = max(0, prompts.MAX_ARTICLE_CHARS - len(header) - 1)
    lines = [header, body[:room]]
    for url, tags in facts.references:
        lines.append(f"Referencia: {clean_plain(url).text} [{', '.join(clean_plain(t).text for t in tags)}]")
    return Material("\n".join(lines), body[:room])


def _advisory_urls(session: Session, cve_id: str) -> list[str]:
    stmt = (
        select(m.CveReference.url)
        .join(m.CveReferenceTag, m.CveReferenceTag.reference_id == m.CveReference.id)
        .where(m.CveReference.cve_id == cve_id, m.CveReferenceTag.tag == "Vendor Advisory")
        .order_by(m.CveReference.url)
    )
    return list(session.scalars(stmt))


def _violations(
    output: dict[str, Any], facts: CveFacts, quotable: str, schema: ToolSchema, exists: Callable[[str], bool]
) -> list[Violation]:
    found = validate_schema(output, schema)
    if found:
        return found
    found = check_cve_analysis(output, facts.cve_id, quotable, exists)
    vector = output["inferred_cvss_vector"]
    if vector and facts.cvss_score is not None:
        found.append(
            Violation("VAL-03.cvss_known", "inferred_cvss_vector", "The CVE already has a CVSS: leave it empty")
        )
    elif vector and base_score(vector) is None and not found:
        found.append(Violation("VAL-03.cvss_not_computable", "inferred_cvss_vector", "Use a CVSS:3.1 base vector"))
    return found


def _allowed(session: Session) -> bool:
    config = BudgetConfig(
        daily_usd=get_decimal(session, "daily_budget_usd"), critical_reserve=get_decimal(session, "critical_reserve")
    )
    return can_start(config, spent_on_day(session, datetime.now(UTC).date()), ESTIMATED_CALL_USD, critical=False)


def _lock(session: Session, cve_id: str) -> None:
    session.execute(select(func.pg_advisory_xact_lock(func.hashtextextended(f"cve-analyst:{cve_id}", 0))))


@dataclass(frozen=True)
class _Prepared:
    """What the call and the write need, read in the first transaction."""

    facts: CveFacts
    model: str


def analyze_cve(session: Session, client: ToolCaller, cve_id: str, options: CveOptions | None = None) -> CveResult:
    """Analyze one CVE. Commits twice: the read transaction before the advisory download and the model call (with
    anything the caller's session already held) and the write transaction after them. Idempotent: a CVE with an
    analysis is not analyzed again."""
    options = options or CveOptions()
    now = options.now or datetime.now(UTC)
    prepared = _prepare(session, cve_id, now)
    session.commit()  # no transaction stays open during the download or while the model answers
    if isinstance(prepared, CveResult):
        return prepared
    facts = prepared.facts
    advisory = options.advisory(list(facts.advisory_urls)) if options.advisory else None
    material = _material(facts, advisory)
    schema = ToolSchema.load(SCHEMA_FILE, SCHEMA_VERSION, default_schemas_dir())
    request = Request(
        model=prepared.model,
        tool=_tool(),
        system=prompts.CVE_SYSTEM,
        user=prompts.cve_user_message(cve_id, material.text),
        validate=lambda output: _violations(output, facts, material.quotable, schema, _exists_without_query),
    )
    result = run_analyst(client, request, options.seams or default_seams())
    versions = prompts.fingerprint(prompts.CVE_PROMPT_VERSION, prompts.CVE_SYSTEM, schema.version, schema.hash)
    outcome = _finish(session, facts, ReviewInfo(AGENT, request, versions, cve_id), result, now)
    session.commit()
    return outcome


def _exists_without_query(_cve_id: str) -> bool:
    """The validator's `exists` without a query while the model answers: the output must name the CVE being analyzed
    (VAL-03.cve_id), which exists; any other identifier is rejected by that rule, which is the one reported."""
    return True


def _prepare(session: Session, cve_id: str, now: datetime) -> _Prepared | CveResult:
    cve = session.get(m.Cve, cve_id)
    if cve is None:
        return CveResult(cve_id, "no_cve")
    if session.scalar(select(m.CveAnalysis.id).where(m.CveAnalysis.cve_id == cve_id)) is not None:
        return CveResult(cve_id, "exists")
    if not _allowed(session):
        _lock(session, cve_id)
        enqueue_failure(session, QueueRef(AGENT, cve_id=cve_id), "budget", now)
        return CveResult(cve_id, "budget", reason="budget")
    facts = _facts(session, cve)
    return _Prepared(facts, str(get_setting(session, "analyst_model")))


def _recheck(session: Session, facts: CveFacts) -> str | None:
    """Under the CVE's lock: None when the CVE is as it was read, else the status that applies now."""
    cve = session.get(m.Cve, facts.cve_id, populate_existing=True)
    if cve is None:
        return "no_cve"
    if session.scalar(select(m.CveAnalysis.id).where(m.CveAnalysis.cve_id == facts.cve_id)) is not None:
        return "exists"
    if (cve.cvss_score, cve.description) != (facts.cvss_score, facts.description):
        return STALE  # a refresh changed what the model read (and the cvss_known rule)
    return None


def _finish(session: Session, facts: CveFacts, info: ReviewInfo, result: RunResult, now: datetime) -> CveResult:
    """The write step: store the review (paid either way), then the analysis only if the CVE did not change."""
    cve_id = facts.cve_id
    _lock(session, cve_id)
    changed = _recheck(session, facts)
    if changed is not None:
        record_review(session, info, result if result.failure else replace(result, failure=STALE), now)
        log.info("cve analyst: %s changed while the model answered (%s); answer not applied", cve_id, changed)
        return CveResult(cve_id, changed, reason=STALE)
    review = record_review(session, info, result, now)
    if result.failure is not None or result.outcome is None or result.outcome.output is None:
        enqueue_failure(session, QueueRef(AGENT, cve_id=cve_id), result.failure or "failed", now)
        return CveResult(cve_id, "queued", reason=result.failure)
    for row in session.scalars(
        select(m.ErrorQueue).where(
            m.ErrorQueue.cve_id == cve_id, m.ErrorQueue.component == AGENT, m.ErrorQueue.status == "pending"
        )
    ):
        resolve(session, row)  # a retry that works closes its queue item in the same transaction
    output = result.outcome.output
    vector = output["inferred_cvss_vector"] or None
    analysis = m.CveAnalysis(
        id=new_id(),
        cve_id=cve_id,
        llm_review_id=review.id,
        inferred_cvss_vector=vector,
        output=output,
        created_at=now,
    )
    session.add(analysis)
    session.flush()
    return CveResult(cve_id, "analyzed", analysis.id, inferred_score=base_score(vector) if vector else None)


def pending_cves(session: Session, limit: int = 50) -> list[str]:
    """CVEs of active finding groups without an analysis, oldest group first (ANA-10)."""
    rows = session.execute(
        text(
            "SELECT g.cve_id FROM finding_group g JOIN finding_group_status s ON s.finding_group_id = g.id "
            "AND s.status = 'active' WHERE NOT EXISTS (SELECT 1 FROM cve_analysis a WHERE a.cve_id = g.cve_id) "
            "AND NOT EXISTS (SELECT 1 FROM error_queue q WHERE q.cve_id = g.cve_id AND q.component = 'cve_analyst' "
            "AND q.status = 'pending' AND q.next_attempt_at IS NULL) "
            "GROUP BY g.cve_id ORDER BY min(g.created_at), g.cve_id LIMIT :n"
        ),
        {"n": limit},
    )
    return [row[0] for row in rows]


def analyze_pending_cves(
    session: Session, client: ToolCaller, options: CveOptions | None = None, limit: int = 50
) -> list[CveResult]:
    """Analyze the pending CVEs one by one; a failing CVE never stops the next one. Commits per CVE (each CVE is a
    read transaction and a write transaction, with the download and the model call between them)."""
    options = options or CveOptions()
    shared = replace(options, seams=options.seams or default_seams())  # one circuit breaker for the whole batch
    results = []
    for cve_id in pending_cves(session, limit):
        results.append(analyze_cve(session, client, cve_id, shared))
    return results
