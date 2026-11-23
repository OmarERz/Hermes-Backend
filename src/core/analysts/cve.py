"""CVE analyst (docs/05 §3, ANA-10 to ANA-15): conditions, components and, only when no CVSS exists, an inferred vector.

One run per CVE, stored once. The material is the CVE description, its CWE, its references and, when the code could
download it from an allowed domain (D-014), the vendor advisory text. The model never gives a score: the vector is
validated for CVSS 3.1 syntax and the **code** computes the score (`core.scoring.cvss`); the scoring engine marks
that S as estimated (ANA-14). The analyst does not write mitigations (D-017).
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

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from core.analysts import prompt as prompts
from core.analysts.runner import Request, ReviewInfo, Seams, default_seams, record_review, run_analyst
from core.db import models as m
from core.db.ids import new_id
from core.ingestion.article import extract_article
from core.ingestion.cleaning import clean_html, clean_plain
from core.ingestion.fetcher import ARTICLE_CONTENT_TYPES, Fetcher, FetchError
from core.ingestion.settings import get_decimal, get_setting
from core.llm.client import LlmClient
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
# D-014 level 2: advisory pages are downloaded only from domains on an allowlist. It comes from the environment
# variable ADVISORY_DOMAINS (comma-separated host names); empty or unset means no advisory text is fetched and the
# analyst works from the CVE record alone (safe by default).
ADVISORY_DOMAINS_ENV = "ADVISORY_DOMAINS"


def advisory_domains() -> tuple[str, ...]:
    raw = os.environ.get(ADVISORY_DOMAINS_ENV, "")
    return tuple(sorted({d.strip().lower().lstrip(".") for d in raw.split(",") if d.strip()}))


class AdvisoryProvider(Protocol):
    def __call__(self, urls: list[str]) -> str | None: ...


def web_advisory_provider(fetcher: Fetcher, allowed: tuple[str, ...] | None = None) -> AdvisoryProvider:
    """Download the first `Vendor Advisory` page whose host is an allowed domain (or a subdomain of one)."""

    domains = advisory_domains() if allowed is None else allowed

    def provide(urls: list[str]) -> str | None:
        for url in urls:
            host = (urlsplit(url).hostname or "").lower()
            if not any(host == d or host.endswith("." + d) for d in domains):
                continue
            try:
                page = fetcher.get(url, ARTICLE_CONTENT_TYPES)
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
    status: str  # analyzed | exists | no_cve | budget | queued
    analysis_id: object | None = None
    reason: str | None = None
    inferred_score: Decimal | None = None


def _tool() -> ToolDefinition:
    return load_tools()[TOOL_NAME]


@dataclass(frozen=True)
class Material:
    """What the model receives, and the part of it a quote may come from (description and advisory, as sent)."""

    text: str
    quotable: str


def _material(session: Session, cve: m.Cve, advisory: str | None) -> Material:
    """External text is cleaned first (SEG-01). Order: header, description, advisory, then references, so that the
    cut at the context limit falls on the references and never on text a quote may cite."""
    cwes = sorted(session.scalars(select(m.CveCwe.cwe_id).where(m.CveCwe.cve_id == cve.id)))
    header = "\n".join(
        [
            f"CVE: {cve.id}",
            f"CVSS: {cve.cvss_score if cve.cvss_score is not None else 'ninguno'}",
            f"CWE: {', '.join(clean_plain(c).text for c in cwes) if cwes else 'ninguno'}",
        ]
    )
    description = clean_html(cve.description or "").text
    body = description
    if advisory:
        body += "\nAviso del fabricante:\n" + clean_html(advisory).text
    room = max(0, prompts.MAX_ARTICLE_CHARS - len(header) - 1)
    lines = [header, body[:room]]
    references = session.scalars(select(m.CveReference).where(m.CveReference.cve_id == cve.id).limit(MAX_REFERENCES))
    for ref in references:
        tags = sorted(session.scalars(select(m.CveReferenceTag.tag).where(m.CveReferenceTag.reference_id == ref.id)))
        lines.append(f"Referencia: {clean_plain(ref.url).text} [{', '.join(clean_plain(t).text for t in tags)}]")
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
    output: dict[str, Any], cve: m.Cve, quotable: str, schema: ToolSchema, exists: Callable[[str], bool]
) -> list[Violation]:
    found = validate_schema(output, schema)
    if found:
        return found
    found = check_cve_analysis(output, cve.id, quotable, exists)
    vector = output["inferred_cvss_vector"]
    if vector and cve.cvss_score is not None:
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


def analyze_cve(session: Session, client: LlmClient, cve_id: str, options: CveOptions | None = None) -> CveResult:
    """Analyze one CVE. Flushes (the caller commits). Idempotent: a CVE with an analysis is not analyzed again."""
    options = options or CveOptions()
    now = options.now or datetime.now(UTC)
    cve = session.get(m.Cve, cve_id)
    if cve is None:
        return CveResult(cve_id, "no_cve")
    if session.scalar(select(m.CveAnalysis.id).where(m.CveAnalysis.cve_id == cve_id)) is not None:
        return CveResult(cve_id, "exists")
    ref = QueueRef(AGENT, cve_id=cve_id)
    if not _allowed(session):
        enqueue_failure(session, ref, "budget", now)
        return CveResult(cve_id, "budget", reason="budget")
    advisory = options.advisory(_advisory_urls(session, cve_id)) if options.advisory else None
    material = _material(session, cve, advisory)
    schema = ToolSchema.load(SCHEMA_FILE, SCHEMA_VERSION, default_schemas_dir())
    request = Request(
        model=str(get_setting(session, "analyst_model")),
        tool=_tool(),
        system=prompts.CVE_SYSTEM,
        user=prompts.cve_user_message(cve_id, material.text),
        validate=lambda output: _violations(
            output, cve, material.quotable, schema, lambda c: session.get(m.Cve, c) is not None
        ),
    )
    result = run_analyst(client, request, options.seams or default_seams())
    versions = prompts.fingerprint(prompts.CVE_PROMPT_VERSION, prompts.CVE_SYSTEM, schema.version, schema.hash)
    review = record_review(session, ReviewInfo(AGENT, request, versions, cve_id), result, now)
    if result.failure is not None or result.outcome is None or result.outcome.output is None:
        enqueue_failure(session, ref, result.failure or "failed", now)
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
    session: Session, client: LlmClient, options: CveOptions | None = None, limit: int = 50
) -> list[CveResult]:
    """Analyze the pending CVEs one by one; a failing CVE never stops the next one. Commits per CVE."""
    options = options or CveOptions()
    shared = replace(options, seams=options.seams or default_seams())  # one circuit breaker for the whole batch
    results = []
    for cve_id in pending_cves(session, limit):
        results.append(analyze_cve(session, client, cve_id, shared))
        session.commit()
    return results
