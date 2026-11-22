"""Builders of metric inputs: judge reviews, assessments, feedback, events, error queue items."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.seeds import seed_catalogs, seed_formula

DAY_START = datetime(2026, 11, 21, 0, 0, tzinfo=UTC)
NOON = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
NOW = datetime(2026, 11, 22, 3, 0, tzinfo=UTC)


def _tag() -> str:
    return uuid.uuid4().hex[:8]


def formula(session: Session) -> uuid.UUID:
    existing = session.scalar(select(m.FormulaVersion.id).where(m.FormulaVersion.version_no == 1))
    if existing is not None:
        return existing
    seed_catalogs(session)
    return seed_formula(session)


def run(session: Session) -> m.Run:
    row = m.Run(kind="nightly", status="succeeded", progress=100, trigger_reason="schedule")
    session.add(row)
    session.flush()
    return row


def review(
    session: Session,
    status: str = "applied",
    *,
    agent: str = "judge",
    attempts: int = 1,
    at: datetime = NOON,
    **kw: object,
) -> m.LlmReview:
    row = m.LlmReview(
        agent=agent,
        mode="scoring" if agent == "judge" else None,
        model="deepseek-v4-pro",
        response_model={},
        prompt_version="1",
        prompt_hash="h",
        schema_version="1",
        schema_hash="h",
        parameters={},
        input_ref="pkg",
        calls=[],
        status=status,
        attempts=attempts,
        tokens_input=100,
        tokens_cached=0,
        tokens_output=50,
        tokens_reasoning=0,
        cost_usd=Decimal("0.010000"),
        latency_ms=900,
        ladder_level=0,
        created_at=at,
        **kw,
    )
    session.add(row)
    session.flush()
    return row


def group(session: Session) -> m.FindingGroup:
    cve = f"CVE-2026-{uuid.uuid4().int % 90000 + 10000}"
    session.add(m.Cve(id=cve))
    product = m.SoftwareProduct(itop_name=f"p-{_tag()}", first_seen_at=NOON)
    session.add(product)
    session.flush()
    row = m.FindingGroup(cve_id=cve, software_product_id=product.id, created_at=NOON)
    session.add(row)
    session.flush()
    return row


def assessment(session: Session, adjustment: int = 0, *, cvss: str | None = None, at: datetime = NOON) -> m.Assessment:
    row = m.Assessment(
        finding_group_id=group(session).id,
        run_id=run(session).id,
        formula_version_id=formula(session),
        trigger="nightly",
        factor_s=Decimal("0.8"),
        factor_p=Decimal("0.5"),
        factor_t=Decimal("0.2"),
        judge_adjustment=adjustment,
        raw_cvss_score=Decimal(cvss) if cvss else None,
        assessed_at=at,
    )
    session.add(row)
    session.flush()
    return row


def asset(session: Session) -> m.Asset:
    row = m.Asset(
        itop_ci_id=f"CI-{_tag()}",
        itop_class="Server",
        name=f"srv-{_tag()}",
        criticality="high",
        confidentiality="public",
        synced_at=NOON,
    )
    session.add(row)
    session.flush()
    return row


def score(session: Session, assessment_row: m.Assessment, final: int) -> None:
    target = asset(session)
    session.add(
        m.AssetScore(
            assessment_id=assessment_row.id,
            asset_id=target.id,
            factor_a=Decimal("1"),
            factor_d=Decimal("0.5"),
            version_factor=Decimal("1.00"),
            base=final,
            ci_adjustment=0,
            final=final,
            snap_criticality="high",
            snap_confidentiality="public",
        )
    )
    session.flush()


def user(session: Session) -> m.AppUser:
    tag = _tag()
    row = m.AppUser(firebase_uid=f"u-{tag}", email=f"{tag}@example.test", role="analyst", active=True, created_at=NOON)
    session.add(row)
    session.flush()
    return row


def feedback(
    session: Session, assessment_row: m.Assessment, verdict: str, *, superseded: bool = False, at: datetime = NOON
) -> None:
    session.add(
        m.Feedback(
            assessment_id=assessment_row.id,
            app_user_id=user(session).id,
            channel="slack",
            verdict=verdict,
            proposed_level="low" if verdict == "wrong_priority" else None,
            created_at=at,
            superseded_at=at if superseded else None,
        )
    )
    session.flush()


def event(session: Session, assessment_row: m.Assessment | None = None, **options: object) -> None:
    """A notification event; options: status, priority, level, created, latency_s."""
    status = str(options.get("status", "delivered"))
    created = options.get("created", NOON)
    assert isinstance(created, datetime)
    latency = int(str(options.get("latency_s", 60)))
    session.add(
        m.NotificationEvent(
            contract_version="1.0",
            event_type="new_ticket",
            priority=str(options.get("priority", "normal")),
            assessment_id=assessment_row.id if assessment_row else None,
            payload={"score": {"level": str(options.get("level", "high"))}},
            status=status,
            attempts=0,
            delivered_at=created + timedelta(seconds=latency) if status == "delivered" else None,
            created_at=created,
        )
    )
    session.flush()
