"""Persistence of judge reviews (L13): `llm_review`, `judge_reason`, `mitigation_draft_step` and `error_queue`.

Append-only (A-2): a review is assembled in memory and written once, complete, when it closes. A package whose
review fell back to the base (L11) gets one `error_queue` entry (PRE-01), retried in the next runs and given up
(shown as pending in the front) after `QUEUE_RETRIES`; a later successful review resolves it. A review skipped on
purpose (degradation ladder) is not queued. Package CIs are iTop CI IDs (`asset.itop_ci_id`); an asset UUID is
accepted too.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import or_, select, text
from sqlalchemy.orm import Session

from core.db.ids import new_id
from core.db.models import Asset, CompanyProfile, ErrorQueue, JudgeReason, LlmReview, MitigationDraftStep
from core.judge.catalog import MORE_CRITICAL_ASSET, JudgeSettings, SensitivityProfile
from core.judge.session import Failure, ReviewOutcome, ReviewStatus

logger = logging.getLogger(__name__)

AGENT = "judge"
MODE_SCORING = "scoring"
QUEUED_FAILURES = frozenset({Failure.TRANSPORT, Failure.REQUEST, Failure.FORMAT, Failure.BUDGET})
QUEUE_RETRIES = 2  # PRE-01: retried in the next 2 runs, then pending in the front
_SETTING_KEYS = (
    "judge_model",
    "judge.max_calls",
    "judge.max_rejections",
    "retries.format",
    "double_review_threshold",
    "double_review_max_diff",
    "sensitivity_profile",
)


class JudgeStoreError(RuntimeError):
    """The review cannot be stored consistently (e.g. a cited CI is not in the inventory)."""


@dataclass(frozen=True)
class ReviewTarget:
    """Where a review belongs: its package row (None once retention deleted it), the input reference and time."""

    review_package_id: uuid.UUID | None
    input_ref: str
    now: datetime


def load_judge_settings(session: Session) -> tuple[JudgeSettings, SensitivityProfile]:
    """Current values of the judge parameters (view setting_current, docs/11 §2) and the output language."""
    rows = session.execute(
        text("SELECT setting_key, value FROM setting_current WHERE setting_key = ANY(:keys)"),
        {"keys": list(_SETTING_KEYS)},
    ).all()
    values: dict[str, Any] = dict(rows)
    language = session.scalar(select(CompanyProfile.output_language).limit(1)) or JudgeSettings.output_language
    defaults = JudgeSettings()
    settings = JudgeSettings(
        model=str(values.get("judge_model", defaults.model)),
        max_calls=int(values.get("judge.max_calls", defaults.max_calls)),
        max_rejections=int(values.get("judge.max_rejections", defaults.max_rejections)),
        format_retries=int(values.get("retries.format", defaults.format_retries)),
        double_review_threshold=int(values.get("double_review_threshold", defaults.double_review_threshold)),
        double_review_max_diff=int(values.get("double_review_max_diff", defaults.double_review_max_diff)),
        output_language=str(language),
    )
    return settings, SensitivityProfile.named(str(values.get("sensitivity_profile", "normal")))


def resolve_assets(session: Session, ci_ids: Iterable[str]) -> dict[str, uuid.UUID]:
    """Map package CI IDs to `asset.id`: by iTop CI ID, or directly when the package carries the asset UUID."""
    wanted = {ci for ci in ci_ids if ci}
    if not wanted:
        return {}
    as_uuid = {ci: _uuid(ci) for ci in wanted}
    uuids = [u for u in as_uuid.values() if u is not None]
    rows = session.execute(
        select(Asset.id, Asset.itop_ci_id).where(or_(Asset.itop_ci_id.in_(wanted), Asset.id.in_(uuids)))
    ).all()
    by_itop = {itop: asset_id for asset_id, itop in rows}
    by_id = {asset_id for asset_id, _ in rows}
    resolved: dict[str, uuid.UUID] = {}
    for ci in wanted:
        if ci in by_itop:
            resolved[ci] = by_itop[ci]
        elif (candidate := as_uuid[ci]) is not None and candidate in by_id:
            resolved[ci] = candidate
    return resolved


def save_review(
    session: Session,
    outcome: ReviewOutcome,
    target: ReviewTarget,
    *,
    status: ReviewStatus | None = None,
    second_review_of: uuid.UUID | None = None,
) -> uuid.UUID:
    """Insert the review with its reasons and accepted mitigation; returns the `llm_review.id`."""
    cited = {r.ci_id for r in outcome.reasons if r.ci_id} | {s.ci_id for s in outcome.mitigation.steps if s.ci_id}
    assets = resolve_assets(session, (ci for ci in cited if ci is not None))
    review = LlmReview(id=new_id(), **_review_columns(outcome, target, status))
    review.second_review_of_id = second_review_of
    session.add(review)
    session.flush()
    session.add_all(_reason_rows(review.id, outcome, assets))
    session.add_all(_mitigation_rows(review.id, outcome, assets))
    session.flush()
    return review.id


def sync_error_queue(
    session: Session, review_package_id: uuid.UUID | None, failure: Failure | None, now: datetime
) -> bool:
    """PRE-01 for one package: queue (or count a new attempt on) a failed review, resolve it after a good one.
    A given-up entry stays given up (pending in the front) until a later review succeeds. Returns True when the
    package is waiting for a retry."""
    if review_package_id is None:
        return False
    entry = session.scalars(
        select(ErrorQueue)
        .where(ErrorQueue.review_package_id == review_package_id, ErrorQueue.status.in_(("pending", "gave_up")))
        .order_by(ErrorQueue.created_at.desc())
        .limit(1)
        .with_for_update()
    ).one_or_none()
    if failure not in QUEUED_FAILURES:
        if entry is not None and failure is not Failure.LADDER:  # the judge answered (fully or partially)
            entry.status = "resolved"
        return False
    if entry is None:
        entry = ErrorQueue(
            id=new_id(),
            component=AGENT,
            review_package_id=review_package_id,
            attempts=0,
            status="pending",
            created_at=now,
        )
        session.add(entry)
    elif entry.status == "pending":
        entry.attempts += 1
    entry.reason = f"judge {failure}"
    entry.next_attempt_at = now
    if entry.attempts >= QUEUE_RETRIES:
        entry.status = "gave_up"
    session.flush()
    return entry.status == "pending"


def _review_columns(outcome: ReviewOutcome, target: ReviewTarget, status: ReviewStatus | None) -> Mapping[str, Any]:
    mitigation = outcome.mitigation
    return {
        "agent": AGENT,
        "mode": MODE_SCORING,
        "review_package_id": target.review_package_id,
        "model": outcome.model,
        "response_model": {"model": outcome.response_model},
        "prompt_version": outcome.versions.prompt_version,
        "prompt_hash": outcome.versions.prompt_hash,
        "schema_version": outcome.versions.schema_version,
        "schema_hash": outcome.versions.schema_hash,
        "parameters": dict(outcome.parameters) | {"failure": outcome.failure.value if outcome.failure else None},
        "input_ref": target.input_ref,
        "calls": [call.as_dict() for call in outcome.calls],
        "status": (status or outcome.status).value,
        "attempts": outcome.attempts,
        "summary": outcome.summary,
        "proposed_adjustment": outcome.adjustment,  # accepted group reasons, without more_critical_asset (A-8)
        "mitigation_status": mitigation.status.value,
        "mitigation_discard_rule": mitigation.rule,
        "tokens_input": outcome.usage.input,
        "tokens_cached": outcome.usage.cached_input,
        "tokens_output": outcome.usage.output,
        "tokens_reasoning": outcome.usage.reasoning,
        "cost_usd": outcome.cost_usd,
        "latency_ms": outcome.latency_ms,
        "ladder_level": outcome.ladder_level,
        "created_at": target.now,
    }


def _reason_rows(review_id: uuid.UUID, outcome: ReviewOutcome, assets: Mapping[str, uuid.UUID]) -> list[JudgeReason]:
    rows: list[JudgeReason] = []
    for record in outcome.reasons:
        asset_id: uuid.UUID | None = None
        if record.code == MORE_CRITICAL_ASSET:
            asset_id = assets.get(record.ci_id or "")
            if asset_id is None:
                if record.status == "accepted":
                    raise JudgeStoreError("an accepted more_critical_asset cites a CI that is not in the inventory")
                # judge_reason requires the asset for this reason: the rejected call stays in llm_review.calls
                logger.info("rejected more_critical_asset without an inventory CI kept only in calls")
                continue
        rows.append(
            JudgeReason(
                id=new_id(),
                llm_review_id=review_id,
                seq=record.seq,
                reason_code=record.code,
                points=record.points,
                element_id=record.evidence_id,
                quote=record.quote,
                asset_id=asset_id,
                status=record.status,
                rejection_rule=record.rule,
            )
        )
    return rows


def _mitigation_rows(
    review_id: uuid.UUID, outcome: ReviewOutcome, assets: Mapping[str, uuid.UUID]
) -> list[MitigationDraftStep]:
    rows: list[MitigationDraftStep] = []
    for step in outcome.mitigation.steps:
        asset_id = assets.get(step.ci_id) if step.ci_id else None
        if step.ci_id and asset_id is None:
            raise JudgeStoreError("a mitigation step cites a CI that is not in the inventory")
        rows.append(
            MitigationDraftStep(
                llm_review_id=review_id,
                step_order=step.order,
                asset_id=asset_id,
                action=step.action,
                element_id=step.element_id,
                quote=step.quote,
            )
        )
    return rows


def _uuid(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value)
    except ValueError:
        return None
