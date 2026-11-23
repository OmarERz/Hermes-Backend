"""Persistence of judge reviews (L13): `llm_review`, `judge_reason`, `mitigation_draft_step` and `error_queue`.

Append-only (A-2): a review is assembled in memory and written once, complete, when it closes. A package whose
review fell back to the base (L11) gets one `error_queue` entry (PRE-01), retried in the next runs and given up
(shown as pending in the front) after `QUEUE_RETRIES`; a later successful review resolves it. A review skipped on
purpose (degradation ladder) is not queued. Package CIs are iTop CI IDs (`asset.itop_ci_id`); an asset UUID is
accepted too. A review is always stored, even when a CI it cites left the inventory while the model answered: its
tokens were paid and count for the daily budget (F6.1 #69).
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import or_, select, text
from sqlalchemy.orm import Session

from core.db.ids import new_id
from core.db.models import (
    Alert,
    AlertAsset,
    Asset,
    CompanyProfile,
    ErrorQueue,
    InstalledSoftware,
    JudgeReason,
    LlmReview,
    MitigationDraftStep,
    SoftwareProduct,
    VerifiedRelationship,
)
from core.judge.budget import FALLBACK_PRICE, TURN_ESTIMATE, LedgerDailyBudget, ModelPrice
from core.judge.catalog import MORE_CRITICAL_ASSET, JudgeSettings, SensitivityProfile, load_reason_catalog
from core.judge.mitigation import MitigationResult, MitigationStatus
from core.judge.mode2 import AlertDecision, relation_identity
from core.judge.session import Failure, JudgeEnvironment, ReviewOutcome, ReviewStatus
from core.validation.budget import BudgetConfig, spent_on

logger = logging.getLogger(__name__)

AGENT = "judge"
# LIMIT reaches the queue only from mode 2, where hitting the limits means no decision; a mode 1 review that hit
# them still answered (partial_review with its accepted reasons) and its callers pass no failure.
QUEUED_FAILURES = frozenset({Failure.TRANSPORT, Failure.REQUEST, Failure.FORMAT, Failure.BUDGET, Failure.LIMIT})
QUEUE_RETRIES = 2  # PRE-01: retried in the next 2 runs, then pending in the front
MODE2_MIN_CONFIDENCE = "mode2.min_confidence"
_SETTING_KEYS = (
    "judge_model",
    "judge.max_calls",
    "judge.max_rejections",
    "retries.format",
    "double_review_threshold",
    "double_review_max_diff",
    "sensitivity_profile",
)


MISSING_CI_RULE = "JUE-MIT-04"  # a mitigation step cites a CI that is not (any more) in the inventory


@dataclass(frozen=True)
class ReviewTarget:
    """Where a review belongs: its package row (None once retention deleted it), the input reference and time."""

    review_package_id: uuid.UUID | None
    input_ref: str
    now: datetime


def load_judge_settings(session: Session) -> tuple[JudgeSettings, SensitivityProfile]:
    """Current values of the judge parameters (view setting_current, docs/11 §2) and the output language."""
    rows = session.execute(
        text("SELECT setting_key, value, is_default FROM setting_current WHERE setting_key = ANY(:keys)"),
        {"keys": [*_SETTING_KEYS, MODE2_MIN_CONFIDENCE]},
    ).all()
    values: dict[str, Any] = {key: value for key, value, _default in rows}
    # mode2.min_confidence follows the profile unless an admin set it explicitly (docs/07 §12, docs/11)
    explicit_mode2 = next((value for key, value, default in rows if key == MODE2_MIN_CONFIDENCE and not default), None)
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
        mode2_min_confidence=Decimal(str(explicit_mode2)) if explicit_mode2 is not None else None,
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
    """Insert the review with its reasons and accepted mitigation; returns the `llm_review.id`.

    The cited CIs are resolved before anything is inserted (F6.1 #69), so a CI missing from the inventory never rolls
    the review back: an accepted `more_critical_asset` without its CI keeps no `judge_reason` row (it stays in
    `calls`), and a mitigation step that cites one discards the whole draft (JUE-MIT-05) with rule JUE-MIT-04."""
    cited = {r.ci_id for r in outcome.reasons if r.ci_id} | {s.ci_id for s in outcome.mitigation.steps if s.ci_id}
    assets = resolve_assets(session, (ci for ci in cited if ci is not None))
    if any(step.ci_id and step.ci_id not in assets for step in outcome.mitigation.steps):
        logger.warning("a mitigation step cites a CI that is not in the inventory: the draft is discarded")
        outcome = replace(outcome, mitigation=MitigationResult(MitigationStatus.DISCARDED, rule=MISSING_CI_RULE))
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
    # serialize concurrent reviews of the same package until commit, so only one entry is ever created
    session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": f"judge-queue:{review_package_id}"})
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
    elif entry.status == "pending" and now != entry.next_attempt_at:
        entry.attempts += 1  # one attempt per run: repeated failures of the same run (same `now`) count once
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
        "mode": outcome.mode,
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
                # judge_reason requires the asset for this reason: the call stays in llm_review.calls. An accepted
                # one only happens when the CI left the inventory while the model answered; it adjusts no score,
                # since asset scores exist only for inventory CIs.
                logger.log(
                    logging.WARNING if record.status == "accepted" else logging.INFO,
                    "%s more_critical_asset without an inventory CI kept only in calls",
                    record.status,
                )
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
    for step in outcome.mitigation.steps:  # save_review already discarded a draft that cites a missing CI
        asset_id = assets.get(step.ci_id) if step.ci_id else None
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


# --- mode 2 ----------------------------------------------------------------------------------------------------
class DbInventory:
    """The `Inventory` of mode 2 over the iTop cache: active assets and what they currently run."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def find_asset(self, ci_id: str) -> uuid.UUID | None:
        asset_id = resolve_assets(self._session, [ci_id]).get(ci_id)
        if asset_id is None:
            return None
        decommissioned = self._session.scalar(select(Asset.decommissioned_at).where(Asset.id == asset_id))
        return asset_id if decommissioned is None else None

    def products(self, asset_id: uuid.UUID) -> list[tuple[uuid.UUID, str]]:
        rows = self._session.execute(
            select(InstalledSoftware.id, SoftwareProduct.itop_name)
            .join(SoftwareProduct, SoftwareProduct.id == InstalledSoftware.software_product_id)
            .where(InstalledSoftware.asset_id == asset_id, InstalledSoftware.removed_at.is_(None))
            .order_by(SoftwareProduct.itop_name)
        ).all()
        return [(software_id, name) for software_id, name in rows]


def refuted_relationships(session: Session) -> Callable[[str, str, str], bool]:
    """Relationships a person refuted (verified_relationship): mode 2 never proposes them again (docs/07 §7). Each end
    is compared by identity (`relation_identity`), so 'Nginx Proxy Manager' is not 'Nginx'; the type is not: the same
    two ends refuted as `component` stay refuted as `supplier`, `chain` or a direct link (pending F6.4 #83)."""
    rows = session.execute(
        select(VerifiedRelationship.subject, VerifiedRelationship.object).where(
            VerifiedRelationship.status == "refuted"
        )
    ).all()
    refuted = {(relation_identity(str(sub)), relation_identity(str(obj))) for sub, obj in rows}
    return lambda _kind, subject, obj: (subject, obj) in refuted


def save_alert(session: Session, decision: AlertDecision, review_id: uuid.UUID, now: datetime) -> uuid.UUID:
    """One alert per story (L15 deduplication): any alert the story already has (from correlation or the judge) is
    reused."""
    story_id = uuid.UUID(decision.story_id)
    # serialize concurrent reviews of the same story until commit, so only one of them creates the alert
    session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": f"judge-alert:{story_id}"})
    existing = session.scalars(
        select(Alert.id).where(Alert.story_id == story_id).order_by(Alert.created_at).limit(1)
    ).one_or_none()
    if existing is not None:
        return existing
    alert = Alert(
        id=new_id(),
        story_id=story_id,
        relevance=decision.relevance,
        relationship_type=decision.relationship_type,
        relationship_detail=decision.relationship,
        verification_action=decision.verification_action,
        confidence=decision.confidence,
        llm_review_id=review_id,
        status="open",
        created_at=now,
    )
    session.add(alert)
    session.flush()
    if decision.asset_id is not None:
        session.add(
            AlertAsset(
                alert_id=alert.id,
                asset_id=decision.asset_id,
                installed_software_id=decision.installed_software_id,
                version_confirmed=False,  # an inferred relationship never confirms the version (E = 0.6)
            )
        )
        session.flush()
    return alert.id


# --- budget ----------------------------------------------------------------------------------------------------
_BUDGET_KEYS = ("daily_budget_usd", "critical_reserve")


def _settings(session: Session, keys: Iterable[str]) -> dict[str, Any]:
    rows = session.execute(
        text("SELECT setting_key, value FROM setting_current WHERE setting_key = ANY(:keys)"), {"keys": list(keys)}
    ).all()
    return {str(row[0]): row[1] for row in rows}


def load_model_price(session: Session, model: str) -> ModelPrice | None:
    """USD per million tokens of `model` from the `model_prices` parameter (docs/11, MET-17), or None when it is not
    configured. `model_prices` is not seeded yet: callers must treat None as an unknown cost."""
    return parse_model_price(_settings(session, ["model_prices"]).get("model_prices"), model)


def parse_model_price(prices: Any, model: str) -> ModelPrice | None:
    """`{"<model>": {"input": .., "cached_input": .., "output": ..}}` -> the model's price, or None if malformed."""
    entry = prices.get(model) if isinstance(prices, dict) else None
    if not isinstance(entry, dict):
        return None
    try:
        rates = [Decimal(str(entry[key])) for key in ("input", "cached_input", "output")]
    except (KeyError, ArithmeticError):
        return None
    if not all(rate.is_finite() and rate >= 0 for rate in rates):
        return None  # a negative or non-finite rate would make the budget lie
    return ModelPrice(input=rates[0], cached_input=rates[1], output=rates[2])


def load_daily_budget(session: Session, price: ModelPrice, today: date) -> LedgerDailyBudget:
    """The judge's daily budget from `daily_budget_usd` and `critical_reserve` (docs/11) over `llm_usage_daily`."""
    values = _settings(session, _BUDGET_KEYS)
    defaults = BudgetConfig()
    config = BudgetConfig(
        daily_usd=Decimal(str(values.get("daily_budget_usd", defaults.daily_usd))),
        critical_reserve=Decimal(str(values.get("critical_reserve", defaults.critical_reserve))),
    )
    return LedgerDailyBudget(lambda: spent_on(session, today), config, price.cost(TURN_ESTIMATE))


def judge_environment(session: Session, today: date, ladder_level: int = 0) -> JudgeEnvironment:
    """The production environment of the judge: active reasons, current parameters and profile, the model's price
    and the shared daily budget over `llm_usage_daily` (L12). Without a `model_prices` entry a conservative fallback
    price keeps the budget advancing (TODO(P-015): `model_prices` is not seeded)."""
    settings, profile = load_judge_settings(session)
    price = load_model_price(session, settings.model)
    if price is None:
        logger.warning("model_prices has no entry for %s: using the conservative fallback price", settings.model)
        price = FALLBACK_PRICE
    return JudgeEnvironment(
        catalog=load_reason_catalog(session),
        profile=profile,
        settings=settings,
        today=today,
        daily_budget=load_daily_budget(session, price, today),
        price=price,
        ladder_level=ladder_level,
    )
