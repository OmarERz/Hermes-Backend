"""Mode 4 in supervised mode: the weekly proposals and the human decision on them (docs/07 §10, D-020).

The weekly job only writes `calibration_proposal` rows (status `proposed`) and never applies anything. A person
approves or rejects each one through the API: approving applies the change the same way a manual edit does (a new
formula version through the configuration service, or a source level change with its F2.3 rules) and audits it.
Guards: at most one weight at a time and +/- the weekly limit, the same parameter not twice inside the cooldown, a
reverted change blocked for the block weeks, and nothing of the blocked list (docs/13 §2) is ever a target: only
weights and source levels are proposed. The autonomous level (`mode4_autonomous`) is outside this scope: even with
it switched on, nothing is applied without approval.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any, Final

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from core.calibration.claims import resolve_claims
from core.calibration.reliability import TierSuggestion, source_scores, suggest_tiers
from core.calibration.settings import CalibrationSettings, load_settings
from core.calibration.weights import WINDOW_DAYS, Candidate, best_candidate, load_cases
from core.configuration import service
from core.configuration.errors import ConflictError, ForbiddenParameterError, NotFoundError, Problem
from core.db import models as m
from core.ingestion.sources import SourceRuleError, change_trust_tier
from core.scoring.engine import FACTORS
from core.scoring.formula_repo import load_active_formula

WEEK: Final = timedelta(days=7)
SOURCE_PREFIX: Final = "source:"
LOCK_KEY: Final = 7_001_020


@dataclass
class WeeklyResult:
    run_id: uuid.UUID | None
    created: list[uuid.UUID] = field(default_factory=list)
    resolved_confirmed: int = 0
    resolved_refuted: int = 0


def _blocked_keys(session: Session, now: datetime, settings: CalibrationSettings) -> frozenset[str]:
    """Targets that must not get a new proposal: open ones, changed inside the cooldown, or blocked after a revert."""
    cooldown_since = now - timedelta(weeks=settings.cooldown_weeks)
    rows = session.execute(
        text(
            "SELECT DISTINCT target_key FROM calibration_proposal WHERE status = 'proposed' "
            "OR (status IN ('approved', 'applied') AND decided_at >= :since) "
            "OR (blocked_until IS NOT NULL AND blocked_until >= :today)"
        ),
        {"since": cooldown_since, "today": now.date()},
    )
    keys = frozenset(row[0] for row in rows)
    # A weight change rescales every other weight, so the weights count as one parameter for cooldown and blocks.
    return keys | frozenset(f"weights.{f}" for f in FACTORS) if any(k.startswith("weights.") for k in keys) else keys


def _weight_proposal(
    run_id: uuid.UUID, candidate: Candidate, formula_weights: dict[str, Decimal], now: datetime
) -> m.CalibrationProposal:
    previous = {f"weights.{f}": str(formula_weights[f]) for f in sorted(formula_weights)}
    proposed = {f"weights.{f}": str(candidate.formula.weights[f]) for f in sorted(candidate.formula.weights)}
    evidence = (
        f"Con {candidate.cases} retroalimentaciones de «prioridad equivocada» de los últimos {WINDOW_DAYS} días, "
        f"el error medio frente a la puntuación que propusieron las personas baja de {candidate.mae_before:.2f} "
        f"a {candidate.mae_after:.2f} puntos."
    )
    return m.CalibrationProposal(
        run_id=run_id,
        target_kind="weight",
        target_key=f"weights.{candidate.factor}",
        previous_value=previous,
        proposed_value=proposed,
        evidence=evidence,
        backtest={
            "cases": candidate.cases,
            "window_days": WINDOW_DAYS,
            "mae_before": f"{candidate.mae_before:.4f}",
            "mae_after": f"{candidate.mae_after:.4f}",
        },
        status="proposed",
        created_at=now,
    )


def _source_proposal(
    run_id: uuid.UUID, item: TierSuggestion, settings: CalibrationSettings, now: datetime
) -> m.CalibrationProposal:
    source = item.source
    direction = "sube" if item.proposed_tier < source.tier else "baja"
    evidence = (
        f"{source.confirmed} afirmaciones confirmadas y {source.refuted} refutadas de {source.resolved} resueltas en "
        f"{settings.window_days} días: puntuación {source.score:.2f} "
        f"({'umbral de subida' if direction == 'sube' else 'umbral de bajada'} "
        f"{settings.raise_at if direction == 'sube' else settings.lower_at})."
    )
    return m.CalibrationProposal(
        run_id=run_id,
        target_kind="source_trust",
        target_key=f"{SOURCE_PREFIX}{source.code}",
        previous_value={"trust_tier": source.tier},
        proposed_value={"trust_tier": item.proposed_tier},
        evidence=evidence,
        status="proposed",
        created_at=now,
    )


def run_weekly(session: Session, now: datetime, *, force: bool = False) -> WeeklyResult:
    """Compute this week's proposals. Idempotent inside a week; the caller commits. Never applies a change."""
    session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": LOCK_KEY})
    if not force:
        recent = session.scalar(
            select(m.Run.id).where(m.Run.kind == "mode4", m.Run.status == "succeeded", m.Run.started_at >= now - WEEK)
        )
        if recent is not None:
            return WeeklyResult(None)
    run = m.Run(kind="mode4", status="running", progress=0, trigger_reason="schedule", started_at=now)
    session.add(run)
    session.flush()
    resolved = resolve_claims(session, now)
    result = WeeklyResult(run.id, resolved_confirmed=resolved.confirmed, resolved_refuted=resolved.refuted)
    settings = load_settings(session)
    skip = _blocked_keys(session, now, settings)
    for item in suggest_tiers(source_scores(session, now, settings.window_days), settings):
        if f"{SOURCE_PREFIX}{item.source.code}" in skip:
            continue
        proposal = _source_proposal(run.id, item, settings, now)
        session.add(proposal)
        session.flush()
        result.created.append(proposal.id)
    _, formula = load_active_formula(session)
    candidate = best_candidate(formula, load_cases(session, now), settings.weekly_limit, skip)
    if candidate is not None:
        proposal = _weight_proposal(run.id, candidate, dict(formula.weights), now)
        session.add(proposal)
        session.flush()
        result.created.append(proposal.id)
    run.status, run.progress, run.finished_at = "succeeded", 100, now
    session.flush()
    return result


# --- reading ---------------------------------------------------------------------------------------------------
def _previous(row: m.CalibrationProposal) -> dict[str, Any]:
    value: dict[str, Any] = row.previous_value or {}
    return value


def describe(row: m.CalibrationProposal) -> str:
    """The one-line summary shown in the list (Spanish)."""
    if row.target_kind == "source_trust":
        code = row.target_key.removeprefix(SOURCE_PREFIX)
        old, new = _previous(row).get("trust_tier"), row.proposed_value["trust_tier"]
        return f"Cambiar el nivel de la fuente {code} de {old} a {new}"
    changes = ", ".join(
        f"{key} {_previous(row).get(key, '?')} → {value}" for key, value in sorted(row.proposed_value.items())
    )
    return f"Cambiar los pesos: {changes}"


def list_proposals(session: Session) -> list[m.CalibrationProposal]:
    return list(
        session.scalars(
            select(m.CalibrationProposal).order_by(
                m.CalibrationProposal.created_at.desc(), m.CalibrationProposal.id.desc()
            )
        )
    )


def _get(session: Session, proposal_id: str) -> m.CalibrationProposal:
    try:
        row = session.get(m.CalibrationProposal, uuid.UUID(proposal_id), with_for_update=True)
    except ValueError:
        row = None
    if row is None:
        raise NotFoundError("La propuesta no existe.")
    if row.status != "proposed":
        raise ConflictError("La propuesta ya fue resuelta.", (Problem("path.id", "already_decided"),))
    return row


# --- the decision -------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Decider:
    user_id: uuid.UUID | None
    now: datetime


def _audit(session: Session, who: Decider, action: str, row: m.CalibrationProposal, after: dict[str, Any]) -> None:
    session.add(
        m.AuditLog(
            app_user_id=who.user_id,
            action=action,
            entity_type="calibration_proposal",
            entity_id=str(row.id),
            before={"status": "proposed", "target": row.target_key, "value": row.previous_value},
            after=after,
            created_at=who.now,
        )
    )


def _same(a: object, b: object) -> bool:
    try:
        return Decimal(str(a)) == Decimal(str(b))
    except InvalidOperation:
        return str(a) == str(b)


def _apply_weights(session: Session, row: m.CalibrationProposal, who: Decider) -> uuid.UUID:
    current = service.current_values(session)
    if any(not _same(current.get(key), value) for key, value in _previous(row).items()):
        raise ConflictError(
            "La fórmula cambió desde que se hizo la propuesta; ya no aplica.", (Problem("path.id", "stale_proposal"),)
        )
    user = session.get(m.AppUser, who.user_id) if who.user_id is not None else None
    if user is None or not user.active or user.role != "admin":  # the route checks it too; the core does not trust it
        raise ForbiddenParameterError("No tienes permiso para este cambio.", (Problem("path.id", "requires_admin"),))
    actor = service.Actor(who.user_id, user.role, who.now, origin="mode4")
    service.update(session, actor, service.current_version(session), {k: str(v) for k, v in row.proposed_value.items()})
    version_id = session.scalar(select(m.FormulaVersion.id).where(m.FormulaVersion.status == "active"))
    if version_id is None:
        raise ConflictError("No hay una versión de la fórmula activa.")
    return version_id


def _apply_source(session: Session, row: m.CalibrationProposal, who: Decider) -> None:
    code = row.target_key.removeprefix(SOURCE_PREFIX)
    source = session.scalar(select(m.Source).where(m.Source.code == code))
    if source is None:
        raise NotFoundError("La fuente de la propuesta ya no existe.")
    if source.trust_tier != _previous(row).get("trust_tier"):
        raise ConflictError(
            "El nivel de la fuente cambió desde que se hizo la propuesta; ya no aplica.",
            (Problem("path.id", "stale_proposal"),),
        )
    try:
        change_trust_tier(session, source.id, str(row.proposed_value["trust_tier"]), who.user_id, who.now)
    except SourceRuleError as error:
        raise ForbiddenParameterError(str(error), (Problem("path.id", "source_rule"),)) from None


def approve(session: Session, proposal_id: str, who: Decider) -> m.CalibrationProposal:
    """Apply the proposal as a person's decision. The caller commits afterwards."""
    row = _get(session, proposal_id)
    if row.target_kind == "weight":
        row.formula_version_id = _apply_weights(session, row, who)
    elif row.target_kind == "source_trust":
        _apply_source(session, row, who)
    else:
        raise ConflictError(
            "Este tipo de propuesta todavía no se puede aplicar desde aquí.", (Problem("path.id", "unsupported_kind"),)
        )
    row.status, row.decided_by, row.decided_at = "applied", who.user_id, who.now
    _audit(
        session,
        who,
        "calibration.approve",
        row,
        {"status": "applied", "formula_version_id": str(row.formula_version_id)},
    )
    session.flush()
    return row


def reject(session: Session, proposal_id: str, who: Decider) -> m.CalibrationProposal:
    row = _get(session, proposal_id)
    row.status, row.decided_by, row.decided_at = "rejected", who.user_id, who.now
    _audit(session, who, "calibration.reject", row, {"status": "rejected"})
    session.flush()
    return row
