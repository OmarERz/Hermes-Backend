"""Configuration read and write: catalog, current values, optimistic versions, history and restore (API-03, API-05).

One configuration version covers the formula and every editable parameter. History is append-only
(`setting_value` rows and `formula_version` rows), so the number is derived: version 1 is the factory state and
every distinct change moment after it adds one. A change writes all its rows with the same timestamp, which is what
makes it one version. Every write is audited (`audit_log`, entity `config`) in the same transaction.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Final

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from core.configuration import formula_store as fs
from core.configuration.errors import (
    ForbiddenParameterError,
    NotFoundError,
    Problem,
    ValidationFailedError,
    VersionConflictError,
    check_text,
)
from core.db import models as m
from core.scoring.engine import Formula
from core.scoring.formula_repo import load_active_formula, load_formula

LOCK_KEY: Final = 7_001_010
SUMMARY_KEYS: Final = 5
ROLE_RANK: Final = {"reader": 0, "analyst": 1, "admin": 2}
API_TYPES: Final = {
    "int": "integer",
    "decimal": "decimal",
    "bool": "boolean",
    "text": "string",
    "enum": "enum",
    "json": "string",
}
GENERIC: Final = "Los datos enviados no son válidos."
STALE: Final = "La configuración cambió desde que la leíste; vuelve a cargarla."


@dataclass(frozen=True)
class Parameter:
    key: str
    group: str
    type: str
    default: str
    level: str  # free | validated
    min_role: str
    description: str
    min: str | None = None
    max: str | None = None
    validations: tuple[str, ...] = ()


@dataclass(frozen=True)
class VersionEntry:
    version: int
    created_at: datetime
    author: str
    summary: str


@dataclass(frozen=True)
class Actor:
    """Who writes, with which role, and the one timestamp shared by every row of the change."""

    user_id: uuid.UUID | None
    role: str
    now: datetime


@dataclass
class _Context:
    session: Session
    now: datetime
    user_id: uuid.UUID | None


# --- catalog and values ----------------------------------------------------------------------------------
def _text(value: Any, value_type: str) -> str:
    if value_type == "bool":
        return "true" if value else "false"
    if value_type == "json":
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    if value_type == "decimal":
        return str(Decimal(str(value)))
    return str(value)


def _bound(value: Decimal | None) -> str | None:
    return None if value is None else format(value.normalize(), "f")


FORMULA_DESCRIPTIONS: Final = {
    "weights": "Peso del factor {name} en la puntuación base",
    "levels": "Valor del nivel {name} (de 0 a 1, de más fuerte a más débil)",
    "bands": "Puntuación mínima de la urgencia {name} (1 crítica, 4 baja)",
    "decay": "Paso {name} del decaimiento de la amenaza por antigüedad",
    "formula": "Parámetro de la fórmula: {name}",
}


def _formula_parameter(key: str, formula: Formula) -> Parameter:
    family, _, name = key.partition(".")
    bounds: tuple[str | None, str | None] = {"weights": ("0", "1"), "levels": ("0", "1"), "bands": ("0", "100")}.get(
        family, (None, None)
    )
    if key == "formula.s_without_cvss":
        bounds = ("0.5", "1")
    elif key == "formula.kev_exposed_floor":
        bounds = ("80", "100")
    elif key.endswith(".multiplier"):
        bounds = ("0", "1")
    elif key.endswith(".max_age_days"):
        bounds = ("0", None)
    integer = family == "bands" or key in {"formula.kev_exposed_floor"} or key.endswith(".max_age_days")
    default = fs.formula_values(formula)[key]
    return Parameter(
        key=key,
        group="formula",
        type="integer" if integer else "decimal",
        default=default,
        level="validated",
        min_role="admin",
        description=FORMULA_DESCRIPTIONS[family].format(name=name),
        min=bounds[0],
        max=bounds[1],
        validations=("weights_sum_to_one",) if family == "weights" else ("formula_rules",),
    )


def catalog(session: Session) -> list[Parameter]:
    """Every editable parameter: the formula (defaults are the active version's) and the settings catalog."""
    _, formula = load_active_formula(session)
    parameters = [_formula_parameter(key, formula) for key in fs.formula_values(formula)]
    for definition in session.scalars(select(m.SettingDefinition).order_by(m.SettingDefinition.key)):
        parameters.append(
            Parameter(
                key=definition.key,
                group=definition.group_code,
                type=API_TYPES[definition.value_type],
                default=_text(definition.default_value, definition.value_type),
                level=definition.edit_level,
                min_role=definition.min_role,
                description=definition.description,
                min=_bound(definition.min_value),
                max=_bound(definition.max_value),
            )
        )
    return sorted(parameters, key=lambda p: (p.group != "formula", p.group, p.key))


def _setting_values(session: Session) -> dict[str, str]:
    rows = session.execute(
        text(
            "SELECT c.setting_key, c.value, d.value_type FROM setting_current c "
            "JOIN setting_definition d ON d.key = c.setting_key ORDER BY c.setting_key"
        )
    )
    return {key: _text(value, value_type) for key, value, value_type in rows}


# --- versions ----------------------------------------------------------------------------------------------
def _events(session: Session) -> list[tuple[datetime, uuid.UUID | None]]:
    rows = session.execute(
        text(
            "SELECT at, who FROM (SELECT changed_at AS at, changed_by AS who FROM setting_value "
            "UNION ALL SELECT created_at, created_by FROM formula_version WHERE origin <> 'seed') e "
            "ORDER BY at, who NULLS LAST"
        )
    )
    seen: dict[datetime, uuid.UUID | None] = {}
    for at, who in rows:
        seen.setdefault(at, who)
    return list(seen.items())


def current_version(session: Session) -> int:
    return 1 + len(_events(session))


def current_values(session: Session) -> dict[str, str]:
    _, formula = load_active_formula(session)
    return {**fs.formula_values(formula), **_setting_values(session)}


def _user_label(session: Session, user_id: uuid.UUID | None) -> str:
    user = session.get(m.AppUser, user_id) if user_id else None
    return (user.display_name or user.email) if user else "sistema"


def versions(session: Session) -> list[VersionEntry]:
    """Newest first. A version's summary is the one written to the audit trail when it was made."""
    events = _events(session)
    audit = {
        row.created_at: (row.after or {}).get("summary")
        for row in session.scalars(select(m.AuditLog).where(m.AuditLog.entity_type == "config"))
    }
    first = session.scalar(select(m.FormulaVersion.created_at).order_by(m.FormulaVersion.version_no).limit(1))
    entries = [VersionEntry(1, first or datetime.fromtimestamp(0, UTC), "sistema", "Valores de fábrica")]
    for number, (at, who) in enumerate(events, start=2):
        entries.append(VersionEntry(number, at, _user_label(session, who), audit.get(at) or "Cambio de configuración"))
    return entries[::-1]


def _state_at(session: Session, version: int) -> tuple[dict[str, Any], uuid.UUID]:
    """Setting values (raw jsonb) and formula version id as they were in `version`."""
    events = _events(session)
    if not 1 <= version <= len(events) + 1:
        raise NotFoundError("La versión solicitada no existe.")
    moment = events[version - 2][0] if version > 1 else None
    values: dict[str, Any] = {d.key: d.default_value for d in session.scalars(select(m.SettingDefinition))}
    if moment is not None:
        rows = session.execute(
            text(
                "SELECT DISTINCT ON (setting_key) setting_key, value FROM setting_value "
                "WHERE changed_at <= :t ORDER BY setting_key, version DESC"
            ),
            {"t": moment},
        )
        values.update(dict(rows.all()))
        formula_id = session.scalar(
            select(m.FormulaVersion.id)
            .where(m.FormulaVersion.created_at <= moment, m.FormulaVersion.status != "draft")
            .order_by(m.FormulaVersion.version_no.desc())
            .limit(1)
        )
    else:
        formula_id = session.scalar(select(m.FormulaVersion.id).order_by(m.FormulaVersion.version_no).limit(1))
    if formula_id is None:
        raise NotFoundError("La versión solicitada no existe.")
    return values, formula_id


# --- parsing and validating setting values --------------------------------------------------------------
def _invalid(key: str, issue: str, message: str = GENERIC) -> ValidationFailedError:
    return ValidationFailedError(message, (Problem(f"body.changes.{key}", issue),))


def parse_setting(session: Session, definition: m.SettingDefinition, raw: str) -> Any:
    """The JSON value to store for `raw`, validated against the catalog (X-5)."""
    key, kind = definition.key, definition.value_type
    if kind in {"int", "decimal"}:
        try:
            number = Decimal(raw.strip())
        except InvalidOperation:
            raise _invalid(key, "invalid_number") from None
        if not number.is_finite() or (kind == "int" and number != number.to_integral_value()):
            raise _invalid(key, "invalid_number")
        if (definition.min_value is not None and number < definition.min_value) or (
            definition.max_value is not None and number > definition.max_value
        ):
            raise _invalid(key, "out_of_range", "El valor está fuera del rango permitido.")
        return int(number) if kind == "int" else float(number)
    if kind == "bool":
        if raw not in {"true", "false"}:
            raise _invalid(key, "invalid_boolean")
        return raw == "true"
    if kind == "enum":
        options = set(session.scalars(select(m.SettingOption.option_value).where(m.SettingOption.setting_key == key)))
        if raw not in options:
            raise _invalid(key, "not_an_option")
        return raw
    if kind == "json":
        try:
            return json.loads(raw)
        except ValueError:
            raise _invalid(key, "invalid_json") from None
    if not raw.strip():
        raise _invalid(key, "empty")
    return raw.strip()


# --- writing ---------------------------------------------------------------------------------------------------
def _lock_and_check(session: Session, expected: int) -> int:
    session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": LOCK_KEY})
    current = current_version(session)
    if expected != current:
        raise VersionConflictError(STALE)
    return current


def _definitions(session: Session) -> dict[str, m.SettingDefinition]:
    return {d.key: d for d in session.scalars(select(m.SettingDefinition))}


def _check_roles(keys: list[str], role: str, definitions: dict[str, m.SettingDefinition]) -> None:
    for key in keys:
        needed = definitions[key].min_role if key in definitions else "admin"
        if ROLE_RANK[role] < ROLE_RANK[needed]:
            raise ForbiddenParameterError(
                "No tienes permisos para cambiar este parámetro.",
                (Problem(f"body.changes.{key}", f"requires_{needed}"),),
            )


def _summary(prefix: str, keys: list[str]) -> str:
    shown = ", ".join(sorted(keys)[:SUMMARY_KEYS]) + (" y otros" if len(keys) > SUMMARY_KEYS else "")
    return f"{prefix}: {shown}"


@dataclass(frozen=True)
class _Change:
    before: dict[str, str]
    after: dict[str, str]
    summary: str


def _change(before: dict[str, str], after: dict[str, str], summary: str) -> _Change:
    changed = [k for k in after if after[k] != before.get(k)]
    return _Change({k: before.get(k, "") for k in changed}, {k: after[k] for k in changed}, summary)


def _audit(ctx: _Context, action: str, version: int, change: _Change) -> None:
    ctx.session.add(
        m.AuditLog(
            app_user_id=ctx.user_id,
            action=action,
            entity_type="config",
            entity_id=str(version),
            before=change.before,
            after={"values": change.after, "summary": change.summary},
            created_at=ctx.now,
        )
    )


def update(
    session: Session, actor: Actor, expected_version: int, changes: dict[str, str]
) -> tuple[int, dict[str, str]]:
    """Apply `changes` as one new configuration version (no-op when nothing differs). Returns (version, values)."""
    for key, raw in changes.items():
        check_text(f"body.changes.{key[:60]}", key, raw)
    current = _lock_and_check(session, expected_version)
    definitions = _definitions(session)
    formula_changes = {k: v for k, v in changes.items() if fs.is_formula_key(k)}
    unknown = [k for k in changes if k not in definitions and k not in formula_changes]
    if unknown:
        raise ValidationFailedError(GENERIC, tuple(Problem(f"body.changes.{k}", "unknown_parameter") for k in unknown))
    _check_roles(list(changes), actor.role, definitions)
    before = current_values(session)
    ctx = _Context(session, actor.now, actor.user_id)
    stored: dict[str, Any] = {}
    for key, raw in changes.items():
        if key in definitions and key not in formula_changes:
            parsed = parse_setting(session, definitions[key], raw)
            if _text(parsed, definitions[key].value_type) != before[key]:
                stored[key] = parsed
    new_formula = None
    if formula_changes:
        formula_id, formula = load_active_formula(session)
        candidate = fs.apply_changes(formula, formula_changes)
        if candidate != formula:
            new_formula = (formula_id, candidate)
    if not stored and new_formula is None:
        return current, before
    _write(ctx, stored, new_formula, "frontend")
    after = current_values(session)
    changed = [k for k in after if after[k] != before.get(k)]
    summary = _summary("Cambió", changed)
    _audit(ctx, "config.update", current + 1, _change(before, after, summary))
    return current + 1, after


def _write(ctx: _Context, stored: dict[str, Any], new_formula: tuple[uuid.UUID, Formula] | None, origin: str) -> None:
    session = ctx.session
    for key, value in stored.items():
        version = (
            session.scalar(
                select(m.SettingValue.version)
                .where(m.SettingValue.setting_key == key)
                .order_by(m.SettingValue.version.desc())
                .limit(1)
            )
            or 0
        ) + 1
        session.add(
            m.SettingValue(
                setting_key=key, version=version, value=value, origin=origin, changed_by=ctx.user_id, changed_at=ctx.now
            )
        )
    if new_formula is not None:
        source_id, formula = new_formula
        fs.save_new_version(
            session, source_id, formula, fs.NewVersion(ctx.user_id, ctx.now, "Cambio desde la configuración")
        )
    session.flush()


def restore(session: Session, actor: Actor, version: int, expected_version: int) -> tuple[int, dict[str, str]]:
    """Make the state of `version` the current one, as a new version (FRO-08). The judge is not called."""
    current = _lock_and_check(session, expected_version)
    target_values, target_formula_id = _state_at(session, version)
    definitions = _definitions(session)
    before = current_values(session)
    differing = [k for k, v in target_values.items() if _text(v, definitions[k].value_type) != before[k]]
    _check_roles(differing, actor.role, definitions)
    ctx = _Context(session, actor.now, actor.user_id)
    stored = {
        key: value for key, value in target_values.items() if _text(value, definitions[key].value_type) != before[key]
    }
    _, active = load_active_formula(session)
    target = load_formula(session, target_formula_id)
    new_formula = (target_formula_id, target) if target != active else None
    if not stored and new_formula is None:
        return current, before
    if new_formula is not None and ROLE_RANK[actor.role] < ROLE_RANK["admin"]:
        raise ForbiddenParameterError(
            "No tienes permisos para cambiar la fórmula.", (Problem("body", "requires_admin"),)
        )
    _write(ctx, stored, new_formula, "frontend")
    after = current_values(session)
    _audit(ctx, "config.restore", current + 1, _change(before, after, f"Restauró la versión {version}"))
    return current + 1, after
