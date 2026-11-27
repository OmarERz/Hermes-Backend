"""The formula as flat editable parameters, and saving an edit as a new formula version (FRO-05, API-05).

Keys: `weights.<factor>`, `levels.<factor>.<code>`, `formula.s_without_cvss`, `formula.kev_exposed_floor`,
`bands.<urgency>` (minimum score) and `decay.<step>.multiplier` / `decay.<step>.max_age_days` (the open last
step has no day limit). `core.scoring.engine.validate_formula` is the single source of the structural rules.
An edit never changes a version in place: it creates a new active one and supersedes the old.

The judge reasons are switched on and off per formula version too (`formula_reason_range.enabled`, FRO-03), as
`reasons.<code>.enabled`; they are not part of the engine's `Formula` (only the judge reads them).
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.configuration.errors import Problem, ValidationFailedError
from core.db import models as m
from core.scoring.engine import Formula, FormulaError
from core.textnum import ascii_int

STORED_DECIMALS: Final = 4  # formula values are stored as numeric(5,4)
BONUS: Final = "personal_data_bonus"
LEVEL_PARTS: Final = 2  # factor and level code after the `levels.` prefix
DECAY_PARTS: Final = 2  # step number and field after the `decay.` prefix
FORMULA_PREFIXES: Final = ("weights.", "levels.", "formula.", "bands.", "decay.")
REASON_PREFIX: Final = "reasons."
REASON_SUFFIX: Final = ".enabled"
MESSAGE: Final = "La fórmula no es válida."


def is_formula_key(key: str) -> bool:
    return key.startswith(FORMULA_PREFIXES)


def is_reason_key(key: str) -> bool:
    return key.startswith(REASON_PREFIX)


def reason_key(code: str) -> str:
    return f"{REASON_PREFIX}{code}{REASON_SUFFIX}"


def reason_flags(session: Session, formula_version_id: uuid.UUID) -> dict[str, bool]:
    """Whether each judge reason is enabled in a formula version, by reason code."""
    rows = session.execute(
        select(m.FormulaReasonRange.reason_code, m.FormulaReasonRange.enabled).where(
            m.FormulaReasonRange.formula_version_id == formula_version_id
        )
    )
    return {code: bool(enabled) for code, enabled in rows}


def reason_values(flags: Mapping[str, bool]) -> dict[str, str]:
    return {reason_key(code): "true" if enabled else "false" for code, enabled in sorted(flags.items())}


def apply_reason_changes(flags: Mapping[str, bool], changes: Mapping[str, str]) -> dict[str, bool]:
    """`flags` with the `reasons.<code>.enabled` changes applied; an unknown reason or a value other than `true` or
    `false` raises `ValidationFailedError`."""
    result = dict(flags)
    for key, raw in changes.items():
        code = key.removeprefix(REASON_PREFIX).removesuffix(REASON_SUFFIX)
        if not key.endswith(REASON_SUFFIX) or code not in result:
            raise _bad(key, "unknown_parameter")
        if raw not in {"true", "false"}:
            raise _bad(key, "invalid_boolean")
        result[code] = raw == "true"
    return result


def formula_values(formula: Formula) -> dict[str, str]:
    values: dict[str, str] = {f"weights.{f}": str(w) for f, w in sorted(formula.weights.items())}
    for factor, codes in formula.levels.items():
        for code, value in codes.items():
            values[f"levels.{factor}.{code}"] = str(value)
    values[f"levels.D.{BONUS}"] = str(formula.personal_data_bonus)
    values["formula.s_without_cvss"] = str(formula.s_without_cvss)
    values["formula.kev_exposed_floor"] = str(formula.kev_exposed_floor)
    for urgency, minimum in sorted(formula.urgency_bands.items()):
        values[f"bands.{urgency}"] = str(minimum)
    for number, (limit, multiplier) in enumerate(formula.decay, start=1):
        values[f"decay.{number}.multiplier"] = str(multiplier)
        if limit is not None:
            values[f"decay.{number}.max_age_days"] = str(limit)
    return values


def _bad(key: str, issue: str) -> ValidationFailedError:
    return ValidationFailedError(MESSAGE, (Problem(f"body.changes.{key}", issue),))


def _number(key: str, raw: str) -> Decimal:
    try:
        value = Decimal(raw.strip())
    except InvalidOperation:
        raise _bad(key, "invalid_decimal") from None
    if not value.is_finite():
        raise _bad(key, "invalid_decimal")
    exponent = value.as_tuple().exponent
    if isinstance(exponent, int) and exponent < -STORED_DECIMALS:  # numeric(5,4): more places would be rounded away
        raise _bad(key, "too_many_decimals")
    return value


def _integer(key: str, raw: str) -> int:
    value = _number(key, raw)
    if value != value.to_integral_value():
        raise _bad(key, "invalid_integer")
    return int(value)


class _Draft:
    """The formula being edited: each handler checks one family of keys and raises on a key it does not know."""

    def __init__(self, formula: Formula) -> None:
        self.formula = formula
        self.weights = dict(formula.weights)
        self.levels = {factor: dict(codes) for factor, codes in formula.levels.items()}
        self.bands = dict(formula.urgency_bands)
        self.limits: list[int | None] = [limit for limit, _ in formula.decay]
        self.multipliers: list[Decimal] = [multiplier for _, multiplier in formula.decay]
        self.bonus = formula.personal_data_bonus
        self.s_without = formula.s_without_cvss
        self.floor = formula.kev_exposed_floor

    def set(self, key: str, raw: str) -> None:
        parts = key.split(".")
        family = parts[0]
        handler = {
            "weights": self._weight,
            "levels": self._level,
            "formula": self._scalar,
            "bands": self._band,
            "decay": self._decay,
        }.get(family)
        if handler is None:
            raise _bad(key, "unknown_parameter")
        handler(key, parts[1:], raw)

    def _weight(self, key: str, rest: list[str], raw: str) -> None:
        if len(rest) != 1 or rest[0] not in self.weights:
            raise _bad(key, "unknown_parameter")
        self.weights[rest[0]] = _number(key, raw)

    def _level(self, key: str, rest: list[str], raw: str) -> None:
        if len(rest) != LEVEL_PARTS:
            raise _bad(key, "unknown_parameter")
        factor, code = rest
        if factor == "D" and code == BONUS:
            self.bonus = _number(key, raw)
        elif code in self.levels.get(factor, {}):
            self.levels[factor][code] = _number(key, raw)
        else:
            raise _bad(key, "unknown_parameter")

    def _scalar(self, key: str, rest: list[str], raw: str) -> None:
        if rest == ["s_without_cvss"]:
            self.s_without = _number(key, raw)
        elif rest == ["kev_exposed_floor"]:
            self.floor = _integer(key, raw)
        else:
            raise _bad(key, "unknown_parameter")

    def _band(self, key: str, rest: list[str], raw: str) -> None:
        band = ascii_int(rest[0]) if len(rest) == 1 else None
        if band is None or band not in self.bands:
            raise _bad(key, "unknown_parameter")
        self.bands[band] = _integer(key, raw)

    def _decay(self, key: str, rest: list[str], raw: str) -> None:
        number = ascii_int(rest[0]) if len(rest) == DECAY_PARTS else None
        if number is None or not 1 <= number <= len(self.limits):
            raise _bad(key, "unknown_parameter")
        index = number - 1
        if rest[1] == "multiplier":
            self.multipliers[index] = _number(key, raw)
        elif rest[1] == "max_age_days" and self.limits[index] is not None:
            self.limits[index] = _integer(key, raw)
        else:
            raise _bad(key, "unknown_parameter")

    def build(self) -> Formula:
        return replace(
            self.formula,
            weights=self.weights,
            levels=self.levels,
            personal_data_bonus=self.bonus,
            s_without_cvss=self.s_without,
            kev_exposed_floor=self.floor,
            urgency_bands=self.bands,
            decay=tuple(zip(self.limits, self.multipliers, strict=True)),
        )


def apply_changes(formula: Formula, changes: dict[str, str]) -> Formula:
    """The formula with `changes` applied and validated; raises `ValidationFailedError` with the rule that failed."""
    draft = _Draft(formula)
    for key, raw in changes.items():
        draft.set(key, raw)
    try:
        return draft.build()
    except FormulaError as error:
        raise ValidationFailedError(MESSAGE, tuple(Problem("body.changes", i) for i in _issues(str(error)))) from None


def _issues(text: str) -> list[str]:
    """Machine-readable rule behind a `FormulaError` (its text is English and never shown)."""
    lowered = text.lower()
    rules = (
        ("sum to 1.0", "weights_sum_to_one"),
        ("each weight", "weight_out_of_range"),
        ("monotonic", "levels_not_monotonic"),
        ("levels of", "level_out_of_range"),
        ("decay", "decay_not_decreasing"),
        ("urgency band", "bands_not_ordered"),
        ("s_without_cvss", "s_without_cvss_out_of_range"),
        ("floor", "floor_out_of_range"),
        ("dead zone", "dead_zone_out_of_range"),
    )
    return [issue for needle, issue in rules if needle in lowered][:1] or ["formula_invalid"]


@dataclass(frozen=True)
class NewVersion:
    author: uuid.UUID | None
    now: datetime
    note: str
    origin: str = "frontend"  # frontend | mode4
    reasons_enabled: Mapping[str, bool] | None = None  # FRO-03: flags to set; None copies the source's


def save_new_version(session: Session, source_id: uuid.UUID, formula: Formula, meta: NewVersion) -> m.FormulaVersion:
    """Create a new active version with `formula`'s values, copying what is not editable from `source_id`."""
    author, now, note = meta.author, meta.now, meta.note
    current = session.scalar(select(m.FormulaVersion).where(m.FormulaVersion.status == "active"))
    source = session.get(m.FormulaVersion, source_id)
    if source is None:
        raise LookupError("formula version not found")
    next_no = (
        session.scalar(select(m.FormulaVersion.version_no).order_by(m.FormulaVersion.version_no.desc())) or 0
    ) + 1
    version = m.FormulaVersion(
        version_no=next_no,
        status="draft",
        based_on_id=source.id,
        origin=meta.origin,
        s_without_cvss=formula.s_without_cvss,
        kev_exposed_floor=formula.kev_exposed_floor,
        hysteresis_margin=source.hysteresis_margin,
        hysteresis_evaluations=source.hysteresis_evaluations,
        hysteresis_days=source.hysteresis_days,
        note=note,
        created_by=author,
        created_at=now,
    )
    session.add(version)
    session.flush()
    for factor, weight in formula.weights.items():
        session.add(m.FormulaWeight(formula_version_id=version.id, factor=factor, weight=weight))
    for level in session.scalars(select(m.FormulaLevel).where(m.FormulaLevel.formula_version_id == source.id)):
        value = formula.personal_data_bonus if level.is_bonus else formula.levels[level.factor][level.level_code]
        session.add(
            m.FormulaLevel(
                formula_version_id=version.id,
                factor=level.factor,
                level_code=level.level_code,
                rank=level.rank,
                value=value,
                is_bonus=level.is_bonus,
            )
        )
    for urgency, minimum in formula.urgency_bands.items():
        session.add(m.FormulaUrgencyBand(formula_version_id=version.id, urgency=urgency, min_score=minimum))
    for number, (limit, multiplier) in enumerate(formula.decay, start=1):
        session.add(
            m.FormulaDecayStep(formula_version_id=version.id, step_no=number, max_age_days=limit, multiplier=multiplier)
        )
    for rng in session.scalars(
        select(m.FormulaReasonRange).where(m.FormulaReasonRange.formula_version_id == source.id)
    ):
        session.add(
            m.FormulaReasonRange(
                formula_version_id=version.id,
                reason_code=rng.reason_code,
                min_points=rng.min_points,
                max_points=rng.max_points,
                enabled=(meta.reasons_enabled or {}).get(rng.reason_code, rng.enabled),
            )
        )
    session.flush()
    if current is not None:
        current.status = "superseded"
        session.flush()
    version.status = "active"
    version.activated_at = now
    session.flush()
    return version
