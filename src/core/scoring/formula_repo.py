"""Load a formula version from the database into the engine's ``Formula`` (formula_* tables, A-10).

The active version drives every evaluation; a specific version (for history or a simulation of a draft) can be
loaded by id. The dead zone is an editable setting (``setting_current.dead_zone``), not part of the version.
Whatever the database holds goes through ``validate_formula``, so a malformed version fails loudly here instead
of producing wrong scores.
"""

from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.scoring.engine import Formula, FormulaError

DEFAULT_DEAD_ZONE = 4


class FormulaVersionNotFoundError(LookupError):
    """The requested formula version does not exist."""


class NoActiveFormulaError(FormulaVersionNotFoundError):
    """No formula version is active (the database was never seeded or every version was superseded)."""


# The whole formula — version, weights, levels, bands, decay and the dead zone setting — in one statement, so one
# snapshot: under READ COMMITTED a formula change committed between separate queries could otherwise mix two versions
# (or a version with another dead zone) into a combination that was never active. Numerics travel as text so the
# Decimal values are exact.
_FORMULA = text(
    """
    SELECT fv.id, fv.s_without_cvss::text AS s_without_cvss, fv.kev_exposed_floor,
           (SELECT json_agg(json_build_object('factor', w.factor, 'weight', w.weight::text))
              FROM formula_weight w WHERE w.formula_version_id = fv.id) AS weights,
           (SELECT json_agg(json_build_object('factor', l.factor, 'code', l.level_code, 'value', l."value"::text,
                                              'bonus', l.is_bonus) ORDER BY l.factor, l."rank")
              FROM formula_level l WHERE l.formula_version_id = fv.id) AS levels,
           (SELECT json_agg(json_build_object('urgency', b.urgency, 'min_score', b.min_score))
              FROM formula_urgency_band b WHERE b.formula_version_id = fv.id) AS bands,
           (SELECT json_agg(json_build_object('max_age_days', d.max_age_days, 'multiplier', d.multiplier::text)
                            ORDER BY d.step_no)
              FROM formula_decay_step d WHERE d.formula_version_id = fv.id) AS decay,
           (SELECT sc.value FROM setting_current sc WHERE sc.setting_key = 'dead_zone') AS dead_zone
      FROM formula_version fv
     WHERE (CAST(:version_id AS uuid) IS NULL AND fv.status = 'active') OR fv.id = CAST(:version_id AS uuid)
    """
)


def load_active_formula(session: Session) -> tuple[uuid.UUID, Formula]:
    row = session.execute(_FORMULA, {"version_id": None}).one_or_none()
    if row is None:
        raise NoActiveFormulaError("no active formula version")
    return row.id, _formula(row)


def load_formula(session: Session, version_id: uuid.UUID) -> Formula:
    row = session.execute(_FORMULA, {"version_id": version_id}).one_or_none()
    if row is None:
        raise FormulaVersionNotFoundError(f"formula version {version_id} does not exist")
    return _formula(row)


def _formula(row: Any) -> Formula:
    weights = {w["factor"]: Decimal(w["weight"]) for w in row.weights or []}
    levels: dict[str, dict[str, Decimal]] = {}
    bonus: Decimal | None = None
    for level in row.levels or []:
        if level["bonus"]:  # the database allows only D.personal_data_bonus (formula_level_bonus_only_d)
            bonus = Decimal(level["value"])
            continue
        levels.setdefault(level["factor"], {})[level["code"]] = Decimal(level["value"])
    if bonus is None:
        raise FormulaError("the formula version has no personal-data bonus level")
    return Formula(
        weights=weights,
        levels=levels,
        personal_data_bonus=bonus,
        s_without_cvss=Decimal(row.s_without_cvss),
        kev_exposed_floor=row.kev_exposed_floor,
        dead_zone=_dead_zone(row.dead_zone),
        urgency_bands={b["urgency"]: b["min_score"] for b in row.bands or []},
        decay=tuple((d["max_age_days"], Decimal(d["multiplier"])) for d in row.decay or []),
    )


def _dead_zone(value: object) -> int:
    if value is None:  # unseeded settings catalog: the documented default (docs/11)
        return DEFAULT_DEAD_ZONE
    if isinstance(value, bool) or not isinstance(value, int | str):
        raise FormulaError("the dead_zone setting must be an integer")
    try:
        return int(value)
    except ValueError as exc:
        raise FormulaError("the dead_zone setting must be an integer") from exc
