"""Load a formula version from the database into the engine's ``Formula`` (formula_* tables, A-10).

The active version drives every evaluation; a specific version (for history or a simulation of a draft) can be
loaded by id. The dead zone is an editable setting (``setting_current.dead_zone``), not part of the version.
Whatever the database holds goes through ``validate_formula``, so a malformed version fails loudly here instead
of producing wrong scores.
"""

from __future__ import annotations

import uuid
from decimal import Decimal

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from core.db import models as m
from core.scoring.engine import Formula, FormulaError

DEFAULT_DEAD_ZONE = 4


class FormulaVersionNotFoundError(LookupError):
    """The requested formula version does not exist."""


class NoActiveFormulaError(FormulaVersionNotFoundError):
    """No formula version is active (the database was never seeded or every version was superseded)."""


def load_active_formula(session: Session) -> tuple[uuid.UUID, Formula]:
    version_id = session.scalar(select(m.FormulaVersion.id).where(m.FormulaVersion.status == "active"))
    if version_id is None:
        raise NoActiveFormulaError("no active formula version")
    return version_id, load_formula(session, version_id)


def load_formula(session: Session, version_id: uuid.UUID) -> Formula:
    version = session.get(m.FormulaVersion, version_id)
    if version is None:
        raise FormulaVersionNotFoundError(f"formula version {version_id} does not exist")
    weights = {
        w.factor: w.weight
        for w in session.scalars(select(m.FormulaWeight).where(m.FormulaWeight.formula_version_id == version_id))
    }
    levels: dict[str, dict[str, Decimal]] = {}
    bonus: Decimal | None = None
    rows = session.scalars(
        select(m.FormulaLevel)
        .where(m.FormulaLevel.formula_version_id == version_id)
        .order_by(m.FormulaLevel.factor, m.FormulaLevel.rank)
    )
    for level in rows:
        if level.is_bonus:  # the database allows only D.personal_data_bonus (formula_level_bonus_only_d)
            bonus = level.value
            continue
        levels.setdefault(level.factor, {})[level.level_code] = level.value
    if bonus is None:
        raise FormulaError("the formula version has no personal-data bonus level")
    bands = {
        b.urgency: b.min_score
        for b in session.scalars(
            select(m.FormulaUrgencyBand).where(m.FormulaUrgencyBand.formula_version_id == version_id)
        )
    }
    decay = tuple(
        (step.max_age_days, step.multiplier)
        for step in session.scalars(
            select(m.FormulaDecayStep)
            .where(m.FormulaDecayStep.formula_version_id == version_id)
            .order_by(m.FormulaDecayStep.step_no)
        )
    )
    return Formula(
        weights=weights,
        levels=levels,
        personal_data_bonus=bonus,
        s_without_cvss=version.s_without_cvss,
        kev_exposed_floor=version.kev_exposed_floor,
        dead_zone=_dead_zone(session),
        urgency_bands=bands,
        decay=decay,
    )


def _dead_zone(session: Session) -> int:
    value = session.execute(
        text("SELECT value FROM setting_current WHERE setting_key = 'dead_zone'")
    ).scalar_one_or_none()
    if value is None:  # unseeded settings catalog: the documented default (docs/11)
        return DEFAULT_DEAD_ZONE
    if isinstance(value, bool) or not isinstance(value, int | str):
        raise FormulaError("the dead_zone setting must be an integer")
    try:
        return int(value)
    except ValueError as exc:
        raise FormulaError("the dead_zone setting must be an integer") from exc
