"""Weight proposals from the human feedback of the last 30 days, tested before they are proposed (docs/07 §10).

Humans say what a finding should have scored (`wrong_priority` feedback with `proposed_score`). The engine is
deterministic, so every candidate weight change can be replayed over the stored factors: the score a ticket got is
the highest final among its CIs (EVA-07). A change is proposed only when it brings the scores closer to the humans'
by more than the noise, over at least 30 cases; one weight at a time, at most +/- the weekly limit, the others
rescaled so the weights still add up to 1.0.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import Final

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.scoring.engine import FACTORS, Factors, Formula, FormulaError, base_score, final_score, floor_eligible

WINDOW_DAYS: Final = 30
MIN_CASES: Final = 30  # docs/07 §10: a change only counts with enough cases
NOISE_RELATIVE: Final = Decimal("0.05")  # the new error must be at least 5% lower ...
NOISE_ABSOLUTE: Final = Decimal("0.5")  # ... and half a point lower
PLACES: Final = Decimal("0.0001")


@dataclass(frozen=True)
class CaseCi:
    factors: Factors
    version_factor: Decimal
    ci_adjustment: int
    exposed: bool | None


@dataclass(frozen=True)
class Case:
    """One piece of feedback: the CIs of the assessment it was about and the score a person wanted."""

    cis: tuple[CaseCi, ...]
    judge_adjustment: int
    in_kev: bool
    wanted: int


@dataclass(frozen=True)
class Candidate:
    factor: str
    formula: Formula
    mae_before: Decimal
    mae_after: Decimal
    cases: int


_CASES = text(
    "SELECT f.id, a.judge_adjustment, COALESCE(a.raw_in_kev, false), f.proposed_score, "
    "a.factor_s, a.factor_p, a.factor_t, s.factor_a, s.factor_d, s.version_factor, s.ci_adjustment, s.snap_exposed "
    "FROM feedback f JOIN assessment a ON a.id = f.assessment_id JOIN asset_score s ON s.assessment_id = a.id "
    "WHERE f.verdict = 'wrong_priority' AND f.proposed_score IS NOT NULL AND f.superseded_at IS NULL "
    "AND f.created_at >= :since ORDER BY f.id, s.asset_id"
)


def load_cases(session: Session, now: datetime) -> list[Case]:
    cis: dict[uuid.UUID, list[CaseCi]] = defaultdict(list)
    heads: dict[uuid.UUID, tuple[int, bool, int]] = {}
    for row in session.execute(_CASES, {"since": now - timedelta(days=WINDOW_DAYS)}):
        feedback_id, adjustment, in_kev, wanted = row[0], row[1], row[2], row[3]
        heads.setdefault(feedback_id, (int(adjustment), bool(in_kev), int(wanted)))
        factors = Factors(*(Decimal(row[i]) for i in range(4, 9)))
        cis[feedback_id].append(CaseCi(factors, Decimal(row[9]), int(row[10]), row[11]))
    return [Case(tuple(cis[fid]), *heads[fid]) for fid in heads]


def ticket_final(formula: Formula, case: Case) -> int:
    return max(
        final_score(
            formula,
            base_score(formula, ci.factors, ci.version_factor),
            judge_adjustment=case.judge_adjustment,
            ci_adjustment=ci.ci_adjustment,
            floor=floor_eligible(in_kev=case.in_kev, exposed=ci.exposed),
        ).final
        for ci in case.cis
    )


def mean_error(formula: Formula, cases: list[Case]) -> Decimal:
    total = sum(abs(ticket_final(formula, case) - case.wanted) for case in cases)
    return Decimal(total) / Decimal(len(cases))


def shifted(weights: dict[str, Decimal], factor: str, relative: Decimal) -> dict[str, Decimal] | None:
    """`factor` changed by `relative` (+0.10 = +10%), the others rescaled, rounded to 4 places, sum exactly 1."""
    new = (weights[factor] * (Decimal(1) + relative)).quantize(PLACES, ROUND_HALF_UP)
    if not Decimal(0) <= new <= Decimal(1) or new == weights[factor]:
        return None
    others = {f: w for f, w in weights.items() if f != factor}
    total = sum(others.values(), Decimal(0))
    if total == 0:
        return None
    scaled = {f: (w * (Decimal(1) - new) / total).quantize(PLACES, ROUND_HALF_UP) for f, w in others.items()}
    largest = max(scaled, key=lambda f: scaled[f])
    scaled[largest] += Decimal(1) - new - sum(scaled.values(), Decimal(0))
    return {**scaled, factor: new}


def best_candidate(
    formula: Formula, cases: list[Case], weekly_limit: Decimal, skip: frozenset[str]
) -> Candidate | None:
    """The single weight change that best matches the feedback, or None when nothing clearly improves."""
    if len(cases) < MIN_CASES:
        return None
    before = mean_error(formula, cases)
    best: Candidate | None = None
    for factor in FACTORS:
        if f"weights.{factor}" in skip:
            continue
        for sign in (Decimal(1), Decimal(-1)):
            weights = shifted(dict(formula.weights), factor, sign * weekly_limit)
            if weights is None:
                continue
            try:
                candidate = replace(formula, weights=weights)
            except FormulaError:
                continue
            after = mean_error(candidate, cases)
            if best is None or after < best.mae_after:
                best = Candidate(factor, candidate, before, after, len(cases))
    if best is None:
        return None
    gain = best.mae_before - best.mae_after
    if gain < NOISE_ABSOLUTE or gain < best.mae_before * NOISE_RELATIVE:
        return None
    return best
