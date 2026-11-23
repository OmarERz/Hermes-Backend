"""Raw vs processed (D-039, EVA-11 to EVA-13, MET-24 to MET-27) and the waterfall of one score (EVA-12).

The raw value is what a CVSS-only scanner would say (100 x S). The comparison runs over the current scored
findings with the raw snapshot each assessment kept (EVA-14), so a later NVD change does not move it. Levels are
compared by name, each on its own scale (EVA-13): a CVSS 7.0 is "high" while 70 on the final scale is "medium".
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from typing import Final

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.scoring.engine import (
    Factors,
    FinalScore,
    Formula,
    clamp_score,
    cvss_level,
    delta_breakdown,
    final_score,
    floor_eligible,
    round_half_up,
)
from core.scoring.formula_repo import load_formula
from core.views.common import LEVELS, ScoredFinding, scored_findings, speaking

HIDDEN_CRITICAL_CVSS: Final = Decimal("7.0")  # MET-25: CVSS below 7.0 ...
HIDDEN_CRITICAL_FINAL: Final = 75  # ... with a final of 75 or more
NOISE_CVSS: Final = Decimal("9.0")  # MET-26: CVSS 9.0 or more ...
NOISE_FINAL: Final = 50  # ... with a final below 50
MIN_PAIR: Final = 2
CAUSES: Final = {
    "P": "Explotación",
    "T": "Contexto de amenaza",
    "A": "Criticidad y exposición del activo",
    "D": "Sensibilidad de los datos",
    "judge": "Ajuste del juez",
    "floor": "Piso de KEV con el activo expuesto",
}

_INPUTS: Final = text(
    """
    SELECT s.assessment_id, s.asset_id, ast.itop_ci_id AS ci_id, ast.name AS asset_name, a.formula_version_id,
           a.factor_s, a.factor_p, a.factor_t, s.factor_a, s.factor_d, s.version_factor, s.base, s.ci_adjustment,
           s.final, a.judge_adjustment, a.raw_cvss_score, a.raw_in_kev, s.snap_exposed,
           (a.llm_review_id IS NULL OR r.status = 'no_judge_review') AS no_judge_review,
           (ast.decommissioned_at IS NOT NULL) AS retired
      FROM asset_score s
      JOIN assessment a ON a.id = s.assessment_id
      JOIN asset ast ON ast.id = s.asset_id
      LEFT JOIN llm_review r ON r.id = a.llm_review_id
     WHERE s.assessment_id = ANY(CAST(:assessments AS uuid[]))
    """
)


@dataclass(frozen=True)
class ScoreInputs:
    """Everything stored for one CI score: the factors, the adjustments and the raw snapshot."""

    assessment_id: uuid.UUID
    asset_id: uuid.UUID
    ci_id: str
    asset_name: str
    formula_version_id: uuid.UUID
    factor_s: Decimal
    factor_p: Decimal
    factor_t: Decimal
    factor_a: Decimal
    factor_d: Decimal
    version_factor: Decimal
    base: int
    ci_adjustment: int
    final: int
    judge_adjustment: int
    raw_cvss_score: Decimal | None
    raw_in_kev: bool | None
    snap_exposed: bool | None
    no_judge_review: bool
    retired: bool

    @property
    def factors(self) -> Factors:
        return Factors(s=self.factor_s, p=self.factor_p, t=self.factor_t, a=self.factor_a, d=self.factor_d)

    @property
    def raw(self) -> int:
        """EVA-11: 100 x S, rounded half up (the `raw_value` of asset_score_detail)."""
        return round_half_up(100 * self.factor_s)


ScoreKey = tuple[uuid.UUID, uuid.UUID]  # (assessment, asset)


def load_inputs(session: Session, assessment_ids: Sequence[uuid.UUID]) -> dict[ScoreKey, ScoreInputs]:
    """The stored inputs of every CI score of the given assessments, by (assessment, asset)."""
    if not assessment_ids:
        return {}
    rows = session.execute(_INPUTS, {"assessments": list(set(assessment_ids))}).mappings().all()
    return {(row["assessment_id"], row["asset_id"]): ScoreInputs(**row) for row in rows}


class FormulaCache:
    """Formula versions loaded once per request."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._loaded: dict[uuid.UUID, Formula] = {}

    def get(self, version_id: uuid.UUID) -> Formula:
        if version_id not in self._loaded:
            self._loaded[version_id] = load_formula(self._session, version_id)
        return self._loaded[version_id]


def _result(formula: Formula, inputs: ScoreInputs) -> FinalScore:
    """The engine's account of the stored final. When today's dead zone no longer reproduces the stored final
    (it is a setting, not part of the formula version), the stored base and final win: the whole difference is
    shown as the judge's adjustment."""
    result = final_score(
        formula,
        inputs.base,
        judge_adjustment=None if inputs.no_judge_review else inputs.judge_adjustment,
        ci_adjustment=inputs.ci_adjustment,
        floor=floor_eligible(in_kev=bool(inputs.raw_in_kev), exposed=inputs.snap_exposed),
    )
    if result.final == inputs.final:
        return result
    difference = inputs.final - inputs.base
    return FinalScore(
        final=inputs.final,
        applied_adjustment=difference,
        proposed_adjustment=difference,
        clamp_effect=0,
        floor_applied=False,
        suggestion=None,
        no_judge_review=inputs.no_judge_review,
    )


def bars(formula: Formula, inputs: ScoreInputs) -> dict[str, int]:
    """EVA-12 waterfall in whole points: raw + every bar == final, exactly.

    P, T, A and D are 100 · wX · (X - S) rounded half up; `judge`, `clamp` and `floor` come from the engine;
    `version` is the effect of E on alerts without a finding (0 otherwise); `rounding` takes what the whole-point
    display leaves over (the rounding of the base and of the four terms).
    """
    result = _result(formula, inputs)
    detail = delta_breakdown(formula, inputs.factors, result, inputs.base)
    out = {name: round_half_up(value) for name, value in detail.terms.items()}
    unversioned = clamp_score(round_half_up(detail.raw + sum(detail.terms.values(), Decimal(0))))
    out["judge"] = detail.judge
    out["clamp"] = detail.clamp
    out["floor"] = detail.floor
    out["version"] = inputs.base - unversioned if inputs.version_factor != 1 else 0
    out["rounding"] = inputs.final - inputs.raw - sum(out.values())
    return out


def main_cause(waterfall: dict[str, int]) -> str:
    """The bar that moves the score the most, in words (P, T, A, D, judge or floor)."""
    name = max(CAUSES, key=lambda key: (abs(waterfall.get(key, 0)), -list(CAUSES).index(key)))
    value = waterfall.get(name, 0)
    return "Sin cambio frente al CVSS" if value == 0 else f"{CAUSES[name]} ({value:+d})"


@dataclass(frozen=True)
class ComparisonRow:
    finding_id: uuid.UUID
    cve: str
    product: str
    ci_id: str
    cvss: Decimal | None
    raw: int
    base: int
    judge_adjustment: int
    final: int
    delta: int
    main_cause: str


@dataclass(frozen=True)
class Summary:
    reclassification_matrix: dict[str, dict[str, int]]
    funnel: dict[str, int]
    reclassified_percent: str
    hidden_criticals: int
    avoided_noise: int
    rank_correlation: str


def _current(session: Session) -> tuple[list[ScoredFinding], dict[ScoreKey, ScoreInputs]]:
    rows = [r for r in scored_findings(session) if r.is_current]
    return rows, load_inputs(session, [r.assessment_id for r in rows])


def comparison_rows(session: Session) -> list[ComparisonRow]:
    """One row per current scored finding, with its raw value, its score and the main cause of the change."""
    rows, inputs = _current(session)
    formulas = FormulaCache(session)
    out: list[ComparisonRow] = []
    for row in rows:
        stored = inputs[(row.assessment_id, row.asset_id)]
        waterfall = bars(formulas.get(stored.formula_version_id), stored)
        out.append(
            ComparisonRow(
                finding_id=row.finding_id,
                cve=row.cve,
                product=row.product,
                ci_id=row.ci_id,
                cvss=stored.raw_cvss_score,
                raw=stored.raw,
                base=row.base,
                judge_adjustment=row.judge_adjustment + row.ci_adjustment,
                final=row.final,
                delta=row.final - stored.raw,
                main_cause=main_cause(waterfall),
            )
        )
    return out


def _percent(part: int, whole: int) -> str:
    if whole == 0:
        return "0.0"
    return str((Decimal(100 * part) / Decimal(whole)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def summary(session: Session) -> Summary:
    """Matrix, funnel and indicators over the current scored findings (MET-24 to MET-27)."""
    rows, inputs = _current(session)
    rated = [(r, inputs[(r.assessment_id, r.asset_id)].raw_cvss_score) for r in rows]
    with_cvss = [(r, cvss) for r, cvss in rated if cvss is not None]
    matrix = {row: dict.fromkeys(LEVELS, 0) for row in LEVELS}
    for r, cvss in with_cvss:
        level = cvss_level(cvss)
        if level in matrix and r.level in matrix[level]:
            matrix[level][r.level] += 1
    by_group: dict[uuid.UUID, list[ScoredFinding]] = defaultdict(list)
    for r in rows:
        by_group[r.group_id].append(r)
    voices = {group: max(speaking(members), key=lambda m: m.final) for group, members in by_group.items()}
    funnel = {
        "raw": len(rows),
        "groups": len(by_group),
        "with_threat_context": sum(1 for v in voices.values() if inputs[(v.assessment_id, v.asset_id)].factor_t > 0),
        "judge_adjusted": sum(
            1 for members in by_group.values() if any(m.judge_adjustment + m.ci_adjustment != 0 for m in members)
        ),
        "high_or_critical": sum(1 for v in voices.values() if v.level in {"critical", "high"}),
    }
    tau = kendall_tau_b([cvss for _r, cvss in with_cvss], [Decimal(r.final) for r, _c in with_cvss])
    return Summary(
        reclassification_matrix=matrix,
        funnel=funnel,
        reclassified_percent=_percent(sum(1 for r, cvss in with_cvss if cvss_level(cvss) != r.level), len(with_cvss)),
        hidden_criticals=sum(
            1 for r, cvss in with_cvss if cvss < HIDDEN_CRITICAL_CVSS and r.final >= HIDDEN_CRITICAL_FINAL
        ),
        avoided_noise=sum(1 for r, cvss in with_cvss if cvss >= NOISE_CVSS and r.final < NOISE_FINAL),
        rank_correlation=str((tau or Decimal(0)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)),
    )


def _inversions(values: list[Decimal]) -> int:
    """Pairs i < j with values[i] > values[j] (strictly), by merge sort: O(n log n)."""
    if len(values) < MIN_PAIR:
        return 0
    middle = len(values) // 2
    left, right = values[:middle], values[middle:]
    count = _inversions(left) + _inversions(right)
    left.sort()
    right.sort()
    j = 0
    for item in left:
        while j < len(right) and right[j] < item:
            j += 1
        count += j
    return count


def _tied_pairs(values: Sequence[object]) -> int:
    counts: dict[object, int] = defaultdict(int)
    for value in values:
        counts[value] += 1
    return sum(c * (c - 1) // 2 for c in counts.values())


def kendall_tau_b(xs: Sequence[Decimal], ys: Sequence[Decimal]) -> Decimal | None:
    """Kendall's tau-b between two orders (MET-27), O(n log n) (Knight's method); None when undefined."""
    n = len(xs)
    if n < MIN_PAIR or n != len(ys):
        return None
    pairs = sorted(zip(xs, ys, strict=True))
    total = n * (n - 1) // 2
    tied_x, tied_y, tied_both = _tied_pairs(xs), _tied_pairs(ys), _tied_pairs(pairs)
    discordant = _inversions([y for _x, y in pairs])
    numerator = total - tied_x - tied_y + tied_both - 2 * discordant
    denominator = (Decimal(total - tied_x) * Decimal(total - tied_y)).sqrt()
    return None if denominator == 0 else Decimal(numerator) / denominator


@dataclass(frozen=True)
class Breakdown:
    assessment_id: uuid.UUID
    ci_id: str
    raw: int
    waterfall: dict[str, int]
    final: int


def assessment_breakdown(session: Session, assessment_id: uuid.UUID, ci_id: str | None) -> Breakdown | None:
    """The waterfall of one CI of an assessment: the given CI, or the one with the highest final (live CIs first,
    ties by name). None if the assessment, or that CI in it, does not exist."""
    scores = list(load_inputs(session, [assessment_id]).values())
    if ci_id is not None:
        scores = [s for s in scores if s.ci_id == ci_id]
    if not scores:
        return None
    pool = [s for s in scores if not s.retired] or scores
    chosen = max(sorted(pool, key=lambda s: (s.asset_name, str(s.asset_id))), key=lambda s: s.final)
    waterfall = bars(load_formula(session, chosen.formula_version_id), chosen)
    return Breakdown(assessment_id, chosen.ci_id, chosen.raw, waterfall, chosen.final)
