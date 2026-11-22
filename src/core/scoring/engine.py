"""Per-CI scoring engine (docs/06 §3-§4.2, EVA-01..EVA-14). Pure functions, no I/O, no LLM.

All arithmetic uses ``decimal.Decimal`` with ROUND_HALF_UP (EVA-10). The formula parameters (weights, factor
levels, urgency bands, decay steps) are injected as a ``Formula`` so a formula version from the database, a
simulation or a test can drive the same code.

    base(CI)  = 100 x (wS·S + wP·P + wT·T + wA·A(CI) + wD·D(CI))
    final(CI) = clamp(base + net adjustment, 0, 100), dead zone on the adjustment, KEV + exposed floor
    ticket    = the highest final among the ticket's current CIs (EVA-07/EVA-08)
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal
from enum import StrEnum
from itertools import pairwise

FACTORS = ("S", "P", "T", "A", "D")
ONE = Decimal(1)
ZERO = Decimal(0)
HUNDRED = Decimal(100)
TEN = Decimal(10)
MAX_SCORE = 100


def round_half_up(value: Decimal) -> int:
    """Round to an integer, halves away from zero for positives (EVA-10: 40.5 -> 41)."""
    return int(value.quantize(ONE, rounding=ROUND_HALF_UP))


def clamp_score(value: int) -> int:
    return max(0, min(MAX_SCORE, value))


class FormulaError(ValueError):
    """The formula parameters break a structural rule (weights must sum to 1.0, levels must be monotonic)."""


@dataclass(frozen=True)
class Formula:
    """One formula version (docs/datos/modelo-v1 formula_*): weights, level values, floors and bands."""

    weights: Mapping[str, Decimal]
    levels: Mapping[str, Mapping[str, Decimal]]  # factor -> level code -> value, strongest first
    personal_data_bonus: Decimal = Decimal("0.2")
    s_without_cvss: Decimal = Decimal("0.8")
    kev_exposed_floor: int = 90
    dead_zone: int = 4
    urgency_bands: Mapping[int, int] = field(default_factory=lambda: {1: 90, 2: 75, 3: 50, 4: 0})
    decay: Sequence[tuple[int | None, Decimal]] = (
        (7, Decimal("1.0")),
        (30, Decimal("0.6")),
        (None, Decimal("0.3")),
    )

    def __post_init__(self) -> None:
        validate_formula(self)

    def level(self, factor: str, code: str) -> Decimal:
        try:
            return self.levels[factor][code]
        except KeyError as exc:
            raise FormulaError(f"unknown level {factor}.{code}") from exc


# Rank of every level, strongest first (formula_level.rank, A-10). Monotonicity is checked in this order, never
# in the order a mapping happens to list its keys.
LEVEL_ORDER: dict[str, tuple[str, ...]] = {
    "P": ("kev_or_exploited", "public_poc", "epss_p90", "other"),
    "T": (
        "peer_exploited_with_vector",
        "peer_attacked",
        "sector_region_with_vector",
        "trend_4_or_more_sources",
        "sector_region",
        "trend_2_to_3_sources",
        "sector_only",
        "trend_1_source",
        "no_news",
    ),
    "A": ("critical_exposed", "critical_internal_or_normal_exposed", "normal_internal_or_unknown", "low"),
    "D": ("highly_classified", "classified", "unclassified", "public"),
    "E": ("version_confirmed", "version_unknown"),
}
FLOOR_RANGE = (80, 100)  # FRO-01: editable only inside this range
S_WITHOUT_CVSS_RANGE = (Decimal("0.5"), ONE)  # FRO-05
DEAD_ZONE_RANGE = (0, 10)  # docs/11 dead_zone


def validate_formula(formula: Formula) -> None:
    """FRO-05: weights in 0-1 summing to exactly 1.0; levels monotonic by rank; decay decreasing in 0-1;
    urgency bands ordered; s_without_cvss 0.5-1.0; floor 80-100; dead zone 0-10."""
    _validate_weights(formula)
    _validate_levels(formula)
    _validate_decay(formula)
    _validate_bands(formula)
    if not S_WITHOUT_CVSS_RANGE[0] <= formula.s_without_cvss <= S_WITHOUT_CVSS_RANGE[1]:
        raise FormulaError("s_without_cvss must be between 0.5 and 1.0")
    if not FLOOR_RANGE[0] <= formula.kev_exposed_floor <= FLOOR_RANGE[1]:
        raise FormulaError("the KEV + exposed floor must be between 80 and 100")
    if not DEAD_ZONE_RANGE[0] <= formula.dead_zone <= DEAD_ZONE_RANGE[1]:
        raise FormulaError("the dead zone must be between 0 and 10")


URGENCIES = (1, 2, 3, 4)  # TIC-03, formula_urgency_band


def _validate_bands(formula: Formula) -> None:
    if tuple(sorted(formula.urgency_bands)) != URGENCIES:
        raise FormulaError(f"urgency bands must be exactly {URGENCIES}")
    minimums = [formula.urgency_bands[band] for band in URGENCIES]
    if any(not 0 <= m <= MAX_SCORE for m in minimums):
        raise FormulaError("urgency band thresholds must be between 0 and 100")
    if any(later >= earlier for earlier, later in pairwise(minimums)):
        raise FormulaError("urgency bands must be ordered (more urgent bands need higher scores)")
    if minimums[-1] != 0:
        raise FormulaError("the lowest urgency band must start at 0 so every score has a band")


def _validate_weights(formula: Formula) -> None:
    if set(formula.weights) != set(FACTORS):
        raise FormulaError(f"weights must cover exactly {FACTORS}")
    if any(not ZERO <= w <= ONE for w in formula.weights.values()):
        raise FormulaError("each weight must be between 0 and 1")
    total = sum(formula.weights.values(), ZERO)
    if total != ONE:
        raise FormulaError(f"weights must sum to 1.0, got {total}")


def _validate_levels(formula: Formula) -> None:
    if set(formula.levels) != set(LEVEL_ORDER):
        raise FormulaError(f"levels must cover exactly the factors {tuple(LEVEL_ORDER)}")
    for factor, values in formula.levels.items():
        order = LEVEL_ORDER.get(factor)
        if order is None or set(values) != set(order):
            raise FormulaError(f"levels of {factor} must be exactly {order}")
        if any(not ZERO <= v <= ONE for v in values.values()):
            raise FormulaError(f"levels of {factor} must be between 0 and 1")
        ranked = [values[code] for code in order]
        if any(later > earlier for earlier, later in pairwise(ranked)):
            raise FormulaError(f"levels of {factor} must be monotonic (strongest first)")


def _validate_decay(formula: Formula) -> None:
    multipliers = [m for _limit, m in formula.decay]
    limits = [limit for limit, _m in formula.decay]
    finite = [limit for limit in limits[:-1] if limit is not None]
    if not multipliers or limits[-1] is not None or len(finite) != len(limits) - 1:
        raise FormulaError("decay steps must end with an open step (no day limit)")
    if any(later <= earlier for earlier, later in pairwise(finite)) or any(limit < 0 for limit in finite):
        raise FormulaError("decay day limits must be non-negative and strictly increasing")
    if any(not ZERO <= m <= ONE for m in multipliers) or any(b > a for a, b in pairwise(multipliers)):
        raise FormulaError("decay multipliers must decrease and stay between 0 and 1")


def default_formula() -> Formula:
    """Formula v1 (D-034, A-10): the same values the seed loads."""
    d = Decimal
    return Formula(
        weights={"S": d("0.25"), "P": d("0.30"), "T": d("0.20"), "A": d("0.15"), "D": d("0.10")},
        levels={
            "P": {"kev_or_exploited": d("1.0"), "public_poc": d("0.75"), "epss_p90": d("0.5"), "other": d("0.2")},
            "T": {
                "peer_exploited_with_vector": d("1.0"),
                "peer_attacked": d("0.85"),
                "sector_region_with_vector": d("0.7"),
                "trend_4_or_more_sources": d("0.6"),
                "sector_region": d("0.5"),
                "trend_2_to_3_sources": d("0.4"),
                "sector_only": d("0.3"),
                "trend_1_source": d("0.2"),
                "no_news": d("0.0"),
            },
            "A": {
                "critical_exposed": d("1.0"),
                "critical_internal_or_normal_exposed": d("0.8"),
                "normal_internal_or_unknown": d("0.5"),
                "low": d("0.3"),
            },
            "D": {"highly_classified": d("0.8"), "classified": d("0.5"), "unclassified": d("0.5"), "public": d("0.1")},
            "E": {"version_confirmed": d("1.0"), "version_unknown": d("0.6")},
        },
    )


# --- Factors ------------------------------------------------------------------------------------------------


class SeverityOrigin(StrEnum):
    CVSS = "cvss"  # CNA or NVD score
    ESTIMATED = "estimated"  # computed from the CVE analyst's inferred vector
    UNRATED = "unrated"  # no score at all: conservative default


def severity(
    formula: Formula, cvss: Decimal | None, inferred_cvss: Decimal | None = None
) -> tuple[Decimal, SeverityOrigin]:
    """S = CVSS / 10; else the inferred vector's score / 10 (estimated); else s_without_cvss (unrated)."""
    if cvss is not None:
        return _unit(cvss / TEN), SeverityOrigin.CVSS
    if inferred_cvss is not None:
        return _unit(inferred_cvss / TEN), SeverityOrigin.ESTIMATED
    return formula.s_without_cvss, SeverityOrigin.UNRATED


class ExploitationGrade(StrEnum):
    """Grade reported by the news analysts (docs/05)."""

    NONE = "none"
    DENIED = "denied"
    ATTEMPTED = "attempted"
    LIMITED = "limited"
    ACTIVE = "active"
    MASS = "mass"


CONFIRMED_GRADES = frozenset({ExploitationGrade.LIMITED, ExploitationGrade.ACTIVE, ExploitationGrade.MASS})


def exploitation_level(
    *, in_kev: bool, grade: ExploitationGrade, public_poc: bool, epss_percentile: Decimal | None
) -> str:
    """P level: KEV or confirmed exploitation > PoC/public exploit or attempted > EPSS percentile ≥ 0.90 > other.

    A ``denied`` grade adds nothing (it never lowers a KEV entry either).
    """
    if in_kev or grade in CONFIRMED_GRADES:
        return "kev_or_exploited"
    if public_poc or grade is ExploitationGrade.ATTEMPTED:
        return "public_poc"
    if epss_percentile is not None and epss_percentile >= Decimal("0.90"):
        return "epss_p90"
    return "other"


@dataclass(frozen=True)
class ThreatEvidence:
    """One threat-context signal for a group, with the age in days of its newest supporting news."""

    level_code: str  # a T level code, e.g. "peer_attacked"
    age_days: int


TREND_MANY_SOURCES = 4
TREND_SOME_SOURCES = 2


def trend_level(sources_last_7_days: int) -> str | None:
    """Trend level from the number of distinct sources reporting in the last 7 days (none -> no trend)."""
    if sources_last_7_days >= TREND_MANY_SOURCES:
        return "trend_4_or_more_sources"
    if sources_last_7_days >= TREND_SOME_SOURCES:
        return "trend_2_to_3_sources"
    if sources_last_7_days == 1:
        return "trend_1_source"
    return None


def decay_multiplier(formula: Formula, age_days: int) -> Decimal:
    """Weight loss by evidence age (D-013): x1.0 up to day 7, x0.6 days 8-30, x0.3 after."""
    for limit, multiplier in formula.decay:
        if limit is None or age_days <= limit:
            return multiplier
    return formula.decay[-1][1]


def threat(formula: Formula, evidence: Iterable[ThreatEvidence]) -> Decimal:
    """T = the maximum over the evidence of level value x decay(age), never below the configured no-news level
    (0 in formula v1). KEV/P never decay."""
    best = formula.level("T", "no_news")
    for item in evidence:
        value = formula.level("T", item.level_code) * decay_multiplier(formula, item.age_days)
        best = max(best, value)
    return best


class Criticality(StrEnum):
    """iTop business criticality as cached in ``asset.criticality``."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


def asset_level(criticality: Criticality, exposed: bool | None) -> str:
    """A level (docs/06 §3). Exposure unknown counts as internal (P-013); no criticality is 0.5 even if exposed."""
    is_exposed = exposed is True
    if criticality is Criticality.HIGH:
        return "critical_exposed" if is_exposed else "critical_internal_or_normal_exposed"
    if criticality is Criticality.MEDIUM:
        return "critical_internal_or_normal_exposed" if is_exposed else "normal_internal_or_unknown"
    if criticality is Criticality.LOW:
        return "low"
    return "normal_internal_or_unknown"


class Confidentiality(StrEnum):
    """D-037 confidentiality, as cached in ``asset.confidentiality``."""

    PUBLIC = "public"
    CLASSIFIED = "classified"
    HIGHLY_CLASSIFIED = "highly_classified"
    UNCLASSIFIED = "unclassified"


def data_sensitivity(formula: Formula, confidentiality: Confidentiality, personal_data: bool | None) -> Decimal:
    """D = confidentiality level + personal-data bonus, capped at 1.0; unknown personal data adds nothing."""
    value = formula.level("D", confidentiality.value)
    if personal_data is True:
        value += formula.personal_data_bonus
    return min(value, ONE)


# --- Base, final, ticket ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Factors:
    """The five factors of one CI: S, P, T come from the group; A, D from the CI (D-035, EVA-09)."""

    s: Decimal
    p: Decimal
    t: Decimal
    a: Decimal
    d: Decimal

    def by_name(self) -> dict[str, Decimal]:
        return {"S": self.s, "P": self.p, "T": self.t, "A": self.a, "D": self.d}


def base_unrounded(formula: Formula, factors: Factors) -> Decimal:
    values = factors.by_name()
    return HUNDRED * sum((formula.weights[f] * values[f] for f in FACTORS), ZERO)


def base_score(formula: Formula, factors: Factors, version_factor: Decimal = ONE) -> int:
    """Rounded base, 0-100. ``version_factor`` is E for alerts without a finding (1.0 confirmed, 0.6 unknown)."""
    return clamp_score(round_half_up(base_unrounded(formula, factors) * version_factor))


@dataclass(frozen=True)
class FinalScore:
    final: int
    applied_adjustment: int  # 0 inside the dead zone; recorded anyway as ``proposed_adjustment``
    proposed_adjustment: int
    clamp_effect: int  # points removed or added by clamping base + adjustment to 0-100
    floor_applied: bool
    suggestion: int | None  # the reviewed value the floor overrode (D-012); None without a judge review
    no_judge_review: bool


def floor_eligible(*, in_kev: bool, exposed: bool | None) -> bool:
    """EVA-03: the floor applies when the CVE is in KEV and this CI is exposed (unknown exposure is not)."""
    return in_kev and exposed is True


def final_score(
    formula: Formula,
    base: int,
    *,
    judge_adjustment: int | None,
    ci_adjustment: int = 0,
    floor: bool,
) -> FinalScore:
    """EVA-01..EVA-04: base + judge + CI adjustment, dead zone, clamp, KEV + exposed floor.

    ``judge_adjustment`` None means the judge was unavailable or failed validation: no adjustment at all,
    flagged ``no_judge_review`` (EVA-04, L11). Precedence (docs/02 §4, 22 nov 2026): the KEV + exposed floor
    (EVA-03) is a safety minimum independent of the judge, so it still applies under the fallback.
    ``floor`` comes from ``floor_eligible``.
    """
    no_review = judge_adjustment is None
    proposed = (judge_adjustment or 0) + (ci_adjustment if not no_review else 0)
    applied = 0 if abs(proposed) <= formula.dead_zone else proposed
    unclamped = base + applied
    value = clamp_score(unclamped)
    floor_applies = floor and value < formula.kev_exposed_floor
    suggestion = value if floor_applies and not no_review else None
    if floor_applies:
        value = formula.kev_exposed_floor
    return FinalScore(
        final=value,
        applied_adjustment=applied,
        proposed_adjustment=proposed,
        clamp_effect=clamp_score(unclamped) - unclamped,
        floor_applied=floor_applies,
        suggestion=suggestion,
        no_judge_review=no_review,
    )


class FindingStatus(StrEnum):
    NEW = "new"
    PERSISTENT = "persistent"
    REOPENED = "reopened"
    NO_DATA = "no_data"
    FIXED = "fixed"


CURRENT_STATUSES = frozenset(
    {FindingStatus.NEW, FindingStatus.PERSISTENT, FindingStatus.REOPENED, FindingStatus.NO_DATA}
)


@dataclass(frozen=True)
class CiScore:
    asset_name: str
    final: int
    status: FindingStatus
    decommissioned: bool = False


@dataclass(frozen=True)
class TicketScore:
    score: int
    driven_by: str
    urgency: int


def ticket_score(formula: Formula, cis: Iterable[CiScore]) -> TicketScore | None:
    """EVA-07/EVA-08: the highest final among current CIs (fixed and decommissioned ones do not count).

    Ties go to the first CI by name so the "driven by" text is stable. None when no CI is current.
    """
    current = [c for c in cis if c.status in CURRENT_STATUSES and not c.decommissioned]
    if not current:
        return None
    best = max(sorted(current, key=lambda c: c.asset_name), key=lambda c: c.final)
    return TicketScore(score=best.final, driven_by=best.asset_name, urgency=urgency(formula, best.final))


def urgency(formula: Formula, score: int) -> int:
    """The most urgent band (lowest number) whose minimum the score reaches (TIC-03); band 4 starts at 0."""
    return next(band for band in URGENCIES if score >= formula.urgency_bands[band])


# --- Raw vs processed (EVA-11..EVA-13) ----------------------------------------------------------------------


def raw_score(factors: Factors) -> Decimal:
    """What a CVSS-only scanner would say: 100 x S."""
    return HUNDRED * factors.s


@dataclass(frozen=True)
class DeltaBreakdown:
    """Waterfall from the raw value to the final (EVA-12); each term is one bar."""

    raw: Decimal
    terms: dict[str, Decimal]  # P, T, A, D: 100 · wX · (X - S)
    rounding: Decimal  # rounded base - unrounded base
    judge: int
    clamp: int  # effect of keeping base + adjustment inside 0-100
    floor: int

    def total(self) -> Decimal:
        """raw + every bar == final (EVA-12)."""
        return self.raw + sum(self.terms.values(), ZERO) + self.rounding + self.judge + self.clamp + self.floor


def delta_breakdown(formula: Formula, factors: Factors, result: FinalScore, base: int) -> DeltaBreakdown:
    values = factors.by_name()
    terms = {f: HUNDRED * formula.weights[f] * (values[f] - factors.s) for f in ("P", "T", "A", "D")}
    unrounded = base_unrounded(formula, factors)
    floor = result.final - clamp_score(base + result.applied_adjustment) if result.floor_applied else 0
    return DeltaBreakdown(
        raw=raw_score(factors),
        terms=terms,
        rounding=Decimal(base) - unrounded,
        judge=result.applied_adjustment,
        clamp=result.clamp_effect,
        floor=floor,
    )


def cvss_level(cvss: Decimal | None) -> str | None:
    """CVSS qualitative level by name (EVA-13): critical 9.0-10, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9."""
    if cvss is None:
        return None
    if cvss >= Decimal("9.0"):
        return "critical"
    if cvss >= Decimal("7.0"):
        return "high"
    if cvss >= Decimal("4.0"):
        return "medium"
    if cvss >= Decimal("0.1"):
        return "low"
    return "none"


def _unit(value: Decimal) -> Decimal:
    return max(ZERO, min(ONE, value))
