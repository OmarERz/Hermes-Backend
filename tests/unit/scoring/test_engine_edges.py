"""Edge behaviour of the scoring engine beyond the docs/06 §8 table."""

from __future__ import annotations

from decimal import Decimal

import pytest

from core.scoring.engine import (
    CiScore,
    Confidentiality,
    Criticality,
    ExploitationGrade,
    Factors,
    FindingStatus,
    FormulaError,
    SeverityOrigin,
    ThreatEvidence,
    asset_level,
    base_score,
    cvss_level,
    data_sensitivity,
    decay_multiplier,
    default_formula,
    delta_breakdown,
    exploitation_level,
    final_score,
    floor_eligible,
    severity,
    threat,
    ticket_score,
    trend_level,
    urgency,
)

F = default_formula()
D = Decimal


def test_severity_origins() -> None:
    assert severity(F, D("9.8")) == (D("0.98"), SeverityOrigin.CVSS)
    assert severity(F, None, D("6.5")) == (D("0.65"), SeverityOrigin.ESTIMATED)
    assert severity(F, None, None) == (D("0.8"), SeverityOrigin.UNRATED)


@pytest.mark.parametrize(
    ("in_kev", "grade", "poc", "epss", "level"),
    [
        (False, ExploitationGrade.MASS, False, None, "kev_or_exploited"),
        (False, ExploitationGrade.ATTEMPTED, False, None, "public_poc"),
        (False, ExploitationGrade.NONE, False, D("0.90"), "epss_p90"),
        (False, ExploitationGrade.DENIED, False, D("0.89"), "other"),
        (True, ExploitationGrade.DENIED, False, None, "kev_or_exploited"),
    ],
)
def test_exploitation_levels(
    in_kev: bool, grade: ExploitationGrade, poc: bool, epss: Decimal | None, level: str
) -> None:
    assert exploitation_level(in_kev=in_kev, grade=grade, public_poc=poc, epss_percentile=epss) == level


@pytest.mark.parametrize(
    ("count", "level"), [(0, None), (1, "trend_1_source"), (3, "trend_2_to_3_sources"), (4, "trend_4_or_more_sources")]
)
def test_trend_levels(count: int, level: str | None) -> None:
    assert trend_level(count) == level


@pytest.mark.parametrize(
    ("age", "multiplier"), [(0, "1.0"), (7, "1.0"), (8, "0.6"), (30, "0.6"), (31, "0.3"), (400, "0.3")]
)
def test_decay(age: int, multiplier: str) -> None:
    assert decay_multiplier(F, age) == D(multiplier)


@pytest.mark.parametrize(
    ("crit", "exposed", "level"),
    [
        (Criticality.UNKNOWN, None, "normal_internal_or_unknown"),
        (Criticality.UNKNOWN, True, "normal_internal_or_unknown"),
        (Criticality.MEDIUM, True, "critical_internal_or_normal_exposed"),
        (Criticality.HIGH, None, "critical_internal_or_normal_exposed"),
        (Criticality.LOW, True, "low"),
    ],
)
def test_asset_levels(crit: Criticality, exposed: bool | None, level: str) -> None:
    assert asset_level(crit, exposed) == level


@pytest.mark.parametrize(
    ("conf", "personal", "value"),
    [
        (Confidentiality.PUBLIC, True, "0.3"),
        (Confidentiality.CLASSIFIED, True, "0.7"),
        (Confidentiality.UNCLASSIFIED, None, "0.5"),
        (Confidentiality.HIGHLY_CLASSIFIED, True, "1.0"),
    ],
)
def test_data_sensitivity_examples(conf: Confidentiality, personal: bool | None, value: str) -> None:
    assert data_sensitivity(F, conf, personal) == D(value)


def test_alert_version_factor() -> None:
    f = Factors(D("0.98"), D("1.0"), D("0.5"), D("1.0"), D("1.0"))
    assert base_score(F, f, version_factor=D("0.6")) == 54  # 89.5 x 0.6 = 53.7 -> 54


def test_final_is_clamped_and_unknown_exposure_has_no_floor() -> None:
    assert final_score(F, 95, judge_adjustment=20, floor=False).final == 100
    assert final_score(F, 3, judge_adjustment=-10, floor=False).final == 0
    assert floor_eligible(in_kev=True, exposed=None) is False
    assert floor_eligible(in_kev=False, exposed=True) is False


def test_floor_keeps_the_reviewed_value_as_suggestion() -> None:
    """A valid review proposing 0 still leaves 70 as the blocked suggestion (EVA-03, asset_score_detail)."""
    result = final_score(F, 70, judge_adjustment=0, floor=True)
    assert (result.final, result.suggestion, result.no_judge_review) == (90, 70, False)


def test_fallback_keeps_the_floor_and_records_no_suggestion() -> None:
    """Precedence (docs/02 §4): without a judge there is no adjustment, but the KEV + exposed floor holds."""
    result = final_score(F, 70, judge_adjustment=None, floor=True)
    assert (result.final, result.applied_adjustment, result.suggestion, result.no_judge_review) == (90, 0, None, True)
    assert final_score(F, 70, judge_adjustment=None, floor=False).final == 70


def test_no_judge_ignores_ci_adjustment() -> None:
    result = final_score(F, 60, judge_adjustment=None, ci_adjustment=10, floor=False)
    assert (result.final, result.no_judge_review, result.proposed_adjustment) == (60, True, 0)


def test_ci_adjustment_adds_to_the_judge() -> None:
    result = final_score(F, 60, judge_adjustment=3, ci_adjustment=4, floor=False)
    assert (result.final, result.applied_adjustment) == (67, 7)


def test_floor_bar_in_the_breakdown() -> None:
    f = Factors(D("0.70"), D("1.0"), D("0.0"), D("1.0"), D("0.1"))
    base = base_score(F, f)
    result = final_score(F, base, judge_adjustment=-10, floor=True)
    breakdown = delta_breakdown(F, f, result, base)
    assert breakdown.judge == -10
    assert breakdown.floor == 90 - (base - 10)


def test_ticket_edges() -> None:
    assert ticket_score(F, []) is None
    assert ticket_score(F, [CiScore("a", 80, FindingStatus.FIXED)]) is None
    gone = CiScore("b", 99, FindingStatus.PERSISTENT, decommissioned=True)
    kept = CiScore("c", 40, FindingStatus.NO_DATA)
    ticket = ticket_score(F, [gone, kept])
    assert ticket is not None
    assert (ticket.score, ticket.driven_by, ticket.urgency) == (40, "c", 4)
    tie = ticket_score(F, [CiScore("zeta", 77, FindingStatus.NEW), CiScore("alfa", 77, FindingStatus.NEW)])
    assert tie is not None
    assert tie.driven_by == "alfa"


@pytest.mark.parametrize(("score", "band"), [(100, 1), (90, 1), (89, 2), (75, 2), (74, 3), (50, 3), (49, 4), (0, 4)])
def test_urgency_bands(score: int, band: int) -> None:
    assert urgency(F, score) == band


def test_threat_takes_the_strongest_signal_after_decay() -> None:
    """A 1.0 signal from 40 days ago (x0.3 = 0.3) loses to a fresh 0.5 one, in either order (D-013)."""
    old = ThreatEvidence("peer_exploited_with_vector", age_days=40)
    fresh = ThreatEvidence("sector_region", age_days=1)
    assert threat(F, [old, fresh]) == D("0.5")
    assert threat(F, [fresh, old]) == D("0.5")


def test_threat_without_news_uses_the_configured_level() -> None:
    levels = {k: dict(v) for k, v in F.levels.items()}
    levels["T"] = dict(levels["T"]) | {"no_news": D("0.1")}
    formula = type(F)(weights=F.weights, levels=levels)
    assert threat(formula, []) == D("0.1")
    assert threat(F, []) == D("0")


@pytest.mark.parametrize(
    ("cvss", "level"),
    [
        (None, None),
        (D("10.0"), "critical"),
        (D("9.0"), "critical"),
        (D("8.9"), "high"),
        (D("7.0"), "high"),
        (D("6.9"), "medium"),
        (D("4.0"), "medium"),
        (D("3.9"), "low"),
        (D("0.1"), "low"),
        (D("0.0"), "none"),
    ],
)
def test_cvss_levels(cvss: Decimal | None, level: str | None) -> None:
    assert cvss_level(cvss) == level


def test_formula_rejects_missing_factor_and_out_of_range_levels() -> None:
    with pytest.raises(FormulaError, match="exactly"):
        type(F)(weights={"S": D("0.5"), "P": D("0.5")}, levels=F.levels)
    levels = {k: dict(v) for k, v in F.levels.items()}
    levels["A"] = dict(levels["A"]) | {"critical_exposed": D("1.2")}
    with pytest.raises(FormulaError, match="between 0 and 1"):
        type(F)(weights=F.weights, levels=levels)
    with pytest.raises(FormulaError, match="unknown level"):
        F.level("P", "nope")


@pytest.mark.parametrize(("base", "judge", "floor"), [(95, 20, False), (3, -10, False), (5, -20, True), (88, 10, True)])
def test_breakdown_always_adds_up_to_the_final(base: int, judge: int, floor: bool) -> None:
    f = Factors(D("0.70"), D("1.0"), D("0.0"), D("1.0"), D("0.1"))
    result = final_score(F, base, judge_adjustment=judge, floor=floor)
    # Use the real base of these factors for the rounding bar, then the given base for the rest of the chain.
    breakdown = delta_breakdown(F, f, result, base)
    assert breakdown.total() == D(result.final)
