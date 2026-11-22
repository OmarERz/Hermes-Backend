"""docs/06 §8 mandatory cases (EVA-10): they must pass exactly, with Decimal and ROUND_HALF_UP."""

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
    ThreatEvidence,
    asset_level,
    base_score,
    base_unrounded,
    data_sensitivity,
    default_formula,
    delta_breakdown,
    exploitation_level,
    final_score,
    floor_eligible,
    severity,
    threat,
    ticket_score,
)

F = default_formula()
D = Decimal


def factors(s: str, p: str, t: str, a: str, d: str) -> Factors:
    return Factors(D(s), D(p), D(t), D(a), D(d))


# CVSS 7.0, critical internal (A 0.8), Classified without personal data (D 0.5), default weights, no judge.
@pytest.mark.parametrize(
    ("case", "p", "t", "unrounded", "expected"),
    [
        ("day 0, no news, low EPSS", "0.2", "0", "40.5", 41),
        ("day 2, PoC published", "0.75", "0.4", "65.0", 65),
        ("day 4, exploited against a peer + KEV", "1.0", "1.0", "84.5", 85),
        ("day 40, no new news (T decays x0.3)", "1.0", "0.3", "70.5", 71),
    ],
)
def test_timeline_cases(case: str, p: str, t: str, unrounded: str, expected: int) -> None:
    f = factors("0.70", p, t, "0.8", "0.5")
    assert base_unrounded(F, f) == D(unrounded), case
    assert base_score(F, f) == expected, case


def test_factor_functions_produce_the_case_inputs() -> None:
    s, _ = severity(F, D("7.0"))
    assert s == D("0.70")
    assert F.level("A", asset_level(Criticality.HIGH, exposed=False)) == D("0.8")
    assert data_sensitivity(F, Confidentiality.CLASSIFIED, personal_data=False) == D("0.5")
    p_level = exploitation_level(in_kev=False, grade=ExploitationGrade.NONE, public_poc=False, epss_percentile=D("0.3"))
    assert F.level("P", p_level) == D("0.2")
    p_level = exploitation_level(in_kev=False, grade=ExploitationGrade.NONE, public_poc=True, epss_percentile=None)
    assert F.level("P", p_level) == D("0.75")
    p_level = exploitation_level(in_kev=True, grade=ExploitationGrade.NONE, public_poc=False, epss_percentile=None)
    assert F.level("P", p_level) == D("1.0")
    assert threat(F, []) == D("0")
    assert threat(F, [ThreatEvidence("trend_2_to_3_sources", age_days=1)]) == D("0.4")
    assert threat(F, [ThreatEvidence("peer_exploited_with_vector", age_days=3)]) == D("1.0")
    assert threat(F, [ThreatEvidence("peer_exploited_with_vector", age_days=40)]) == D("0.3")


# CVSS 9.8, in KEV, T 0.5, same custodian for the three CIs.
PER_CI = [
    ("web-prod", Criticality.HIGH, True, Confidentiality.HIGHLY_CLASSIFIED, True, D("1.0"), D("1.0"), 90),
    ("staging", Criticality.MEDIUM, False, Confidentiality.PUBLIC, False, D("0.5"), D("0.1"), 73),
    ("dev", Criticality.LOW, False, Confidentiality.PUBLIC, False, D("0.3"), D("0.1"), 70),
]


@pytest.mark.parametrize("row", PER_CI, ids=[r[0] for r in PER_CI])
def test_per_ci_scores(row: tuple[str, Criticality, bool, Confidentiality, bool, Decimal, Decimal, int]) -> None:
    name, crit, exposed, conf, personal, a, d, expected = row
    assert F.level("A", asset_level(crit, exposed)) == a
    assert data_sensitivity(F, conf, personal) == d
    f = Factors(D("0.98"), D("1.0"), D("0.5"), a, d)
    base = base_score(F, f)
    result = final_score(F, base, judge_adjustment=0, floor=floor_eligible(in_kev=True, exposed=exposed))
    assert result.final == expected, name


def test_ticket_takes_the_highest_ci() -> None:
    cis = [CiScore(name, expected, FindingStatus.PERSISTENT) for name, *_, expected in PER_CI]
    ticket = ticket_score(F, cis)
    assert ticket is not None
    assert (ticket.score, ticket.driven_by, ticket.urgency) == (90, "web-prod", 1)


def test_cis_are_never_mixed() -> None:
    """CVSS 9.8, PoC P 0.75, T 0.5: the ticket is 73, never 82 (A of CI-1 with D of CI-2, EVA-09)."""
    ci1 = base_score(F, factors("0.98", "0.75", "0.5", "1.0", "0.1"))
    ci2 = base_score(F, factors("0.98", "0.75", "0.5", "0.3", "1.0"))
    assert (ci1, ci2) == (73, 72)
    assert base_unrounded(F, factors("0.98", "0.75", "0.5", "0.3", "1.0")) == D("71.5")
    ticket = ticket_score(F, [CiScore("CI-1", ci1, FindingStatus.NEW), CiScore("CI-2", ci2, FindingStatus.NEW)])
    assert ticket is not None
    assert ticket.score == 73
    assert base_score(F, factors("0.98", "0.75", "0.5", "1.0", "1.0")) == 82  # the forbidden mix


@pytest.mark.parametrize(
    ("conf", "personal", "expected"),
    [
        (Confidentiality.CLASSIFIED, False, 77),
        (Confidentiality.HIGHLY_CLASSIFIED, True, 82),
    ],
)
def test_d_distinguishes_what_a_cannot(conf: Confidentiality, personal: bool, expected: int) -> None:
    d = data_sensitivity(F, conf, personal)
    base = base_score(F, Factors(D("0.98"), D("0.75"), D("0.5"), D("1.0"), d))
    assert final_score(F, base, judge_adjustment=0, floor=False).final == expected


def test_delta_breakdown_of_day_4() -> None:
    f = factors("0.70", "1.0", "1.0", "0.8", "0.5")
    base = base_score(F, f)
    result = final_score(F, base, judge_adjustment=None, floor=False)
    breakdown = delta_breakdown(F, f, result, base)
    assert breakdown.raw == D("70.00")
    assert breakdown.terms == {"P": D("9.000"), "T": D("6.000"), "A": D("1.500"), "D": D("-2.000")}
    assert sum(breakdown.terms.values()) == D("14.5")
    assert (base, breakdown.rounding) == (85, D("0.5"))
    assert result.no_judge_review is True


def test_floor_records_the_judge_suggestion() -> None:
    result = final_score(F, 70, judge_adjustment=-15, floor=floor_eligible(in_kev=True, exposed=True))
    assert (result.final, result.floor_applied, result.suggestion) == (90, True, 55)


@pytest.mark.parametrize(("judge", "expected", "applied"), [(4, 74, 0), (5, 79, 5), (-4, 74, 0), (-5, 69, -5)])
def test_dead_zone(judge: int, expected: int, applied: int) -> None:
    result = final_score(F, 74, judge_adjustment=judge, floor=False)
    assert (result.final, result.applied_adjustment, result.proposed_adjustment) == (expected, applied, judge)


def test_weights_must_sum_to_one() -> None:
    weights = dict(F.weights) | {"S": D("0.30")}
    with pytest.raises(FormulaError, match=r"sum to 1\.0"):
        type(F)(weights=weights, levels=F.levels)


def test_levels_must_be_monotonic() -> None:
    levels = {k: dict(v) for k, v in F.levels.items()}
    levels["P"] = {"kev_or_exploited": D("0.8"), "public_poc": D("0.9"), "epss_p90": D("0.5"), "other": D("0.2")}
    with pytest.raises(FormulaError, match="monotonic"):
        type(F)(weights=F.weights, levels=levels)


def test_fixed_driver_hands_the_ticket_to_the_next_ci() -> None:
    cis = [CiScore("web-prod", 90, FindingStatus.FIXED), CiScore("staging", 73, FindingStatus.PERSISTENT)]
    ticket = ticket_score(F, cis)
    assert ticket is not None
    assert (ticket.score, ticket.driven_by) == (73, "staging")
