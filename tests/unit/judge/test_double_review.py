"""Blind double review (L10, docs/07 §6, §11): triggers, code comparison and fallback, with the LLM double."""

from __future__ import annotations

from dataclasses import replace
from datetime import date
from typing import Any

import pytest

from core.judge.budget import FREE, UnlimitedDailyBudget
from core.judge.catalog import JudgeSettings, ReasonCatalog, SensitivityProfile
from core.judge.double_review import combine, combine_outcomes, needs_double_review
from core.judge.package import ReviewPackage
from core.judge.service import JudgeService
from core.judge.session import Failure, JudgeEnvironment, JudgeSession, ReviewOutcome, ReviewStatus
from doubles.llm import LlmDouble, tool_call_completion
from harness.judge import double_llm_client, finding_package

pytestmark = pytest.mark.unit

MASS = {
    "reason_code": "mass_exploitation",
    "direction": "up",
    "points": 18,
    "evidence_id": "news-1",
    "quote": "Researchers observed mass exploitation of CVE-2026-1111",
    "explanation": "Explotación masiva reciente.",
}
AUTH = {
    "reason_code": "requires_authentication",
    "direction": "down",
    "points": -5,
    "evidence_id": "cve-1",
    "quote": "Successful exploitation requires the mod_proxy module",
    "explanation": "Requiere un módulo opcional.",
}
CRITICAL_ASSET = {
    "reason_code": "more_critical_asset",
    "direction": "up",
    "points": 8,
    "evidence_id": "ci-2",
    "quote": "Este servidor procesa los pagos con tarjeta",
    "explanation": "El texto de iTop muestra que procesa pagos.",
}


def env(**overrides: Any) -> JudgeEnvironment:
    values: dict[str, Any] = {
        "catalog": ReasonCatalog.default(),
        "profile": SensitivityProfile.named("normal"),
        "settings": JudgeSettings(),
        "today": date(2026, 11, 22),
        "daily_budget": UnlimitedDailyBudget(),
        "price": FREE,
    }
    values.update(overrides)
    return JudgeEnvironment(**values)


def propose(args: dict[str, Any], call_id: str = "p") -> dict[str, Any]:
    return tool_call_completion("propose_reason", args, call_id=call_id)


def finalize() -> dict[str, Any]:
    return tool_call_completion("finalize_review", {"summary": "Resumen.", "mitigation_steps": []}, call_id="f")


def double_with(responses: list[dict[str, Any]]) -> LlmDouble:
    double = LlmDouble()
    double.add_case("case", responses)
    double.use("case")
    return double


def package(content: dict[str, Any] | None = None) -> ReviewPackage:
    return ReviewPackage.from_content(content or finding_package())


def base_outcome() -> ReviewOutcome:
    return JudgeSession(double_llm_client(double_with([finalize()])), package(), env()).run()


# --- combine ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [
        (18, 14, 16),
        (12, 13, 13),  # 12.5 rounds half up
        (-18, -12, -12),  # lowering keeps the smaller magnitude
        (-12, -18, -12),
        (18, -5, None),
        (10, 22, None),
        (0, 0, 0),
        (0, 5, None),
        (7, 7, 7),
    ],
)
def test_combine_follows_docs_07_section_6(first: int, second: int, expected: int | None) -> None:
    assert combine(first, second, 10) == expected


def test_combine_outcomes_compares_group_and_ci_adjustments() -> None:
    outcome = base_outcome()
    a = replace(outcome, adjustment=18, ci_adjustments={"CI-2": 8})
    b = replace(outcome, adjustment=14, ci_adjustments={"CI-2": 6})
    agreed = combine_outcomes(a, b, 10)
    assert (agreed.agreed, agreed.adjustment, agreed.ci_adjustments) == (True, 16, {"CI-2": 7})
    only_first = combine_outcomes(a, replace(b, ci_adjustments={}), 10)
    assert not only_first.agreed  # CI-2: +8 against 0
    assert (only_first.adjustment, only_first.ci_adjustments) == (0, {})
    zero_ci = combine_outcomes(replace(a, ci_adjustments={"CI-1": 0}), replace(b, ci_adjustments={}), 10)
    assert zero_ci.agreed
    assert zero_ci.ci_adjustments == {}
    group_disagrees = combine_outcomes(a, replace(b, adjustment=-5, ci_adjustments={"CI-2": 8}), 10)
    assert not group_disagrees.agreed


# --- triggers --------------------------------------------------------------------------------------------------
def test_triggers() -> None:
    outcome = base_outcome()
    pkg = package()
    settings = JudgeSettings()
    assert not needs_double_review(outcome, pkg, settings)
    assert needs_double_review(replace(outcome, adjustment=15), pkg, settings)
    assert needs_double_review(replace(outcome, adjustment=-15), pkg, settings)
    assert not needs_double_review(replace(outcome, adjustment=14), pkg, settings)
    assert needs_double_review(replace(outcome, adjustment=8, ci_adjustments={"CI-2": 8}), pkg, settings)
    assert needs_double_review(replace(outcome, out_of_range=True), pkg, settings)
    assert needs_double_review(replace(outcome, cites_suspicious=True), pkg, settings)
    assert not needs_double_review(
        replace(outcome, adjustment=None, status=ReviewStatus.NO_JUDGE_REVIEW), pkg, settings
    )
    assert needs_double_review(replace(outcome, adjustment=10, ladder_level=1), pkg, settings)  # watched: 10
    assert needs_double_review(replace(outcome, adjustment=12), pkg, JudgeSettings(double_review_threshold=12))


def test_crossing_critical_triggers() -> None:
    content = finding_package()
    content["group"]["cis"][1]["base"]["score"] = 86
    outcome = replace(base_outcome(), adjustment=5)
    assert needs_double_review(outcome, package(content), JudgeSettings())  # 86 -> 91
    content["group"]["cis"][1]["base"]["score"] = 93
    assert needs_double_review(replace(outcome, adjustment=-5), package(content), JudgeSettings())  # 93 -> 88
    content["group"]["cis"][1]["base"]["score"] = 99
    assert not needs_double_review(outcome, package(content), JudgeSettings())  # stays Critical (clamped 100)


# --- service ---------------------------------------------------------------------------------------------------
def test_plus_18_then_minus_5_applies_only_the_base() -> None:
    """docs/07 §11: +18 triggers the double review; with -5 in the second one only the base applies."""
    double = double_with([propose(MASS), finalize(), propose(AUTH), finalize()])
    result = JudgeService(double_llm_client(double), env()).evaluate(package())
    assert result.status is ReviewStatus.JUDGE_DISAGREEMENT
    assert result.adjustment == 0
    assert result.ci_adjustments == {}
    assert not result.no_judge_review
    assert result.second is not None
    assert result.second.adjustment == -5
    double.assert_calls(4)
    blind = double.requests[2].body["messages"]
    assert [m["role"] for m in blind] == ["system", "user"]  # the second review never sees the first


def test_a_ci_reason_in_only_one_review_is_a_disagreement() -> None:
    second = {**MASS, "points": 14}
    responses = [propose(MASS), propose(CRITICAL_ASSET, "c"), finalize(), propose(second), finalize()]
    double = double_with(responses)
    result = JudgeService(double_llm_client(double), env()).evaluate(package())
    assert result.status is ReviewStatus.JUDGE_DISAGREEMENT  # CI-2: +8 against no adjustment
    assert result.adjustment == 0
    double.assert_calls(5)


def test_agreeing_reviews_average_when_raising() -> None:
    responses = [propose(MASS), finalize(), propose({**MASS, "points": 14}), finalize()]
    result = JudgeService(double_llm_client(double_with(responses)), env()).evaluate(package())
    assert result.status is ReviewStatus.APPLIED
    assert (result.adjustment, result.ci_adjustments) == (16, {})


def test_agreeing_reviews_with_the_same_ci_reason() -> None:
    second = {**MASS, "points": 14}
    responses = [
        propose(MASS),
        propose(CRITICAL_ASSET, "c"),
        finalize(),
        propose(second),
        propose({**CRITICAL_ASSET, "points": 6}, "d"),
        finalize(),
    ]
    result = JudgeService(double_llm_client(double_with(responses)), env()).evaluate(package())
    assert result.status is ReviewStatus.APPLIED
    assert (result.adjustment, result.ci_adjustments) == (16, {"CI-2": 7})


def test_no_double_review_below_the_threshold() -> None:
    double = double_with([propose({**MASS, "points": 10}), finalize()])
    result = JudgeService(double_llm_client(double), env()).evaluate(package())
    assert result.status is ReviewStatus.APPLIED
    assert result.adjustment == 10
    assert result.second is None
    double.assert_calls(2)


def test_second_review_failure_falls_back_to_base() -> None:
    double = double_with([propose(MASS), finalize()])  # nothing left for the second review: API error
    result = JudgeService(double_llm_client(double), env()).evaluate(package())
    assert result.status is ReviewStatus.NO_JUDGE_REVIEW
    assert result.adjustment is None
    assert result.no_judge_review


def test_partial_second_review_marks_the_result_partial() -> None:
    bad = {**MASS, "quote": "not in the element at all"}
    responses = [propose(MASS), finalize(), propose({**MASS, "points": 16}), propose(bad, "x"), propose(bad, "y")]
    responses.append(propose(bad, "z"))
    result = JudgeService(double_llm_client(double_with(responses)), env()).evaluate(package())
    assert result.second is not None
    assert result.second.status is ReviewStatus.PARTIAL_REVIEW
    assert result.status is ReviewStatus.PARTIAL_REVIEW
    assert result.adjustment == 17


def test_suggestion_level_is_kept_after_agreement() -> None:
    responses = [propose(MASS), finalize(), propose({**MASS, "points": 16}), finalize()]
    result = JudgeService(double_llm_client(double_with(responses)), env(ladder_level=2)).evaluate(package())
    assert result.status is ReviewStatus.SUGGESTION
    assert result.adjustment == 17


def test_failure_reasons_of_the_result() -> None:
    down = JudgeService(double_llm_client(double_with([])), env()).evaluate(package())
    assert (down.status, down.failure, down.second) == (ReviewStatus.NO_JUDGE_REVIEW, Failure.TRANSPORT, None)
    fine = JudgeService(double_llm_client(double_with([finalize()])), env()).evaluate(package())
    assert fine.failure is None


def test_a_partial_first_review_then_a_failed_second_one_reports_the_second_failure() -> None:
    bad = {**MASS, "quote": "not in the element at all"}
    responses = [propose(MASS), propose(bad, "x"), propose(bad, "y"), propose(bad, "z")]  # partial, +18
    result = JudgeService(double_llm_client(double_with(responses)), env()).evaluate(package())
    assert result.first.status is ReviewStatus.PARTIAL_REVIEW
    assert result.status is ReviewStatus.NO_JUDGE_REVIEW
    assert result.failure is Failure.TRANSPORT


def test_a_partial_review_that_applies_has_no_fallback_failure() -> None:
    bad = {**MASS, "quote": "not in the element at all"}
    responses = [propose({**MASS, "points": 10}), propose(bad, "x"), propose(bad, "y"), propose(bad, "z")]
    result = JudgeService(double_llm_client(double_with(responses)), env()).evaluate(package())
    assert result.status is ReviewStatus.PARTIAL_REVIEW
    assert result.first.failure is Failure.LIMIT
    assert result.failure is None
