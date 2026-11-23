"""The judge's daily budget across the reviews of one evaluation (L12, F12.2 #105).

The day's spending is read once, with the environment; what the same caller stored after that must still count
against the day: `JudgeService.evaluate(package, spent_usd)` adds it, and the pipeline's staged judge passes it.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

import pytest

from core.judge.budget import FREE, LedgerDailyBudget
from core.judge.catalog import JudgeSettings, ReasonCatalog, SensitivityProfile
from core.judge.package import ReviewPackage
from core.judge.service import JudgeService
from core.judge.session import Failure, JudgeEnvironment, ReviewStatus
from core.pipeline.judging import PipelineJudge
from core.validation.budget import BudgetConfig, limit_usd
from doubles.llm import LlmDouble, tool_call_completion
from harness.judge import double_llm_client, finding_package

pytestmark = pytest.mark.unit
TURN = Decimal("0.015")
CONFIG = BudgetConfig()


def service(package: ReviewPackage) -> tuple[JudgeService, LlmDouble]:
    """A day that has room for one more turn and not a cent more (read once, as `load_daily_budget` does)."""
    spent = limit_usd(CONFIG, package.is_critical) - TURN
    double = LlmDouble()
    double.add_case("case", [tool_call_completion("finalize_review", {"summary": "Uno.", "mitigation_steps": []})])
    double.use("case")
    env = JudgeEnvironment(
        catalog=ReasonCatalog.default(),
        profile=SensitivityProfile.named("normal"),
        settings=JudgeSettings(),
        today=date(2026, 11, 22),
        daily_budget=LedgerDailyBudget(lambda: spent, CONFIG, TURN),
        price=FREE,
    )
    return JudgeService(double_llm_client(double), env), double


def package() -> ReviewPackage:
    content: dict[str, Any] = finding_package()
    return ReviewPackage.from_content(content)


def test_evaluate_counts_what_the_caller_already_spent_against_the_day() -> None:
    judge, double = service(package())
    assert judge.evaluate(package()).status is ReviewStatus.APPLIED  # the last turn of the day fits
    judge, double = service(package())
    result = judge.evaluate(package(), spent_usd=Decimal("0.01"))  # an earlier review of this caller, stored
    assert (result.status, result.failure) == (ReviewStatus.NO_JUDGE_REVIEW, Failure.BUDGET)
    double.assert_calls(0)


def test_the_pipeline_judge_passes_what_it_already_stored() -> None:
    judge, double = service(package())
    staged = PipelineJudge(judge, datetime(2026, 11, 22, 12, 0, tzinfo=UTC), spent_usd=Decimal("0.01"))
    result = staged.assess(finding_package())
    assert (result.status, result.failure) == (ReviewStatus.NO_JUDGE_REVIEW, Failure.BUDGET)
    double.assert_calls(0)
