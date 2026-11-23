"""The judge as the pipeline uses it (docs/15 F-09, F-10): a package goes in, a stored review comes out.

* Mode 1: `judge_for` returns the staged judge the scoring step hands each finding package to (F12.2 #105): `assess`
  runs `JudgeService.evaluate` (double review, fallback) with no database access, and `record` stores the package
  (`store_package`, COR-06), the review(s) and the error queue in the caller's transaction and answers the group
  adjustment (None = no judge review, final = base) with the review id. `evaluate_group` commits its read
  transaction before `assess`, so no transaction is open while the model answers.
* Mode 2: `dismiss_story` runs `DismissalService.review` on a dismissal candidate's package.
* The environment comes from `judge_environment` with the current ladder level (L14) and the shared daily budget
  (L12, F3.1): when the ladder turned the judge off, `judge_for` returns None and the score is the base.
No LLM ever writes anything here: the services validate and store; the backend decides.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy.orm import Session

from core.correlation.packages import store_package
from core.judge.package import ReviewPackage
from core.judge.service import DismissalService, JudgeResult, JudgeService, StoredDismissalReview
from core.judge.session import JudgeEnvironment, ToolCaller
from core.judge.store import ReviewTarget, judge_environment
from core.metrics.ladder import current_level, effects
from core.scoring.evaluate import JudgeVerdict


def environment(session: Session, now: datetime) -> JudgeEnvironment | None:
    """The judge's environment today, or None when the ladder has turned the judge off (level 3)."""
    level, _ = current_level(session)
    if not effects(level).judge_enabled:
        return None
    return judge_environment(session, now.date(), ladder_level=level)


def _target(session: Session, package: dict[str, Any], now: datetime) -> tuple[ReviewPackage, ReviewTarget]:
    row = store_package(session, package, now)
    parsed = ReviewPackage.from_content(package)
    return parsed, ReviewTarget(review_package_id=row.id, input_ref=f"review_package:{row.id}", now=now)


@dataclass
class PipelineJudge:
    """Mode 1 in two steps (a `StagedJudge` of `core.scoring.evaluate`): the model, then the database."""

    service: JudgeService
    now: datetime
    spent_usd: Decimal = field(default=Decimal(0))  # reviews this judge stored after its environment was read

    def assess(self, package: dict[str, Any]) -> JudgeResult:
        """The review(s) of the package by the model; no database access (the budget was read with the
        environment, plus what this judge already stored)."""
        return self.service.evaluate(ReviewPackage.from_content(package), self.spent_usd)

    def record(self, session: Session, package: dict[str, Any], assessed: JudgeResult) -> JudgeVerdict:
        _, target = _target(session, package, self.now)
        stored = self.service.store(session, target, assessed)
        second = assessed.second.cost_usd if assessed.second is not None else Decimal(0)
        self.spent_usd += assessed.first.cost_usd + second
        return JudgeVerdict(stored.result.adjustment, stored.review_id)


def judge_for(session: Session, caller: ToolCaller, now: datetime) -> PipelineJudge | None:
    """Mode 1 with this session's environment, or None when the ladder turned the judge off."""
    env = environment(session, now)
    if env is None:
        return None
    return PipelineJudge(JudgeService(caller, env), now)


def dismiss_story(
    session: Session, caller: ToolCaller, package: dict[str, Any], now: datetime
) -> StoredDismissalReview | None:
    """Mode 2 on one dismissal candidate; None when the ladder turned the judge off."""
    env = environment(session, now)
    if env is None:
        return None
    parsed, target = _target(session, package, now)
    return DismissalService(caller, env).review(session, parsed, target)
