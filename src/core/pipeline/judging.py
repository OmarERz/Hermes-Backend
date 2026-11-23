"""The judge as the pipeline uses it (docs/15 F-09, F-10): a package goes in, a stored review comes out.

* Mode 1: `judge_for` returns the callable the scoring step hands each finding package to. It stores the package
  (`store_package`, COR-06), runs `JudgeService.review` (double review, fallback, error queue) and answers the
  group adjustment (None = no judge review, final = base) with the review id.
* Mode 2: `dismiss_story` runs `DismissalService.review` on a dismissal candidate's package.
* The environment comes from `judge_environment` with the current ladder level (L14) and the shared daily budget
  (L12, F3.1): when the ladder turned the judge off, `judge_for` returns None and the score is the base.
No LLM ever writes anything here: the services validate and store; the backend decides.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from core.correlation.packages import store_package
from core.judge.package import ReviewPackage
from core.judge.service import DismissalService, JudgeService, StoredDismissalReview
from core.judge.session import JudgeEnvironment, ToolCaller
from core.judge.store import ReviewTarget, judge_environment
from core.metrics.ladder import current_level, effects


@dataclass(frozen=True)
class Verdict:
    """What the scoring step needs from a review: the group adjustment (None = base only) and the review row."""

    adjustment: int | None
    llm_review_id: uuid.UUID | None


JudgeFn = Callable[[dict[str, Any]], Verdict]


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


def judge_for(session: Session, caller: ToolCaller, now: datetime) -> JudgeFn | None:
    """Mode 1 for this session, or None when the ladder turned the judge off."""
    env = environment(session, now)
    if env is None:
        return None
    service = JudgeService(caller, env)

    def judge(package: dict[str, Any]) -> Verdict:
        parsed, target = _target(session, package, now)
        stored = service.review(session, parsed, target)
        return Verdict(stored.result.adjustment, stored.review_id)

    return judge


def dismiss_story(
    session: Session, caller: ToolCaller, package: dict[str, Any], now: datetime
) -> StoredDismissalReview | None:
    """Mode 2 on one dismissal candidate; None when the ladder turned the judge off."""
    env = environment(session, now)
    if env is None:
        return None
    parsed, target = _target(session, package, now)
    return DismissalService(caller, env).review(session, parsed, target)
