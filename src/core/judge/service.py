"""Judge service: one mode 1 review, the blind double review when it triggers (L10), fallback and persistence.

The result is what the scoring engine needs (EVA-01..EVA-04): the group adjustment (None means no judge review,
final = base), the per-CI adjustments of `more_critical_asset`, and the status. Dead zone, floor and the 0-100
limit are applied by the engine; hysteresis and the human-change rule after it (L9). The judge never writes iTop or
Slack (L8).
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, replace

from sqlalchemy.orm import Session

from core.judge.double_review import combine_outcomes, needs_double_review
from core.judge.package import ReviewPackage
from core.judge.session import Failure, JudgeEnvironment, JudgeSession, ReviewOutcome, ReviewStatus, ToolCaller
from core.judge.store import ReviewTarget, save_review, sync_error_queue
from core.llm import ToolDefinition


@dataclass(frozen=True)
class JudgeResult:
    status: ReviewStatus
    adjustment: int | None
    ci_adjustments: Mapping[str, int]
    first: ReviewOutcome
    second: ReviewOutcome | None = None

    @property
    def no_judge_review(self) -> bool:
        return self.adjustment is None

    @property
    def failure(self) -> Failure | None:
        """Why the result fell back to the base (None when the judge answered, even partially): the failure of
        the review that failed, the first one or, if the first answered, the blind second one."""
        if self.status is not ReviewStatus.NO_JUDGE_REVIEW:
            return None
        if self.first.adjustment is None or self.second is None:
            return self.first.failure
        return self.second.failure


@dataclass(frozen=True)
class StoredJudgeResult:
    result: JudgeResult
    review_id: uuid.UUID
    second_review_id: uuid.UUID | None
    queued: bool


class JudgeService:
    def __init__(
        self, caller: ToolCaller, env: JudgeEnvironment, tools: Mapping[str, ToolDefinition] | None = None
    ) -> None:
        self._caller = caller
        self._env = env
        self._tools = tools

    def _session(self, package: ReviewPackage) -> JudgeSession:
        """A fresh, independent conversation: the second review never sees the first one (blind)."""
        return JudgeSession(self._caller, package, self._env, self._tools)

    def evaluate(self, package: ReviewPackage) -> JudgeResult:
        first = self._session(package).run()
        if not needs_double_review(first, package, self._env.settings):
            return JudgeResult(first.status, first.adjustment, first.ci_adjustments, first)
        second = self._session(package).run()
        if second.adjustment is None:  # any failure of the second review: final = base (L11)
            return JudgeResult(ReviewStatus.NO_JUDGE_REVIEW, None, {}, first, second)
        combined = combine_outcomes(first, second, self._env.settings.double_review_max_diff)
        if not combined.agreed:
            return JudgeResult(ReviewStatus.JUDGE_DISAGREEMENT, 0, {}, first, second)
        partial = ReviewStatus.PARTIAL_REVIEW in (first.status, second.status)
        status = (
            ReviewStatus.PARTIAL_REVIEW if partial and first.status is not ReviewStatus.SUGGESTION else first.status
        )
        return JudgeResult(status, combined.adjustment, combined.ci_adjustments, first, second)

    def review(self, session: Session, package: ReviewPackage, target: ReviewTarget) -> StoredJudgeResult:
        """Evaluate and store: the first review carries the final status, the blind one links to it (A-2); the
        package is queued for a later run when the result fell back to the base (PRE-01)."""
        result = self.evaluate(package)
        first = result.first
        if result.failure is not None and first.failure is None:  # the blind review failed: record the cause
            first = replace(first, failure=result.failure)
        first_id = save_review(session, first, target, status=result.status)
        second_id: uuid.UUID | None = None
        if result.second is not None:
            second_id = save_review(session, result.second, target, second_review_of=first_id)
        queued = sync_error_queue(session, target.review_package_id, result.failure, target.now)
        return StoredJudgeResult(result, first_id, second_id, queued)
