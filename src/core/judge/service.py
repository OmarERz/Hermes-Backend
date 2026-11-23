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
from decimal import Decimal

from sqlalchemy.orm import Session

from core.db.models import ReviewPackage as ReviewPackageRow
from core.judge.budget import OffsetDailyBudget
from core.judge.double_review import combine_outcomes, needs_double_review
from core.judge.mitigation import MitigationResult
from core.judge.mode2 import Mode2Context, Mode2Result, mode2_min_confidence, review_candidate, still_holds
from core.judge.package import ReviewPackage
from core.judge.session import Failure, JudgeEnvironment, JudgeSession, ReviewOutcome, ReviewStatus, ToolCaller
from core.judge.store import (
    DbInventory,
    ReviewTarget,
    SnapshotInventory,
    refuted_relationships,
    save_alert,
    save_review,
    sync_error_queue,
)
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

    def evaluate(self, package: ReviewPackage, spent_usd: Decimal = Decimal(0)) -> JudgeResult:
        """The model's review(s) of the package; never touches the database (F12.2 #105). `spent_usd`: what earlier
        reviews of this caller cost since its environment read the day's spending (they count against the day)."""
        env = self._env
        if spent_usd:
            env = replace(env, daily_budget=OffsetDailyBudget(env.daily_budget, spent_usd))
        first = JudgeSession(self._caller, package, env, self._tools).run()  # each review: a fresh conversation
        if not needs_double_review(first, package, env.settings):
            return JudgeResult(first.status, first.adjustment, first.ci_adjustments, first)
        # blind: the second conversation never sees the first one, which is not stored yet and so counts against the
        # day through the offset (L12)
        offset = replace(env, daily_budget=OffsetDailyBudget(env.daily_budget, first.cost_usd))
        second = JudgeSession(self._caller, package, offset, self._tools).run()
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
        """`evaluate` then `store` (tools and tests). The pipeline calls the two steps itself, with no transaction
        open in between (`core.pipeline.judging`)."""
        return self.store(session, target, self.evaluate(package))

    def store(self, session: Session, target: ReviewTarget, result: JudgeResult) -> StoredJudgeResult:
        """Store an evaluation: the first review carries the final status, the blind one links to it (A-2); the
        package is queued for a later run when the result fell back to the base (PRE-01)."""
        first = result.first
        if result.status is ReviewStatus.NO_JUDGE_REVIEW and first.adjustment is not None:
            # the blind review failed: final = base, so no drafted mitigation is kept (JUE-MIT-09); record the cause
            first = replace(first, failure=result.failure, mitigation=MitigationResult.absent())
        first_id = save_review(session, first, target, status=result.status)
        second_id: uuid.UUID | None = None
        if result.second is not None:
            second_id = save_review(session, result.second, target, second_review_of=first_id)
        queued = sync_error_queue(session, target.review_package_id, result.failure, target.now)
        return StoredJudgeResult(result, first_id, second_id, queued)


@dataclass(frozen=True)
class StoredDismissalReview:
    status: ReviewStatus
    review_id: uuid.UUID
    second_review_id: uuid.UUID | None
    alert_id: uuid.UUID | None
    queued: bool


class DismissalService:
    """Mode 2 (docs/15 F-10): review a dismissal candidate, store the review(s) and the alert it validated.

    Three steps, so the pipeline keeps no transaction open while the model answers (F12.2 #105): `context` reads
    what the validation needs (inventory snapshot, refuted relationships), `evaluate` runs the model, and `store`
    re-checks what an accepted alert rests on and writes everything."""

    def __init__(
        self, caller: ToolCaller, env: JudgeEnvironment, tools: Mapping[str, ToolDefinition] | None = None
    ) -> None:
        self._caller = caller
        self._env = env
        self._tools = tools

    def review(self, session: Session, package: ReviewPackage, target: ReviewTarget) -> StoredDismissalReview:
        """The three steps in the caller's session (tools and tests)."""
        _check_candidate(session, package, target.review_package_id)
        return self.store(session, package, target, self.evaluate(package, self.context(session, package)))

    def context(self, session: Session, package: ReviewPackage) -> Mode2Context:
        """The read step: the candidate's own checks, then everything code validates the proposals against."""
        _check_candidate(session, package, None)
        return Mode2Context(
            mode2_min_confidence(self._env), SnapshotInventory.load(session), refuted_relationships(session)
        )

    def _live(self, session: Session) -> Mode2Context:
        """The inventory and refutations as they are now, in the write transaction."""
        return Mode2Context(mode2_min_confidence(self._env), DbInventory(session), refuted_relationships(session))

    def evaluate(self, package: ReviewPackage, context: Mode2Context) -> Mode2Result:
        """The model's review(s) of the candidate; no database access."""
        return review_candidate(self._caller, package, self._env, context, self._tools)

    def store(
        self, session: Session, package: ReviewPackage, target: ReviewTarget, result: Mode2Result
    ) -> StoredDismissalReview:
        """The write step: an alert whose inventory facts changed meanwhile is not raised (`Failure.STALE`, queued
        for a retry); the reviews are stored either way (their tokens were paid)."""
        _check_candidate(session, package, target.review_package_id)
        stale = result.alert is not None and not still_holds(result.alert, self._live(session))
        if stale:
            result = Mode2Result(
                ReviewStatus.NO_JUDGE_REVIEW, replace(result.first, failure=Failure.STALE), result.second
            )
        first = result.first
        if result.status is not first.status:  # the blind review disagreed or failed: nothing is raised
            failure = result.second.failure if result.second is not None else None
            first = replace(first, alert=None, failure=first.failure or failure)
        review_id = save_review(session, first, target, status=result.status)
        second_id = None
        if result.second is not None:
            second_id = save_review(session, result.second, target, second_review_of=review_id)
        alert_id = save_alert(session, result.alert, review_id, target.now) if result.alert is not None else None
        undecided = result.status in (ReviewStatus.NO_JUDGE_REVIEW, ReviewStatus.PARTIAL_REVIEW)
        failure = Failure.STALE if stale else ((result.second or result.first).failure if undecided else None)
        # no decision (provider failure, budget or limits): the candidate is retried later (PRE-01)
        queued = sync_error_queue(session, target.review_package_id, failure, target.now)
        return StoredDismissalReview(result.status, review_id, second_id, alert_id, queued)


def _check_candidate(session: Session, package: ReviewPackage, review_package_id: uuid.UUID | None) -> None:
    """Before asking the judge (F-10): the candidate has exactly one news item, its story is a UUID, and the stored
    package row (when given) is that story's dismissal package with this very content (L13: the audit points at
    exactly what the judge read)."""
    news = [element.news for element in package.news_elements if element.news is not None]
    if len(news) != 1:
        raise ValueError("a dismissal candidate carries exactly one news item")
    try:
        story_id = uuid.UUID(news[0].story_id)
    except ValueError:
        raise ValueError("the news item of a dismissal candidate needs its story UUID") from None
    if review_package_id is not None:
        stored = session.get(ReviewPackageRow, review_package_id)
        same = stored is not None and stored.kind == "dismissal" and stored.story_id == story_id
        if not same or stored is None or ReviewPackage.from_content(stored.content).content != package.content:
            raise ValueError("the stored package is not this dismissal candidate")
