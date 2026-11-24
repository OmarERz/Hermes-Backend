"""Judge detail of a recommendation (D-088, FRO-13, RE-3, RE-5, RE-6): the review an assessment used, its reasons and
its blind second review.

Reasons are the judge's proposals as code validated them (`judge_reason`): accepted ones carry the points applied
with the sensitivity profile of that moment, rejected ones the points proposed and the rule that refused them. A
quote is text taken from the evidence (news, CVE, CI): the front shows it as data, escaped (SEG-02). The raw calls,
the package and the prompt never leave the database (X-2).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from sqlalchemy import text
from sqlalchemy.orm import Session

COMPARED: Final = frozenset({"applied", "suggestion", "partial_review", "judge_disagreement"})
_ASSESSMENT: Final = text("SELECT id, llm_review_id, judge_adjustment FROM assessment WHERE id = :id")
_REVIEW: Final = text(
    """
    SELECT id, status, summary, model, created_at, proposed_adjustment, mitigation_status, second_review_of_id
      FROM llm_review WHERE id = :id
    """
)
_SECOND: Final = text(
    """
    SELECT id, status, proposed_adjustment FROM llm_review WHERE second_review_of_id = :id
     ORDER BY created_at, id LIMIT 1
    """
)
_REASONS: Final = text(
    """
    SELECT jr.llm_review_id, jr.seq, jr.reason_code AS code, t.description AS label, jr.points, jr.quote,
           jr.element_id, a.itop_ci_id AS ci_id, jr.status, jr.rejection_rule
      FROM judge_reason jr
      JOIN judge_reason_type t ON t.code = jr.reason_code
      LEFT JOIN asset a ON a.id = jr.asset_id
     WHERE jr.llm_review_id = ANY(CAST(:reviews AS uuid[]))
     ORDER BY jr.llm_review_id, jr.seq
    """
)
APPLIED: Final = frozenset({"applied", "partial_review"})  # reviews whose proposal reached the score


@dataclass(frozen=True)
class Reason:
    seq: int
    code: str
    label: str
    points: int
    quote: str
    element_id: str
    ci_id: str | None
    status: str
    rejection_rule: str | None


@dataclass(frozen=True)
class DoubleReview:
    agreed: bool | None  # None when the comparison did not decide the outcome
    first_adjustment: int | None
    second_adjustment: int | None
    second_status: str


@dataclass(frozen=True)
class JudgeDetail:
    assessment_id: uuid.UUID
    review_id: uuid.UUID | None
    status: str | None
    summary: str | None
    model: str | None
    reviewed_at: datetime | None
    proposed_adjustment: int | None
    applied_adjustment: int
    dead_zone_applied: bool
    accepted_reasons: list[Reason]
    rejected_reasons: list[Reason]
    double_review: DoubleReview | None
    mitigation_status: str | None


def reasons_of(session: Session, reviews: list[uuid.UUID]) -> dict[uuid.UUID, list[Reason]]:
    """Every reason of the given reviews, in the order the judge proposed them, by review."""
    found: dict[uuid.UUID, list[Reason]] = {}
    if not reviews:
        return found
    for row in session.execute(_REASONS, {"reviews": reviews}):
        found.setdefault(row.llm_review_id, []).append(
            Reason(
                seq=int(row.seq),
                code=row.code,
                label=row.label,
                points=int(row.points),
                quote=row.quote,
                element_id=row.element_id,
                ci_id=row.ci_id,
                status=row.status,
                rejection_rule=row.rejection_rule,
            )
        )
    return found


def judge_detail(session: Session, assessment_id: uuid.UUID) -> JudgeDetail | None:
    """The judge behind an assessment; None if the assessment does not exist. Without a review (the base was kept),
    every judge field is empty and the applied adjustment is 0."""
    assessment = session.execute(_ASSESSMENT, {"id": assessment_id}).first()
    if assessment is None:
        return None
    review = session.execute(_REVIEW, {"id": assessment.llm_review_id}).first() if assessment.llm_review_id else None
    if review is None:
        return JudgeDetail(
            assessment.id,
            None,
            None,
            None,
            None,
            None,
            None,
            int(assessment.judge_adjustment),
            False,
            [],
            [],
            None,
            None,
        )
    second = session.execute(_SECOND, {"id": review.id}).first()
    reasons = reasons_of(session, [review.id]).get(review.id, [])
    double = (
        DoubleReview(
            # Only these statuses come out of the comparison; a stale review dropped it (RE-3): unknown.
            agreed=(review.status != "judge_disagreement" and second.proposed_adjustment is not None)
            if review.status in COMPARED
            else None,
            first_adjustment=review.proposed_adjustment,
            second_adjustment=second.proposed_adjustment,
            second_status=second.status,
        )
        if second is not None
        else None
    )
    return JudgeDetail(
        assessment_id=assessment.id,
        review_id=review.id,
        status=review.status,
        summary=review.summary,
        model=review.model,
        reviewed_at=review.created_at,
        proposed_adjustment=review.proposed_adjustment,
        applied_adjustment=int(assessment.judge_adjustment),
        # The proposal reached the score but fell inside the dead zone of that moment (EVA-02).
        dead_zone_applied=review.status in APPLIED
        and review.proposed_adjustment not in (None, 0)
        and int(assessment.judge_adjustment) == 0,
        accepted_reasons=[r for r in reasons if r.status == "accepted"],
        rejected_reasons=[r for r in reasons if r.status != "accepted"],
        double_review=double,
        mitigation_status=review.mitigation_status,
    )
