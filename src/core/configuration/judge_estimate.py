"""Judge estimate for the simulation (FRO-04): what the stored judge reviews would add with another sensitivity
profile or other reasons switched on, without calling the judge.

It starts from the reasons each review accepted (`judge_reason`), whose points were applied with the profile of that
moment (`llm_review.parameters.profile`): each one is taken back to the reference scale and scaled with the proposed
profile (docs/07 §12, decimal arithmetic, ROUND_HALF_UP). Reasons switched off, and downward reasons under a profile
that does not allow lowering, drop out. The adjustment returned is the group's, as in the engine's simulation. When
the review had a blind second review (D-027), both are estimated and compared with the judge's own rule
(`core.judge.double_review.combine`, docs/07 §6) for the group and for every CI (`more_critical_asset` reasons):
any disagreement keeps the base, as `combine_outcomes` does. It is an estimate: a reason the judge did not propose,
or one a rule rejected, never shows up, and whether the new adjustment would trigger a double review is not
replayed.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db import models as m
from core.judge.catalog import CatalogError, ProfileName, SensitivityProfile
from core.judge.double_review import combine
from core.scoring.evaluate import APPLIED_REVIEW_STATUSES

# Reviews whose comparison or proposal decided the score: applied ones, and a disagreement, which the estimate may
# turn into an agreement under another profile or other reasons.
ESTIMABLE: Final = frozenset({*APPLIED_REVIEW_STATUSES, "judge_disagreement"})


def rescale(points: int, applied_with: SensitivityProfile, proposed: SensitivityProfile) -> int:
    """Points applied under one profile, as the other profile would have applied them."""
    exact = Decimal(points) * proposed.range_multiplier / applied_with.range_multiplier
    return int(exact.quantize(Decimal(1), rounding=ROUND_HALF_UP))


def _profile_of(parameters: object) -> SensitivityProfile:
    """The profile a review ran with; reviews stored without one ran with the normal profile."""
    name = parameters.get("profile") if isinstance(parameters, dict) else None
    try:
        return SensitivityProfile.named(str(name or ProfileName.NORMAL.value))
    except CatalogError:
        return SensitivityProfile.named(ProfileName.NORMAL.value)


@dataclass(frozen=True)
class JudgeEstimate:
    """A `proposal` function for `core.scoring.evaluate.simulate`: the estimated group adjustment of an assessment."""

    profile: SensitivityProfile | None  # None keeps the profile each review ran with
    enabled: Mapping[str, bool]  # reason code -> switched on; a code not listed counts as on
    max_diff: int = 10  # double_review_max_diff (L10): how far two blind adjustments may differ and still agree

    def __call__(self, session: Session, assessment: m.Assessment | None) -> int | None:
        if assessment is None or assessment.llm_review_id is None:
            return None
        review = session.execute(
            select(m.LlmReview.status, m.LlmReview.parameters).where(m.LlmReview.id == assessment.llm_review_id)
        ).first()
        if review is None or review.status not in ESTIMABLE:
            return None  # a fallback kept the base: there is no proposal to estimate from
        applied_with = _profile_of(review.parameters)
        proposed = self.profile or applied_with
        first = self._adjustments(session, assessment.llm_review_id, applied_with, proposed)
        blind = session.scalar(
            select(m.LlmReview.id)
            .where(m.LlmReview.second_review_of_id == assessment.llm_review_id)
            .order_by(m.LlmReview.created_at, m.LlmReview.id)
            .limit(1)
        )
        if blind is None:
            return None if review.status == "judge_disagreement" else first.get(None, 0)
        second = self._adjustments(session, blind, applied_with, proposed)
        group = combine(first.get(None, 0), second.get(None, 0), self.max_diff)
        for ci in {key for key in (*first, *second) if key is not None}:
            if combine(first.get(ci, 0), second.get(ci, 0), self.max_diff) is None:
                return None  # a CI disagreement leaves only the base, as for the group
        return group

    def _adjustments(
        self, session: Session, review_id: uuid.UUID, applied_with: SensitivityProfile, proposed: SensitivityProfile
    ) -> dict[uuid.UUID | None, int]:
        """The estimated adjustments of one review: None for the group, one entry per CI with its own reasons."""
        rows = session.execute(
            select(m.JudgeReason.reason_code, m.JudgeReason.points, m.JudgeReason.asset_id).where(
                m.JudgeReason.llm_review_id == review_id, m.JudgeReason.status == "accepted"
            )
        )
        totals: dict[uuid.UUID | None, int] = {}
        for code, points, asset_id in rows:
            if not self.enabled.get(code, True) or (points < 0 and not proposed.allow_lowering):
                continue
            totals[asset_id] = totals.get(asset_id, 0) + rescale(int(points), applied_with, proposed)
        return totals
