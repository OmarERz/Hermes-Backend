"""Double review (L10, D-027, docs/07 §6): when it triggers and how code combines two blind reviews.

Triggers: |adjustment| >= double_review_threshold (group, or group + CI adjustment of any CI), crossing to or from
Critical (>= 90) for any CI, a reason outside its effective range, or a cited suspicious element (SEG-03).
The comparison is done by code, never by an agent: same direction and difference <= double_review_max_diff gives
the rounded average when raising and the smaller magnitude when lowering; otherwise only the base applies, flagged
`judge_disagreement`. A tie-break third call stays disabled (TODO(P-014)).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal

from core.judge.catalog import JudgeSettings
from core.judge.package import ReviewPackage
from core.judge.session import ReviewOutcome, ReviewStatus

MIN_SCORE = 0
MAX_SCORE = 100
WATCHED_THRESHOLD = 10  # docs/07 §8 ladder level 1: the threshold drops from 15 to 10 (TODO(P-006))
_COMPARABLE = frozenset({ReviewStatus.APPLIED, ReviewStatus.SUGGESTION, ReviewStatus.PARTIAL_REVIEW})


def _clamp(score: int) -> int:
    return max(MIN_SCORE, min(MAX_SCORE, score))


def needs_double_review(outcome: ReviewOutcome, package: ReviewPackage, settings: JudgeSettings) -> bool:
    if outcome.status not in _COMPARABLE or outcome.adjustment is None:
        return False
    if outcome.out_of_range or outcome.cites_suspicious:
        return True
    threshold = settings.double_review_threshold
    if outcome.ladder_level >= 1:
        threshold = min(threshold, WATCHED_THRESHOLD)
    deltas = [outcome.adjustment] + [outcome.adjustment + outcome.ci_adjustments.get(ci.ci_id, 0) for ci in package.cis]
    if any(abs(delta) >= threshold for delta in deltas):
        return True
    line = settings.critical_line
    for ci in package.cis:
        before = ci.base_score
        after = _clamp(before + outcome.adjustment + outcome.ci_adjustments.get(ci.ci_id, 0))
        if (before < line) != (after < line):
            return True
    return False


def combine(first: int, second: int, max_diff: int) -> int | None:
    """Code comparison of two adjustments (docs/07 §6). None means disagreement: only the base applies."""
    if first == second:
        return first
    same_direction = (first > 0 and second > 0) or (first < 0 and second < 0)
    if not same_direction or abs(first - second) > max_diff:
        return None
    if first > 0:
        return int((Decimal(first + second) / 2).quantize(Decimal(1), rounding=ROUND_HALF_UP))
    return first if abs(first) <= abs(second) else second


@dataclass(frozen=True)
class Combined:
    agreed: bool
    adjustment: int
    ci_adjustments: Mapping[str, int]


def combine_outcomes(first: ReviewOutcome, second: ReviewOutcome, max_diff: int) -> Combined:
    """Combine the group adjustment and every CI adjustment; any disagreement leaves only the base."""
    group = combine(first.adjustment or 0, second.adjustment or 0, max_diff)
    per_ci: dict[str, int] = {}
    agreed = group is not None
    for ci in sorted(set(first.ci_adjustments) | set(second.ci_adjustments)):
        value = combine(first.ci_adjustments.get(ci, 0), second.ci_adjustments.get(ci, 0), max_diff)
        if value is None:
            agreed = False
        elif value:
            per_ci[ci] = value
    if not agreed or group is None:
        return Combined(agreed=False, adjustment=0, ci_adjustments={})
    return Combined(agreed=True, adjustment=group, ci_adjustments=per_ci)
