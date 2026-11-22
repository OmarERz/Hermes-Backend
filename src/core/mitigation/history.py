"""Score history (EVA-05): every assessment of a group with one row per CI, oldest first, for the charts."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

from sqlalchemy import text
from sqlalchemy.orm import Session

MAX_POINTS = 1000

_HISTORY = text(
    'SELECT * FROM (SELECT a.id, a.assessed_at, a.finding_group_id, a.formula_version_id, a."trigger", '
    "s.asset_id, s.base, a.judge_adjustment, s.ci_adjustment, s.final, d.level, d.floor_applied, "
    "a.factor_s, a.factor_p, a.factor_t, s.factor_a, s.factor_d, "
    "a.raw_cvss_score, a.raw_epss, a.raw_in_kev, (a.llm_review_id IS NULL OR r.status = 'no_judge_review') "
    "FROM assessment a JOIN asset_score s ON s.assessment_id = a.id "
    "JOIN asset_score_detail d ON d.assessment_id = a.id AND d.asset_id = s.asset_id "
    "LEFT JOIN llm_review r ON r.id = a.llm_review_id "
    "WHERE (CAST(:group_id AS uuid) IS NULL OR a.finding_group_id = CAST(:group_id AS uuid)) "
    "AND (CAST(:asset_id AS uuid) IS NULL OR s.asset_id = CAST(:asset_id AS uuid)) "
    "AND (CAST(:before AS timestamptz) IS NULL OR a.assessed_at < CAST(:before AS timestamptz)) "
    "ORDER BY a.assessed_at DESC, a.id DESC, s.asset_id DESC LIMIT :limit) newest "
    "ORDER BY newest.assessed_at, newest.id, newest.asset_id"
)


@dataclass(frozen=True)
class HistoryPoint:
    assessment_id: uuid.UUID
    assessed_at: datetime
    finding_group_id: uuid.UUID | None
    formula_version_id: uuid.UUID
    trigger: str
    asset_id: uuid.UUID
    base: int
    judge_adjustment: int
    ci_adjustment: int
    final: int
    level: str | None
    floor_applied: bool
    factors: dict[str, Decimal]  # S, P, T, A, D
    raw_cvss_score: Decimal | None
    raw_epss: Decimal | None
    raw_in_kev: bool | None
    no_judge_review: bool  # no judge review backs this score: the final is base plus the CI rules only


def score_history(
    session: Session,
    *,
    finding_group_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    limit: int = MAX_POINTS,
    before: datetime | None = None,
) -> list[HistoryPoint]:
    """The history of a vulnerability group, of a CI, or of a CI within a group; at least one filter is required.

    Returns the newest `limit` points in chronological order; pass `before` (the oldest `assessed_at` seen) to page
    back to older ones, so a long history is never cut at the recent end.
    """
    if finding_group_id is None and asset_id is None:
        raise ValueError("give a finding group, an asset or both")
    if not 1 <= limit <= MAX_POINTS:
        raise ValueError("limit must be between 1 and 1000")
    rows = session.execute(
        _HISTORY, {"group_id": finding_group_id, "asset_id": asset_id, "limit": limit, "before": before}
    )
    return [
        HistoryPoint(
            assessment_id=r[0],
            assessed_at=r[1],
            finding_group_id=r[2],
            formula_version_id=r[3],
            trigger=r[4],
            asset_id=r[5],
            base=r[6],
            judge_adjustment=r[7],
            ci_adjustment=r[8],
            final=r[9],
            level=r[10],
            floor_applied=bool(r[11]),
            factors={"S": r[12], "P": r[13], "T": r[14], "A": r[15], "D": r[16]},
            raw_cvss_score=r[17],
            raw_epss=r[18],
            raw_in_kev=r[19],
            no_judge_review=bool(r[20]),
        )
        for r in rows
    ]
