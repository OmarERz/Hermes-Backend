"""RE-9 (D-088): «accept the original score» is a `wrong_priority` feedback proposing the recommendation's base on an
assessment the judge adjusted. The nightly metric counts it and the weight calibration leaves it out."""

from __future__ import annotations

from datetime import date, timedelta
from decimal import Decimal

import f08data as d
import pytest
from sqlalchemy.orm import Session, sessionmaker

from core.calibration.weights import load_cases
from core.db import models as m
from core.metrics.nightly import compute_daily_metrics

pytestmark = pytest.mark.integration
DAY = date(2026, 11, 21)


def judged(session: Session, adjustment: int, scores: list[tuple[int, int]]) -> m.Assessment:
    """An assessment with this judge adjustment and one CI per (base, final)."""
    row = d.assessment(session, adjustment)
    for base, final in scores:
        session.add(
            m.AssetScore(
                assessment_id=row.id,
                asset_id=d.asset(session).id,
                factor_a=Decimal("1"),
                factor_d=Decimal("0.5"),
                version_factor=Decimal("1.00"),
                base=base,
                ci_adjustment=0,
                final=final,
                snap_criticality="high",
                snap_confidentiality="public",
            )
        )
    session.flush()
    return row


def verdict(session: Session, assessment: m.Assessment, kind: str, score: int | None = None) -> None:
    session.add(
        m.Feedback(
            assessment_id=assessment.id,
            app_user_id=d.user(session).id,
            channel="frontend",
            verdict=kind,
            proposed_level="low" if kind == "wrong_priority" else None,
            proposed_score=score,
            created_at=d.NOON,
        )
    )
    session.flush()


def test_accepting_the_original_score_is_counted_and_kept_out_of_calibration(
    factory: sessionmaker[Session],
) -> None:
    with factory() as session, session.begin():
        d.formula(session)
        # The driving CI is the one with the highest final (60 -> 70); the other CI's base (40) is not "the original".
        raised = judged(session, 10, [(60, 70), (40, 50)])
        verdict(session, raised, "wrong_priority", 60)  # accepts the original score
        verdict(session, raised, "wrong_priority", 40)  # a real disagreement with the score
        verdict(session, raised, "relevant")
        lowered = judged(session, -8, [(55, 47)])
        verdict(session, lowered, "wrong_priority", 55)  # accepts the original score
        plain = judged(session, 0, [(50, 50)])
        verdict(session, plain, "wrong_priority", 50)  # no judge adjustment: neither counted nor skipped
    with factory() as session:
        values = {v.code: v.value for v in compute_daily_metrics(session, DAY, d.NOW)}
        assert values["original_score_accepted"] == Decimal(2) / 4  # 2 of the 4 verdicts on judged assessments
        cases = load_cases(session, d.NOON + timedelta(hours=1))
    assert sorted(case.wanted for case in cases) == [40, 50]
