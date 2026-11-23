"""The judge as the pipeline uses it: package stored, review stored, verdict back; the ladder can turn it off."""

from __future__ import annotations

import pytest
from pipeline_support import NOW, judge_caller, make_story, one_reason_review
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from core.pipeline.judging import dismiss_story, judge_for
from doubles.llm import tool_call_completion
from harness.judge import dismissal_package, finding_package

pytestmark = pytest.mark.integration


def test_mode1_stores_the_package_and_the_review_and_answers_the_adjustment(factory: sessionmaker[Session]) -> None:
    caller, double = judge_caller(*one_reason_review())
    with factory() as session, session.begin():
        group_id = session.scalars(select(m.FindingGroup.id).limit(1)).one()
        package = finding_package(package_id=str(group_id))
        judge = judge_for(session, caller, NOW)
        assert judge is not None
        verdict = judge(package)
        assert verdict.adjustment == 10
        review = session.get_one(m.LlmReview, verdict.llm_review_id)
        assert (review.status, review.input_ref.startswith("review_package:")) == ("applied", True)
        stored = session.scalars(select(m.ReviewPackage).where(m.ReviewPackage.finding_group_id == group_id)).one()
        assert stored.fingerprint == package["fingerprint"]
    double.assert_calls(2)


def test_a_judge_turned_off_by_the_ladder_is_not_offered(factory: sessionmaker[Session]) -> None:
    caller, double = judge_caller()
    with factory() as session:
        session.begin()
        session.add(m.JudgeLadderChange(level=3, reason="regresión fallida", changed_at=NOW))
        session.flush()
        assert judge_for(session, caller, NOW) is None
        assert dismiss_story(session, caller, dismissal_package(), NOW) is None
        session.rollback()
    double.assert_calls(0)


def test_mode2_reviews_a_dismissal_candidate(factory: sessionmaker[Session]) -> None:
    caller, _ = judge_caller(tool_call_completion("dismiss_news", {"news_id": "N1", "reason": "No usamos OpenSSL 3."}))
    with factory() as session, session.begin():
        story_id = make_story(session)
        content = dismissal_package(package_id=str(story_id))
        content["news"][0]["story_id"] = str(story_id)
        stored = dismiss_story(session, caller, content, NOW)
        assert stored is not None
        assert stored.alert_id is None
        assert session.get_one(m.LlmReview, stored.review_id).summary == "No usamos OpenSSL 3."
