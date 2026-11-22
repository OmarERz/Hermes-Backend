"""News analyst against PostgreSQL and the deterministic LLM double: no network, no tokens."""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Any

import pytest
from analyst_support import ARTICLE_TEXT, NOW, add_cves, add_story, news_output
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.analysts.news import NewsOptions, analyze_pending, analyze_story
from core.db import models as m
from core.db.ids import new_id
from doubles.llm import LlmDouble, tool_call_completion
from harness.judge import double_llm_client

pytestmark = pytest.mark.integration
TOOL = "submit_news_analysis"


def double_with(*arguments: dict[str, Any]) -> LlmDouble:
    double = LlmDouble()
    double.add_case("news", [tool_call_completion(TOOL, args) for args in arguments])
    double.use("news")
    return double


def analyze(session: Session, double: LlmDouble, story: m.Story) -> Any:
    return analyze_story(session, double_llm_client(double), story.id, NewsOptions(now=NOW))


def test_a_valid_answer_is_stored_and_normalized(session: Session) -> None:
    add_cves(session, "CVE-2026-1111", "CVE-2026-2222")
    peer = m.PeerCompany(id=new_id(), name="Globex Hospital", created_at=NOW)
    session.add(peer)
    story = add_story(session)
    double = double_with(news_output(story.id))
    result = analyze(session, double, story)
    double.assert_calls(1)
    assert result.status == "analyzed"
    analysis = session.get(m.NewsAnalysis, result.analysis_id)
    assert analysis is not None
    assert (analysis.event_type, analysis.summary) == ("active_exploitation", "Resumen sintético.")
    review = session.get(m.LlmReview, analysis.llm_review_id)
    assert review is not None
    assert (review.agent, review.status, review.attempts, review.model) == (
        "news_analyst",
        "applied",
        1,
        "deepseek-flash",
    )
    assert (review.tokens_input, review.tokens_output) == (10, 5)
    assert review.cost_usd == Decimal("0.000005")
    assert review.prompt_version == "news-analyst-v1"
    assert len(review.schema_hash) == 64
    cves = sorted(session.scalars(select(m.NewsCveMention.cve_id).where(m.NewsCveMention.analysis_id == analysis.id)))
    assert cves == ["CVE-2026-1111", "CVE-2026-2222"]
    product = session.scalars(select(m.NewsProductMention)).one()
    assert (product.vendor, product.product, product.version) == ("Acme", "Firewall", None)
    victim = session.scalars(select(m.NewsVictim)).one()
    assert (victim.peer_company_id, victim.sector_code, victim.country_code) == (peer.id, "healthcare", "MX")
    actor = session.scalars(select(m.Actor)).one()
    assert actor.name == "Lockbit"
    assert session.scalars(select(m.ActorAlias.alias)).all() == ["ABCD"]
    vector = session.scalars(select(m.NewsAttackVector)).one()
    assert vector.vector_code == "exposed_management_service"
    claims = {(c.claim_type, c.cve_id) for c in session.scalars(select(m.Claim))}
    assert claims == {("exploited", "CVE-2026-1111"), ("not_exploited", "CVE-2026-2222"), ("public_poc", None)}


def test_the_prompt_is_fixed_in_the_system_role_and_the_news_is_delimited_data(session: Session) -> None:
    add_cves(session, "CVE-2026-1111", "CVE-2026-2222")
    story = add_story(session)
    double = double_with(news_output(story.id))
    analyze(session, double, story)
    body = double.requests[0].body
    system, user = body["messages"][0], body["messages"][1]
    assert system["role"] == "system"
    assert ARTICLE_TEXT not in system["content"]
    assert "DATO" in system["content"]
    assert user["role"] == "user"
    assert ARTICLE_TEXT in user["content"]
    assert "<<<NOTICIA " in user["content"]
    assert body["tool_choice"]["function"]["name"] == TOOL
    assert "iTop" not in json.dumps(body["messages"][1])


def test_a_story_is_analyzed_once(session: Session) -> None:
    add_cves(session, "CVE-2026-1111", "CVE-2026-2222")
    story = add_story(session)
    double = double_with(news_output(story.id))
    assert analyze(session, double, story).status == "analyzed"
    again = analyze(session, double, story)
    assert again.status == "exists"
    double.assert_calls(1)


def test_a_quote_that_is_not_in_the_news_is_retried_with_the_concrete_error(session: Session) -> None:
    add_cves(session, "CVE-2026-1111", "CVE-2026-2222")
    story = add_story(session)
    invented = news_output(story.id)
    invented["cves"][0]["quote"] = "a sentence the article never says CVE-2026-1111"
    double = double_with(invented, news_output(story.id))
    result = analyze(session, double, story)
    double.assert_calls(2)
    assert result.status == "analyzed"
    retry = double.requests[1].body["messages"][-1]["content"]
    assert "VAL-03.quote at cves[0].quote" in retry
    assert "never says" not in retry  # the model's own output does not go back
    review = session.scalars(select(m.LlmReview)).one()
    assert review.attempts == 2


def test_the_same_error_twice_queues_the_story_without_a_third_call(session: Session) -> None:
    add_cves(session, "CVE-2026-1111", "CVE-2026-2222")
    story = add_story(session)
    invented = news_output(story.id)
    invented["cves"][0]["quote"] = "never said CVE-2026-1111"
    double = double_with(invented, invented, news_output(story.id))
    result = analyze(session, double, story)
    double.assert_calls(2)
    assert result.status == "queued"
    assert session.scalar(select(func.count()).select_from(m.NewsAnalysis)) == 0
    queued = session.scalars(select(m.ErrorQueue)).one()
    assert (queued.component, queued.story_id, queued.status) == ("news_analyst", story.id, "pending")
    assert "VAL-03.quote" in queued.reason
    review = session.scalars(select(m.LlmReview)).one()
    assert review.status == "rejected"
    assert review.tokens_input == 20  # both paid calls are counted


def test_a_schema_violation_from_the_provider_is_a_format_failure_that_is_retried(session: Session) -> None:
    add_cves(session, "CVE-2026-1111", "CVE-2026-2222")
    story = add_story(session)
    broken = news_output(story.id)
    del broken["summary"]
    double = double_with(broken, news_output(story.id))
    assert analyze(session, double, story).status == "analyzed"
    double.assert_calls(2)
    assert "VAL-01.format" in double.requests[1].body["messages"][-1]["content"]


def test_an_unknown_cve_is_rejected(session: Session) -> None:
    story = add_story(session)  # neither CVE exists in the database
    double = double_with(news_output(story.id), news_output(story.id))
    assert analyze(session, double, story).status == "queued"
    assert "VAL-03.cve_exists" in session.scalars(select(m.ErrorQueue.reason)).one()


def test_a_provider_failure_queues_the_story(session: Session) -> None:
    story = add_story(session)
    double = LlmDouble()
    double.add_case("down", [])
    double.use("down")  # no response left: HTTP 500
    result = analyze(session, double, story)
    assert result.status == "queued"
    assert result.reason is not None
    assert session.scalars(select(m.ErrorQueue)).one().story_id == story.id


def test_stories_that_cannot_be_analyzed_make_no_call(session: Session) -> None:
    double = double_with()
    assert analyze(session, double, add_story(session, relevance="pending")).status == "not_relevant"
    assert analyze(session, double, add_story(session, relevance="filtered")).status == "not_relevant"
    assert analyze(session, double, add_story(session, text=None)).status == "no_text"
    missing = analyze_story(session, double_llm_client(double), new_id(), NewsOptions(now=NOW))
    assert missing.status == "not_relevant"
    double.assert_calls(0)


def test_an_exhausted_budget_queues_the_story_without_calling_the_model(session: Session) -> None:
    session.add(
        m.SettingValue(id=new_id(), setting_key="daily_budget_usd", version=1, value="0", origin="seed", changed_at=NOW)
    )
    session.flush()
    story = add_story(session)
    double = double_with(news_output(story.id))
    result = analyze(session, double, story)
    assert (result.status, result.reason) == ("budget", "budget")
    double.assert_calls(0)
    assert session.scalars(select(m.ErrorQueue.reason)).one() == "budget"


def test_pending_stories_are_analyzed_one_by_one_and_a_failure_does_not_stop_the_next(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    add_cves(session, "CVE-2026-1111", "CVE-2026-2222")
    bad, good = add_story(session), add_story(session)
    broken = news_output(bad.id)
    broken["cves"][0]["quote"] = "never said CVE-2026-1111"
    double = double_with(broken, broken, news_output(good.id))
    monkeypatch.setattr(session, "commit", session.flush)
    results = analyze_pending(session, double_llm_client(double), NewsOptions(now=NOW))
    assert sorted(r.status for r in results) == ["analyzed", "queued"]
    double.assert_calls(3)
