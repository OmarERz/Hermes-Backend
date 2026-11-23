"""F12.2 #105: the analysts hold no transaction while the model answers (or the advisory downloads), and the write
step re-checks what the answer depends on. Real commits, on this module's own database."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from decimal import Decimal
from typing import Any

import pytest
from analyst_support import ARTICLE_TEXT, NOW, add_cves, add_story, news_output
from sqlalchemy import Engine, func, select, update
from sqlalchemy.orm import Session

from core.analysts.cve import CveOptions, analyze_cve
from core.analysts.news import NewsOptions, analyze_story, pending_stories
from core.db import models as m
from core.db.session import make_engine
from doubles.llm import LlmDouble, tool_call_completion
from harness.judge import double_llm_client
from harness.transactions import open_transactions

pytestmark = pytest.mark.integration
NEWS_TOOL = "submit_news_analysis"
CVE_TOOL = "submit_cve_analysis"


@pytest.fixture
def engine(migrated_url: str) -> Iterator[Engine]:
    engine = make_engine(migrated_url)
    try:
        yield engine
    finally:
        engine.dispose()


def committed_story(engine: Engine) -> m.Story:
    with Session(engine, expire_on_commit=False) as session, session.begin():
        add_cves(session, "CVE-2026-1111", "CVE-2026-2222")
        return add_story(session)


def news_double(*arguments: dict[str, Any]) -> LlmDouble:
    double = LlmDouble()
    double.add_case("news", [tool_call_completion(NEWS_TOOL, args) for args in arguments])
    double.use("news")
    return double


def reviews_of(engine: Engine, input_ref: str) -> list[tuple[str, Any]]:
    with Session(engine) as session:
        rows = session.execute(select(m.LlmReview.status, m.LlmReview.calls).where(m.LlmReview.input_ref == input_ref))
        return [(status, calls) for status, calls in rows]


def test_no_transaction_is_open_during_the_news_calls_or_the_validation_between_them(engine: Engine) -> None:
    story = committed_story(engine)
    invented = news_output(story.id)
    invented["cves"][0]["quote"] = "a sentence the article never says CVE-2026-1111"
    double = news_double(invented, news_output(story.id))  # the first answer is validated, then retried
    seen: list[list[tuple[int, str, int]]] = []
    double.on_request = lambda: seen.append(open_transactions(engine))
    with Session(engine) as session:
        result = analyze_story(session, double_llm_client(double), story.id, NewsOptions(now=NOW))
        assert not session.in_transaction()  # the write step is committed too
    assert result.status == "analyzed"
    assert seen == [[], []]


def test_a_story_filtered_while_the_model_answers_keeps_the_paid_review_but_not_the_answer(engine: Engine) -> None:
    story = committed_story(engine)
    double = news_double(news_output(story.id))

    def filter_story() -> None:  # an admin filters the story meanwhile: nothing blocks this write
        with Session(engine) as other, other.begin():
            other.execute(update(m.Story).where(m.Story.id == story.id).values(relevance_status="filtered"))

    double.on_request = filter_story
    with Session(engine) as session:
        result = analyze_story(session, double_llm_client(double), story.id, NewsOptions(now=NOW))
    assert (result.status, result.reason) == ("not_relevant", "stale")
    assert reviews_of(engine, str(story.id)) == [("rejected", [{"attempts": 1, "failure": "stale"}])]
    with Session(engine) as session:
        assert session.scalar(select(m.NewsAnalysis.id).where(m.NewsAnalysis.story_id == story.id)) is None
        assert session.scalars(select(m.ErrorQueue).where(m.ErrorQueue.story_id == story.id)).all() == []


def test_a_story_another_worker_analyzed_meanwhile_is_not_stored_twice(engine: Engine) -> None:
    story = committed_story(engine)
    double = news_double(news_output(story.id))
    rival = news_double(news_output(story.id))

    def rival_worker() -> None:
        with Session(engine) as other:
            assert analyze_story(other, double_llm_client(rival), story.id, NewsOptions(now=NOW)).status == "analyzed"

    double.on_request = rival_worker
    with Session(engine) as session:
        result = analyze_story(session, double_llm_client(double), story.id, NewsOptions(now=NOW))
    assert (result.status, result.reason) == ("exists", "stale")
    assert sorted(status for status, _ in reviews_of(engine, str(story.id))) == ["applied", "rejected"]
    with Session(engine) as session:
        assert len(session.scalars(select(m.NewsAnalysis).where(m.NewsAnalysis.story_id == story.id)).all()) == 1


def test_a_story_that_changed_its_article_meanwhile_is_analyzed_again_later(engine: Engine) -> None:
    story = committed_story(engine)
    with Session(engine, expire_on_commit=False) as session, session.begin():
        other_article = session.get_one(m.Story, add_story(session, text=ARTICLE_TEXT).id).representative_article_id
    double = news_double(news_output(story.id))

    def regroup() -> None:  # deduplication picked another representative article
        with Session(engine) as other, other.begin():
            other.execute(update(m.Story).where(m.Story.id == story.id).values(representative_article_id=other_article))

    double.on_request = regroup
    with Session(engine) as session:
        result = analyze_story(session, double_llm_client(double), story.id, NewsOptions(now=NOW))
    assert (result.status, result.reason) == ("stale", "stale")
    with Session(engine) as session:
        assert session.scalar(select(m.NewsAnalysis.id).where(m.NewsAnalysis.story_id == story.id)) is None
        assert session.scalars(select(m.ErrorQueue).where(m.ErrorQueue.story_id == story.id)).all() == []
        assert story.id in pending_stories(session, limit=1000)  # the next run analyzes it with its new article


def test_a_failed_answer_for_a_story_that_changed_meanwhile_is_not_queued(engine: Engine) -> None:
    story = committed_story(engine)
    double = LlmDouble()
    double.add_case("down", [])
    double.use("down")

    def filter_story() -> None:
        with Session(engine) as other, other.begin():
            other.execute(update(m.Story).where(m.Story.id == story.id).values(relevance_status="filtered"))

    double.on_request = filter_story
    with Session(engine) as session:
        result = analyze_story(session, double_llm_client(double), story.id, NewsOptions(now=NOW))
    assert result.status == "not_relevant"
    [(status, calls)] = reviews_of(engine, str(story.id))
    assert status == "rejected"
    assert calls[0]["failure"] != "stale"  # the real failure is kept
    with Session(engine) as session:
        assert session.scalars(select(m.ErrorQueue).where(m.ErrorQueue.story_id == story.id)).all() == []


CVE_DESCRIPTION = "The flaw allows remote code execution without authentication."


def cve_output(cve_id: str) -> dict[str, Any]:
    return {
        "cve": cve_id,
        "inferred_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_confidence": 0.7,
        "conditions": [{"type": "authentication", "description": "None needed", "quote": "without authentication"}],
        "components": [],
        "notes": "",
    }


def cve_double(*arguments: dict[str, Any]) -> LlmDouble:
    double = LlmDouble()
    double.add_case("cve", [tool_call_completion(CVE_TOOL, args) for args in arguments])
    double.use("cve")
    return double


def test_no_transaction_is_open_during_the_advisory_download_or_the_cve_call(engine: Engine) -> None:
    cve_id = "CVE-2026-8101"
    with Session(engine) as session, session.begin():
        session.add(m.Cve(id=cve_id, description=CVE_DESCRIPTION, fetched_at=NOW))
    seen: list[tuple[str, list[tuple[int, str, int]]]] = []

    def advisory(urls: list[str]) -> str | None:
        seen.append(("download", open_transactions(engine)))
        return None

    invented = cve_output(cve_id)
    invented["conditions"][0]["quote"] = "a sentence the description never says"
    double = cve_double(invented, cve_output(cve_id))  # the first answer is validated, then retried
    double.on_request = lambda: seen.append(("model", open_transactions(engine)))
    with Session(engine) as session:
        result = analyze_cve(session, double_llm_client(double), cve_id, CveOptions(now=NOW, advisory=advisory))
        assert not session.in_transaction()
    assert result.status == "analyzed"
    assert seen == [("download", []), ("model", []), ("model", [])]


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"description": "A different text after an NVD refresh."}, "stale"),
        ({"cvss_score": Decimal("9.8")}, "stale"),
    ],
)
def test_a_cve_refreshed_while_the_model_answers_is_not_applied(
    engine: Engine, change: dict[str, Any], expected: str
) -> None:
    cve_id = "CVE-2026-8102" if "description" in change else "CVE-2026-8103"
    with Session(engine) as session, session.begin():
        session.add(m.Cve(id=cve_id, description=CVE_DESCRIPTION, fetched_at=NOW))
    double = cve_double(cve_output(cve_id))

    def refresh() -> None:
        with Session(engine) as other, other.begin():
            other.execute(update(m.Cve).where(m.Cve.id == cve_id).values(**change))

    double.on_request = refresh
    with Session(engine) as session:
        result = analyze_cve(session, double_llm_client(double), cve_id, CveOptions(now=NOW))
    assert (result.status, result.reason) == (expected, "stale")
    assert reviews_of(engine, cve_id) == [("rejected", [{"attempts": 1, "failure": "stale"}])]
    with Session(engine) as session:
        assert session.scalar(select(m.CveAnalysis.id).where(m.CveAnalysis.cve_id == cve_id)) is None
        assert session.scalars(select(m.ErrorQueue).where(m.ErrorQueue.cve_id == cve_id)).all() == []


def test_a_cve_another_worker_analyzed_meanwhile_is_not_stored_twice(engine: Engine) -> None:
    cve_id = "CVE-2026-8104"
    with Session(engine) as session, session.begin():
        session.add(m.Cve(id=cve_id, description=CVE_DESCRIPTION, fetched_at=NOW))
    double = cve_double(cve_output(cve_id))
    rival = cve_double(cve_output(cve_id))

    def rival_worker() -> None:
        with Session(engine) as other:
            assert analyze_cve(other, double_llm_client(rival), cve_id, CveOptions(now=NOW)).status == "analyzed"

    double.on_request = rival_worker
    with Session(engine) as session:
        result = analyze_cve(session, double_llm_client(double), cve_id, CveOptions(now=NOW))
    assert (result.status, result.reason) == ("exists", "stale")
    with Session(engine) as session:
        assert len(session.scalars(select(m.CveAnalysis).where(m.CveAnalysis.cve_id == cve_id)).all()) == 1


def test_the_write_step_waits_for_a_concurrent_write_of_the_same_story(engine: Engine) -> None:
    """Two workers that both reach the write step: the story's lock makes the second one see the first's analysis
    instead of breaking on the unique key (cycles never overlap today; this keeps it safe if they ever do)."""
    story = committed_story(engine)
    holder = Session(engine)
    holder.execute(select(func.pg_advisory_xact_lock(func.hashtextextended(f"news-analyst:{story.id}", 0))))
    outcome: list[Any] = []

    def worker() -> None:
        with Session(engine) as session:
            double = news_double(news_output(story.id))
            outcome.append(analyze_story(session, double_llm_client(double), story.id, NewsOptions(now=NOW)))

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(timeout=2)
    assert thread.is_alive()  # the model answered; the write step waits for the lock
    holder.rollback()
    holder.close()
    thread.join(timeout=10)
    assert [r.status for r in outcome] == ["analyzed"]
