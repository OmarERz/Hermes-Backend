"""Mode 2 stores its review, the validated alert (one per story) and its CI link; refuted relationships and the
inventory come from the database (docs/07 §7, L15; docs/15 F-10)."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from dbprovision import provisioned_database
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id
from core.db.seeds import seed
from core.db.session import make_engine
from core.judge.budget import FREE, UnlimitedDailyBudget
from core.judge.catalog import JudgeSettings, ReasonCatalog, SensitivityProfile, TokenCaps
from core.judge.package import ReviewPackage
from core.judge.service import DismissalService
from core.judge.session import JudgeEnvironment, ReviewStatus
from core.judge.store import (
    DbInventory,
    ReviewTarget,
    SnapshotInventory,
    load_judge_settings,
    refuted_relationships,
)
from doubles.llm import LlmDouble, tool_call_completion
from harness.judge import dismissal_package, double_llm_client

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]
NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
QUOTE = "A critical memory corruption flaw affects OpenSSL 3.x"
ALERT = {
    "news_id": "N1",
    "ci_id": "",
    "cited_product": "OpenSSL 3.x",
    "relationship_type": "inferred_component",
    "relationship": "Nginx → usa → OpenSSL del sistema operativo Ubuntu",
    "evidence_id": "N1",
    "quote": QUOTE,
    "suggested_action": "Verificar la versión de OpenSSL de Ubuntu (posible parche retroportado).",
    "confidence": 0.7,
}


@pytest.fixture
def engine(postgres_url: str) -> Iterator[Engine]:
    with provisioned_database(postgres_url, "judgemode2") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        engine = make_engine(db.superuser_url)
        with Session(engine) as session, session.begin():
            seed(session, "demo")
        try:
            yield engine
        finally:
            engine.dispose()


def make_story(session: Session) -> uuid.UUID:
    """A minimal story (source → fetch → article → story) for the alert and package foreign keys."""
    source = m.Source(
        id=new_id(),
        code=f"synthetic-{uuid.uuid4().hex[:8]}",
        name="Synthetic media",
        kind="rss",
        url="https://media.example.test/feed",
        trust_tier="N3",
        is_structural=False,
        is_custom=False,
        enabled=True,
        created_at=NOW,
    )
    session.add(source)
    session.flush()
    run_id = session.scalars(select(m.Run.id).limit(1)).one()
    fetch = m.SourceFetch(id=new_id(), source_id=source.id, run_id=run_id, started_at=NOW, status="ok", items_new=1)
    session.add(fetch)
    session.flush()
    article = m.RawArticle(
        id=new_id(),
        source_fetch_id=fetch.id,
        canonical_url=f"https://media.example.test/{uuid.uuid4().hex}",
        title="Synthetic advisory",
        published_at=NOW,
        captured_at=NOW,
        is_suspicious=False,
    )
    session.add(article)
    session.flush()
    story = m.Story(id=new_id(), representative_article_id=article.id, relevance_status="relevant", created_at=NOW)
    session.add(story)
    session.flush()
    article.story_id = story.id
    session.flush()
    return story.id


def candidate(story_id: uuid.UUID) -> dict[str, Any]:
    content = dismissal_package(package_id=str(story_id))
    content["news"][0]["story_id"] = str(story_id)
    return content


def package_row(session: Session, content: dict[str, Any]) -> uuid.UUID:
    return package_row_for(session, content, uuid.UUID(content["news"][0]["story_id"]))


def package_row_for(session: Session, content: dict[str, Any], story_id: uuid.UUID) -> uuid.UUID:
    row = m.ReviewPackage(
        id=new_id(),
        kind="dismissal",
        story_id=story_id,
        fingerprint=content["fingerprint"],
        content=content,
        built_at=NOW,
    )
    session.add(row)
    session.flush()
    return row.id


def service(responses: list[dict[str, Any]], **settings: Any) -> DismissalService:
    double = LlmDouble()
    double.add_case("case", responses)
    double.use("case")
    env = JudgeEnvironment(
        catalog=ReasonCatalog.default(),
        profile=SensitivityProfile.named("normal"),
        settings=JudgeSettings(**settings),
        today=date(2026, 11, 22),
        daily_budget=UnlimitedDailyBudget(),
        price=FREE,
    )
    return DismissalService(double_llm_client(double), env)


def test_e11_inferred_alert_is_stored_once_per_story(engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        story_id = make_story(session)
        content = candidate(story_id)
        package_id = package_row(session, content)
        target = ReviewTarget(package_id, f"review_package:{package_id}", NOW)
        first = service([tool_call_completion("propose_alert", ALERT)]).review(
            session, ReviewPackage.from_content(content), target
        )
        again = service([tool_call_completion("propose_alert", ALERT)]).review(
            session, ReviewPackage.from_content(content), target
        )
    assert first.alert_id is not None
    assert again.alert_id == first.alert_id  # deduplicated by story (L15)
    assert not first.queued
    with Session(engine) as session:
        alert = session.get_one(m.Alert, first.alert_id)
        assert (alert.relevance, alert.relationship_type, alert.status) == ("inferred", "component", "open")
        assert alert.confidence == Decimal("0.70")
        assert alert.llm_review_id == first.review_id
        assert alert.verification_action.startswith("Verificar la versión de OpenSSL")
        assert session.scalars(select(m.AlertAsset)).all() == []  # no CI cited: "sin activo directo"
        review = session.get_one(m.LlmReview, first.review_id)
        assert (review.mode, review.status, review.proposed_adjustment) == ("dismissals", "applied", None)
        assert review.prompt_version == "judge-mode2-v1"
        assert review.mitigation_status == "absent"
        assert session.scalars(select(m.JudgeReason)).all() == []


def test_alert_with_a_ci_that_runs_the_named_product_links_the_asset(engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        story_id = make_story(session)
        content = candidate(story_id)
        stored = service([tool_call_completion("propose_alert", {**ALERT, "ci_id": "CI-1"})]).review(
            session, ReviewPackage.from_content(content), ReviewTarget(package_row(session, content), "r", NOW)
        )
    assert stored.status is ReviewStatus.APPLIED
    with Session(engine) as session:
        link = session.scalars(select(m.AlertAsset).where(m.AlertAsset.alert_id == stored.alert_id)).one()
        payments = session.scalars(select(m.Asset).where(m.Asset.itop_ci_id == "CI-1")).one()
        assert (link.asset_id, link.version_confirmed) == (payments.id, False)
        assert link.installed_software_id is not None


def test_dismissal_and_fallback(engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        story_id = make_story(session)
        content = candidate(story_id)
        package_id = package_row(session, content)
        target = ReviewTarget(package_id, "r", NOW)
        down = service([]).review(session, ReviewPackage.from_content(content), target)
        dismissed = service(
            [tool_call_completion("dismiss_news", {"news_id": "N1", "reason": "No usamos OpenSSL 3.x."})]
        ).review(session, ReviewPackage.from_content(content), target)
    assert down.status is ReviewStatus.NO_JUDGE_REVIEW
    assert down.queued
    assert dismissed.alert_id is None
    assert not dismissed.queued
    with Session(engine) as session:
        assert session.get_one(m.LlmReview, dismissed.review_id).summary == "No usamos OpenSSL 3.x."
        assert session.scalars(select(m.ErrorQueue.status)).all() == ["resolved"]
        assert session.scalars(select(m.Alert)).all() == []


def test_refuted_relationships_and_inventory_come_from_the_database(engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        user_id = session.scalars(select(m.AppUser.id).limit(1)).first()
        if user_id is None:
            user = m.AppUser(
                id=new_id(),
                firebase_uid="uid-mode2",
                email="mode2@example.test",
                role="admin",
                active=True,
                created_at=NOW,
            )
            session.add(user)
            session.flush()
            user_id = user.id
        session.add(
            m.VerifiedRelationship(
                id=new_id(),
                subject="Nginx",
                relationship_type="component",
                object="OpenSSL  del sistema operativo Ubuntu",
                status="refuted",
                verified_by=user_id,
                verified_at=NOW,
            )
        )
        session.flush()
        story_id = make_story(session)
        content = candidate(story_id)
        refuted = refuted_relationships(session)
        identity = "openssl sistema operativo ubuntu"  # the stored "OpenSSL  del sistema operativo Ubuntu"
        assert refuted("component", "nginx", identity)
        assert refuted("fork", "nginx", identity)  # the same two ends, another type (pending F6.4 #83)
        assert not refuted("component", "nginx proxy manager", identity)
        responses = [
            tool_call_completion("propose_alert", ALERT, call_id="a"),
            tool_call_completion("dismiss_news", {"news_id": "N1", "reason": "Relación refutada antes."}),
        ]
        stored = service(responses).review(
            session, ReviewPackage.from_content(content), ReviewTarget(package_row(session, content), "r", NOW)
        )
        assert session.get_one(m.LlmReview, stored.review_id).calls[0]["rule"] == "L15.refuted"
        assert stored.alert_id is None
        inventory = DbInventory(session)
        payments = inventory.find_asset("CI-1")
        assert payments is not None
        assert [name for _id, name in inventory.products(payments)] == ["OpenSSL"]
        assert inventory.find_asset("CI-404") is None
        snapshot = SnapshotInventory.load(session)  # read before the model call: the same answers (F12.2 #105)
        for ci in ("CI-1", str(payments), "CI-404", str(uuid.uuid4()), ""):
            assert snapshot.find_asset(ci) == inventory.find_asset(ci)
        assert snapshot.products(payments) == inventory.products(payments)
        session.execute(text("UPDATE asset SET decommissioned_at = now() WHERE itop_ci_id = 'CI-1'"))
        assert DbInventory(session).find_asset("CI-1") is None
        assert snapshot.find_asset("CI-1") == payments  # a snapshot does not move: the write step re-checks
        assert SnapshotInventory.load(session).find_asset("CI-1") is None
        assert SnapshotInventory.load(session).find_asset(str(payments)) is None


def test_explicit_mode2_minimum_confidence_setting(engine: Engine) -> None:
    with Session(engine) as session:
        settings, _profile = load_judge_settings(session)
        assert settings.mode2_min_confidence is None  # default: follow the profile
    with Session(engine) as session, session.begin():
        session.execute(
            text(
                "INSERT INTO setting_value (setting_key, version, value, origin, changed_at) "
                "VALUES ('mode2.min_confidence', 1, '\"0.75\"', 'frontend', now())"
            )
        )
    with Session(engine) as session:
        settings, _profile = load_judge_settings(session)
        assert settings.mode2_min_confidence == Decimal("0.75")


def test_a_suspicious_candidate_stores_the_blind_review_and_raises_nothing_on_disagreement(engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        story_id = make_story(session)
        content = candidate(story_id)
        content["news"][0]["suspicious"] = True
        responses = [
            tool_call_completion("propose_alert", ALERT, call_id="a"),
            tool_call_completion("dismiss_news", {"news_id": "N1", "reason": "No aplica."}),
        ]
        stored = service(responses).review(
            session, ReviewPackage.from_content(content), ReviewTarget(package_row(session, content), "r", NOW)
        )
    assert stored.status is ReviewStatus.JUDGE_DISAGREEMENT
    assert stored.alert_id is None
    assert stored.second_review_id is not None
    with Session(engine) as session:
        assert session.get_one(m.LlmReview, stored.review_id).status == "judge_disagreement"
        assert session.get_one(m.LlmReview, stored.second_review_id).second_review_of_id == stored.review_id
        assert session.scalars(select(m.Alert)).all() == []


def test_budget_exhausted_mid_review_queues_the_candidate(engine: Engine) -> None:
    read = tool_call_completion("read_element", {"element_id": "N1"}, call_id="r")
    with Session(engine) as session, session.begin():
        story_id = make_story(session)
        content = candidate(story_id)
        stored = service([read, read], token_caps=TokenCaps(normal=20, complex=40)).review(
            session, ReviewPackage.from_content(content), ReviewTarget(package_row(session, content), "r", NOW)
        )
    assert stored.status is ReviewStatus.PARTIAL_REVIEW
    assert stored.queued
    with Session(engine) as session:
        assert session.scalars(select(m.ErrorQueue.status)).all() == ["pending"]


def test_limit_without_a_decision_queues_the_candidate(engine: Engine) -> None:
    bad = {**ALERT, "ci_id": "CI-404"}
    low = {**ALERT, "confidence": 0.1}
    responses = [
        tool_call_completion("propose_alert", bad, call_id="a"),
        tool_call_completion("propose_alert", low, call_id="b"),
        tool_call_completion("propose_alert", bad, call_id="c"),
    ]
    with Session(engine) as session, session.begin():
        story_id = make_story(session)
        content = candidate(story_id)
        stored = service(responses).review(
            session, ReviewPackage.from_content(content), ReviewTarget(package_row(session, content), "r", NOW)
        )
    assert stored.status is ReviewStatus.PARTIAL_REVIEW
    assert stored.queued
    with Session(engine) as session:
        assert session.scalars(select(m.ErrorQueue.reason)).all() == ["judge limit"]


def test_a_story_that_already_has_an_alert_gets_no_second_one(engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        story_id = make_story(session)
        existing = m.Alert(id=new_id(), story_id=story_id, relevance="R3", status="open", created_at=NOW)
        session.add(existing)
        session.flush()
        existing_id = existing.id
        content = candidate(story_id)
        stored = service([tool_call_completion("propose_alert", ALERT)]).review(
            session, ReviewPackage.from_content(content), ReviewTarget(package_row(session, content), "r", NOW)
        )
    assert stored.alert_id == existing_id


def test_the_candidate_must_be_its_stored_story(engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        story_id = make_story(session)
        other_story = make_story(session)
        content = candidate(story_id)
        package_id = package_row(session, content)
        judge = service([])  # never called
        bad_story = candidate(story_id)
        bad_story["news"][0]["story_id"] = "not-a-uuid"
        with pytest.raises(ValueError, match="story UUID"):
            judge.review(session, ReviewPackage.from_content(bad_story), ReviewTarget(None, "r", NOW))
        two = candidate(story_id)
        two["news"].append({**two["news"][0], "element_id": "N2"})
        with pytest.raises(ValueError, match="exactly one news item"):
            judge.review(session, ReviewPackage.from_content(two), ReviewTarget(None, "r", NOW))
        with pytest.raises(ValueError, match="stored package"):
            judge.review(
                session, ReviewPackage.from_content(candidate(other_story)), ReviewTarget(package_id, "r", NOW)
            )
        changed = candidate(story_id)  # same story and fingerprint, different evidence
        changed["news"][0]["summary"] += " Updated."
        with pytest.raises(ValueError, match="stored package"):
            judge.review(session, ReviewPackage.from_content(changed), ReviewTarget(package_id, "r", NOW))
        independent = candidate(story_id)
        independent["package_id"] = "pkg-independent-id"  # the package ID need not be the story ID
        independent_row = package_row_for(session, independent, story_id)
        stored = service([tool_call_completion("dismiss_news", {"news_id": "N1", "reason": "No aplica."})]).review(
            session, ReviewPackage.from_content(independent), ReviewTarget(independent_row, "r", NOW)
        )
        assert stored.status is ReviewStatus.APPLIED


def test_a_candidate_without_a_stored_package_can_be_reviewed(engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        content = candidate(make_story(session))
        stored = service([tool_call_completion("dismiss_news", {"news_id": "N1", "reason": "No aplica."})]).review(
            session, ReviewPackage.from_content(content), ReviewTarget(None, "inline", NOW)
        )
    assert (stored.status, stored.queued) == (ReviewStatus.APPLIED, False)


def staged_review(engine: Engine, content: dict[str, Any], responses: list[dict[str, Any]]) -> Any:
    """The pipeline's three steps with real commits; CI-1 is retired while the model answers."""
    with Session(engine) as session, session.begin():
        package_id = package_row(session, content)
    double = LlmDouble()
    double.add_case("case", responses)
    double.use("case")

    def retire() -> None:
        with Session(engine) as other, other.begin():
            other.execute(text("UPDATE asset SET decommissioned_at = now() WHERE itop_ci_id = 'CI-1'"))

    double.on_request = retire
    env = JudgeEnvironment(
        catalog=ReasonCatalog.default(),
        profile=SensitivityProfile.named("normal"),
        settings=JudgeSettings(),
        today=date(2026, 11, 22),
        daily_budget=UnlimitedDailyBudget(),
        price=FREE,
    )
    svc = DismissalService(double_llm_client(double), env)
    parsed = ReviewPackage.from_content(content)
    with Session(engine) as session:
        context = svc.context(session, parsed, package_id)
        session.commit()
        result = svc.evaluate(parsed, context)
        assert result.alert is not None  # the snapshot still had CI-1
        stored = svc.store(session, parsed, ReviewTarget(package_id, "r", NOW), result)
        session.commit()
    return stored


def assert_stale(engine: Engine, stored: Any) -> None:
    assert (stored.status, stored.alert_id, stored.queued) == (ReviewStatus.NO_JUDGE_REVIEW, None, True)
    with Session(engine) as session:
        review = session.get_one(m.LlmReview, stored.review_id)
        assert (review.status, review.parameters["failure"]) == ("no_judge_review", "stale")
        assert session.scalars(select(m.Alert)).all() == []
        assert session.scalars(select(m.ErrorQueue.reason)).all() == ["judge stale"]


def test_an_alert_whose_ci_was_retired_while_the_model_answered_is_not_raised(engine: Engine) -> None:
    """F12.2 #105: validated against the snapshot, re-checked when stored; the paid review is kept and queued."""
    with Session(engine) as session, session.begin():
        content = candidate(make_story(session))
    stored = staged_review(engine, content, [tool_call_completion("propose_alert", {**ALERT, "ci_id": "CI-1"})])
    assert_stale(engine, stored)


def test_a_stale_alert_agreed_by_the_blind_review_is_queued_too(engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        content = candidate(make_story(session))
    content["news"][0]["suspicious"] = True  # SEG-03: a blind second review must agree
    alert = tool_call_completion("propose_alert", {**ALERT, "ci_id": "CI-1"})
    stored = staged_review(engine, content, [alert, alert])
    assert stored.second_review_id is not None
    assert_stale(engine, stored)
