"""Judge reviews persist as one append-only audit record with their reasons and mitigation (L13, A-2)."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime
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
from core.judge.catalog import JudgeSettings, ReasonCatalog, SensitivityProfile
from core.judge.package import ReviewPackage
from core.judge.session import JudgeEnvironment, JudgeSession, ReviewOutcome, ReviewStatus
from core.judge.store import JudgeStoreError, ReviewTarget, load_judge_settings, resolve_assets, save_review
from doubles.llm import LlmDouble, tool_call_completion
from harness.judge import double_llm_client, finding_package

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]
NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)

MASS = {
    "reason_code": "mass_exploitation",
    "direction": "up",
    "points": 10,
    "evidence_id": "news-1",
    "quote": "Researchers observed mass exploitation of CVE-2026-1111",
    "explanation": "Explotación masiva reciente.",
}
CRITICAL_ASSET = {
    "reason_code": "more_critical_asset",
    "direction": "up",
    "points": 8,
    "evidence_id": "ci-2",
    "quote": "Este servidor procesa los pagos con tarjeta",
    "explanation": "El texto de iTop muestra que procesa pagos.",
}
STEP = {
    "order": 1,
    "ci_id": "CI-2",
    "action": "Actualizar Example HTTP Server a 2.4.60 o posterior.",
    "element_id": "cve-1",
    "quote": "A heap overflow in Example HTTP Server before 2.4.60 allows remote attackers",
}


@pytest.fixture
def engine(postgres_url: str) -> Iterator[Engine]:
    with provisioned_database(postgres_url, "judgestore") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        engine = make_engine_seeded(db.superuser_url)
        try:
            yield engine
        finally:
            engine.dispose()


def make_engine_seeded(url: str) -> Engine:
    engine = make_engine(url)
    with Session(engine) as session, session.begin():
        seed(session, "demo")
    return engine


def package_row(session: Session, content: dict[str, Any]) -> uuid.UUID:
    group_id = session.scalars(select(m.FindingGroup.id).limit(1)).one()
    row = m.ReviewPackage(
        id=new_id(),
        kind="finding",
        finding_group_id=group_id,
        fingerprint=content["fingerprint"],
        content=content,
        built_at=NOW,
    )
    session.add(row)
    session.flush()
    return row.id


def run(responses: list[dict[str, Any]], content: dict[str, Any] | None = None) -> ReviewOutcome:
    double = LlmDouble()
    double.add_case("case", responses)
    double.use("case")
    env = JudgeEnvironment(
        catalog=ReasonCatalog.default(),
        profile=SensitivityProfile.named("normal"),
        settings=JudgeSettings(),
        today=date(2026, 11, 22),
        daily_budget=UnlimitedDailyBudget(),
        price=FREE,
    )
    return JudgeSession(double_llm_client(double), ReviewPackage.from_content(content or finding_package()), env).run()


def test_review_with_reasons_and_mitigation_is_stored(engine: Engine) -> None:
    rejected_asset = {**CRITICAL_ASSET, "quote": "confidentiality: highly_classified", "evidence_id": "ci-1"}
    outcome = run(
        [
            tool_call_completion("propose_reason", MASS, call_id="a"),
            tool_call_completion("propose_reason", CRITICAL_ASSET, call_id="b"),
            tool_call_completion("propose_reason", rejected_asset, call_id="c"),
            tool_call_completion("finalize_review", {"summary": "Explotación masiva.", "mitigation_steps": [STEP]}),
        ]
    )
    assert outcome.status is ReviewStatus.APPLIED
    with Session(engine) as session, session.begin():
        package_id = package_row(session, finding_package())
        stored = save_review(session, outcome, ReviewTarget(package_id, f"review_package:{package_id}", NOW))
    assert not stored.queued
    with Session(engine) as session:
        review = session.get_one(m.LlmReview, stored.review_id)
        assert (review.agent, review.mode, review.status) == ("judge", "scoring", "applied")
        assert review.review_package_id == package_id
        assert review.proposed_adjustment == 10
        assert review.mitigation_status == "accepted"
        assert review.summary == "Explotación masiva."
        assert len(review.calls) == 4
        assert review.calls[2]["result"] == "rejected"
        assert review.tokens_input == 40
        assert review.prompt_version == "judge-mode1-v1"
        assert review.parameters["failure"] is None
        reasons = session.scalars(
            select(m.JudgeReason).where(m.JudgeReason.llm_review_id == review.id).order_by(m.JudgeReason.seq)
        ).all()
        assets = dict(session.execute(select(m.Asset.itop_ci_id, m.Asset.id)).all())
        assert [(r.seq, r.reason_code, r.status, r.points) for r in reasons] == [
            (1, "mass_exploitation", "accepted", 10),
            (2, "more_critical_asset", "accepted", 8),
            (3, "more_critical_asset", "rejected", 8),
        ]
        assert reasons[1].asset_id == assets["CI-2"]
        assert reasons[2].asset_id == assets["CI-1"]
        assert reasons[2].rejection_rule == "L4.repeated"
        steps = session.scalars(select(m.MitigationDraftStep).where(m.MitigationDraftStep.llm_review_id == review.id))
        assert [(s.step_order, s.asset_id, s.element_id) for s in steps] == [(1, assets["CI-2"], "cve-1")]


def test_rejected_more_critical_asset_without_a_ci_stays_only_in_calls(engine: Engine) -> None:
    rejected_news = {**CRITICAL_ASSET, "evidence_id": "news-1", "quote": MASS["quote"]}
    outcome = run(
        [
            tool_call_completion("propose_reason", rejected_news, call_id="a"),
            tool_call_completion("finalize_review", {"summary": "Sin motivos.", "mitigation_steps": []}),
        ]
    )
    with Session(engine) as session, session.begin():
        stored = save_review(session, outcome, ReviewTarget(None, "inline", NOW))
    with Session(engine) as session:
        assert session.scalars(select(m.JudgeReason).where(m.JudgeReason.llm_review_id == stored.review_id)).all() == []
        review = session.get_one(m.LlmReview, stored.review_id)
        assert review.calls[0]["rule"] == "L4.more_critical_asset"
        assert review.mitigation_status == "absent"


def test_fallback_is_stored_and_queued(engine: Engine) -> None:
    outcome = run([])  # API down
    assert outcome.status is ReviewStatus.NO_JUDGE_REVIEW
    with Session(engine) as session, session.begin():
        package_id = package_row(session, finding_package())
        stored = save_review(session, outcome, ReviewTarget(package_id, "ref", NOW))
    assert stored.queued
    with Session(engine) as session:
        review = session.get_one(m.LlmReview, stored.review_id)
        assert review.status == "no_judge_review"
        assert review.proposed_adjustment is None
        assert review.parameters["failure"] == "transport"
        queue = session.scalars(select(m.ErrorQueue).where(m.ErrorQueue.review_package_id == package_id)).one()
        assert (queue.component, queue.status, queue.reason) == ("judge", "pending", "judge transport")


def test_second_review_is_linked_and_never_queued(engine: Engine) -> None:
    first = run([tool_call_completion("finalize_review", {"summary": "Uno.", "mitigation_steps": []})])
    second = run([])
    with Session(engine) as session, session.begin():
        package_id = package_row(session, finding_package())
        target = ReviewTarget(package_id, "ref", NOW)
        one = save_review(session, first, target, status=ReviewStatus.JUDGE_DISAGREEMENT)
        two = save_review(session, second, target, second_review_of=one.review_id)
    assert not two.queued
    with Session(engine) as session:
        assert session.get_one(m.LlmReview, one.review_id).status == "judge_disagreement"
        assert session.get_one(m.LlmReview, two.review_id).second_review_of_id == one.review_id
        assert session.scalars(select(m.ErrorQueue)).all() == []


def test_unknown_cited_ci_cannot_be_stored(engine: Engine) -> None:
    content = finding_package()
    content["group"]["cis"][1]["ci_id"] = "CI-404"
    outcome = run(
        [
            tool_call_completion("propose_reason", CRITICAL_ASSET, call_id="a"),
            tool_call_completion("finalize_review", {"summary": "Uno.", "mitigation_steps": []}),
        ],
        content,
    )
    with Session(engine) as session, pytest.raises(JudgeStoreError, match="more_critical_asset"):
        save_review(session, outcome, ReviewTarget(None, "ref", NOW))
    step_only = run(
        [
            tool_call_completion(
                "finalize_review", {"summary": "Uno.", "mitigation_steps": [{**STEP, "ci_id": "CI-404"}]}
            )
        ],
        content,
    )
    with Session(engine) as session, pytest.raises(JudgeStoreError, match="mitigation step"):
        save_review(session, step_only, ReviewTarget(None, "ref", NOW))


def test_assets_resolve_by_itop_id_or_uuid(engine: Engine) -> None:
    with Session(engine) as session:
        payments = session.scalars(select(m.Asset).where(m.Asset.itop_ci_id == "CI-1")).one()
        resolved = resolve_assets(session, ["CI-1", str(payments.id), "CI-404", str(uuid.uuid4()), ""])
        assert resolved == {"CI-1": payments.id, str(payments.id): payments.id}
        assert resolve_assets(session, [""]) == {}


def test_settings_come_from_setting_current(engine: Engine) -> None:
    with Session(engine) as session:
        settings, profile = load_judge_settings(session)
        assert (settings.model, settings.max_calls, settings.double_review_threshold) == ("deepseek-v4-pro", 8, 15)
        assert profile.name.value == "normal"
    with Session(engine) as session, session.begin():
        session.execute(
            text(
                "INSERT INTO setting_value (setting_key, version, value, origin, changed_at) VALUES "
                "('sensitivity_profile', 1, '\"minimal\"', 'frontend', now()), "
                "('double_review_threshold', 1, '12', 'frontend', now())"
            )
        )
    with Session(engine) as session:
        settings, profile = load_judge_settings(session)
        assert settings.double_review_threshold == 12
        assert profile.name.value == "minimal"
