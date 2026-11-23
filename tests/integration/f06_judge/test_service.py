"""The judge service stores the first review with the final status and links the blind second review (L10, L13)."""

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
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id
from core.db.seeds import seed
from core.db.session import make_engine
from core.judge.budget import FREE, UnlimitedDailyBudget
from core.judge.catalog import JudgeSettings, ReasonCatalog, SensitivityProfile
from core.judge.package import ReviewPackage
from core.judge.service import JudgeService
from core.judge.session import Failure, JudgeEnvironment, ReviewStatus
from core.judge.store import ReviewTarget, sync_error_queue
from doubles.llm import LlmDouble, tool_call_completion
from harness.judge import double_llm_client, finding_package

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]
NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
MASS = {
    "reason_code": "mass_exploitation",
    "direction": "up",
    "points": 18,
    "evidence_id": "news-1",
    "quote": "Researchers observed mass exploitation of CVE-2026-1111",
    "explanation": "Explotación masiva reciente.",
}
AUTH = {
    "reason_code": "requires_authentication",
    "direction": "down",
    "points": -5,
    "evidence_id": "cve-1",
    "quote": "Successful exploitation requires the mod_proxy module",
    "explanation": "Requiere un módulo opcional.",
}


@pytest.fixture
def engine(postgres_url: str) -> Iterator[Engine]:
    with provisioned_database(postgres_url, "judgesvc") as db:
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


def service(responses: list[dict[str, Any]]) -> JudgeService:
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
    return JudgeService(double_llm_client(double), env)


def finalize() -> dict[str, Any]:
    return tool_call_completion("finalize_review", {"summary": "Resumen.", "mitigation_steps": []}, call_id="f")


def test_disagreement_is_stored_on_both_reviews(engine: Engine) -> None:
    responses = [
        tool_call_completion("propose_reason", MASS, call_id="a"),
        finalize(),
        tool_call_completion("propose_reason", AUTH, call_id="b"),
        finalize(),
    ]
    content = finding_package()
    with Session(engine) as session, session.begin():
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
        stored = service(responses).review(
            session, ReviewPackage.from_content(content), ReviewTarget(row.id, f"review_package:{row.id}", NOW)
        )
    assert stored.result.status is ReviewStatus.JUDGE_DISAGREEMENT
    assert stored.result.adjustment == 0
    assert stored.second_review_id is not None
    assert not stored.queued
    with Session(engine) as session:
        first = session.get_one(m.LlmReview, stored.review_id)
        second = session.get_one(m.LlmReview, stored.second_review_id)
        assert (first.status, first.proposed_adjustment) == ("judge_disagreement", 18)
        assert (second.status, second.proposed_adjustment, second.second_review_of_id) == ("applied", -5, first.id)


def test_single_review_without_double_review(engine: Engine) -> None:
    responses = [tool_call_completion("propose_reason", {**MASS, "points": 10}, call_id="a"), finalize()]
    with Session(engine) as session, session.begin():
        stored = service(responses).review(
            session, ReviewPackage.from_content(finding_package()), ReviewTarget(None, "inline", NOW)
        )
    assert stored.second_review_id is None
    assert stored.result.adjustment == 10
    with Session(engine) as session:
        assert session.get_one(m.LlmReview, stored.review_id).status == "applied"


def test_a_failed_second_review_queues_the_package(engine: Engine) -> None:
    step = {
        "order": 1,
        "ci_id": "",
        "action": "Actualizar Example HTTP Server a 2.4.60 o posterior.",
        "element_id": "cve-1",
        "quote": "A heap overflow in Example HTTP Server before 2.4.60 allows remote attackers",
    }
    drafted = tool_call_completion("finalize_review", {"summary": "Resumen.", "mitigation_steps": [step]})
    responses = [tool_call_completion("propose_reason", MASS, call_id="a"), drafted]  # nothing for the second
    content = finding_package()
    with Session(engine) as session, session.begin():
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
        stored = service(responses).review(session, ReviewPackage.from_content(content), ReviewTarget(row.id, "r", NOW))
    assert stored.result.status is ReviewStatus.NO_JUDGE_REVIEW
    assert stored.result.failure is Failure.TRANSPORT
    assert stored.queued
    with Session(engine) as session:
        first = session.get_one(m.LlmReview, stored.review_id)
        assert first.status == "no_judge_review"
        assert first.parameters["failure"] == "transport"  # the cause is on the main L13 record too
        assert first.mitigation_status == "absent"  # JUE-MIT-09: no drafted mitigation without the judge
        assert session.scalars(select(m.MitigationDraftStep)).all() == []
        assert session.scalars(select(m.ErrorQueue.status)).all() == ["pending"]


STEP = {
    "order": 1,
    "ci_id": "",
    "action": "Actualizar Example HTTP Server a 2.4.60 o posterior.",
    "element_id": "cve-1",
    "quote": "A heap overflow in Example HTTP Server before 2.4.60 allows remote attackers",
}


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


def test_a_stale_double_review_is_stored_as_not_applied(engine: Engine) -> None:
    """F12.2 #105: the package changed while the model answered; both reviews are kept, neither looks applied, and
    an earlier failure of that package is resolved without queueing anything new."""
    drafted = tool_call_completion("finalize_review", {"summary": "Resumen.", "mitigation_steps": [STEP]})
    mass = tool_call_completion("propose_reason", MASS, call_id="a")
    content = finding_package()
    judge = service([mass, drafted, mass, drafted])  # +18: a blind second review that agrees
    result = judge.evaluate(ReviewPackage.from_content(content))
    assert (result.status, result.second is not None) == (ReviewStatus.APPLIED, True)
    with Session(engine) as session, session.begin():
        row_id = package_row(session, content)
        sync_error_queue(session, row_id, Failure.TRANSPORT, NOW)  # an earlier run failed on this package
        stored = judge.store(session, ReviewTarget(row_id, "r", NOW), result, stale=True)
    assert (stored.result.status, stored.result.adjustment, stored.queued) == (
        ReviewStatus.NO_JUDGE_REVIEW,
        None,
        False,
    )
    assert stored.second_review_id is not None
    with Session(engine) as session:
        first = session.get_one(m.LlmReview, stored.review_id)
        second = session.get_one(m.LlmReview, stored.second_review_id)
        assert (first.status, first.parameters["failure"], first.mitigation_status) == (
            "no_judge_review",
            "stale",
            "absent",
        )
        assert (second.status, second.parameters["failure"], second.mitigation_status) == (
            "no_judge_review",
            "stale",
            "absent",
        )
        steps = session.scalars(select(m.MitigationDraftStep)).all()
        assert steps == []  # JUE-MIT-09: no draft from a review that never reached a score
        assert session.scalars(select(m.ErrorQueue.status)).all() == ["resolved"]


def test_a_stale_review_that_failed_keeps_its_real_cause(engine: Engine) -> None:
    judge = service([])  # the provider is down
    content = finding_package()
    result = judge.evaluate(ReviewPackage.from_content(content))
    with Session(engine) as session, session.begin():
        row_id = package_row(session, content)
        stored = judge.store(session, ReviewTarget(row_id, "r", NOW), result, stale=True)
    assert not stored.queued
    with Session(engine) as session:
        review = session.get_one(m.LlmReview, stored.review_id)
        assert (review.status, review.parameters["failure"]) == ("no_judge_review", "transport")  # L13
        assert session.scalars(select(m.ErrorQueue)).all() == []  # the outdated package is not queued


def test_a_stale_review_whose_blind_review_failed_keeps_that_cause(engine: Engine) -> None:
    drafted = tool_call_completion("finalize_review", {"summary": "Resumen.", "mitigation_steps": [STEP]})
    judge = service([tool_call_completion("propose_reason", MASS, call_id="a"), drafted])  # nothing for the second
    content = finding_package()
    result = judge.evaluate(ReviewPackage.from_content(content))
    assert (result.adjustment, result.failure) == (None, Failure.TRANSPORT)
    with Session(engine) as session, session.begin():
        stored = judge.store(session, ReviewTarget(package_row(session, content), "r", NOW), result, stale=True)
    assert stored.second_review_id is not None
    with Session(engine) as session:
        for review_id in (stored.review_id, stored.second_review_id):
            review = session.get_one(m.LlmReview, review_id)
            assert (review.status, review.parameters["failure"]) == ("no_judge_review", "transport")
        assert session.scalars(select(m.ErrorQueue)).all() == []
