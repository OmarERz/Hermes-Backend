"""Judge reviews persist as one append-only audit record with their reasons and mitigation (L13, A-2)."""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
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
from core.judge.session import Failure, JudgeEnvironment, JudgeSession, ReviewOutcome, ReviewStatus
from core.judge.store import (
    ReviewTarget,
    load_judge_settings,
    resolve_assets,
    save_review,
    sync_error_queue,
)
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
        review_id = save_review(session, outcome, ReviewTarget(package_id, f"review_package:{package_id}", NOW))
    with Session(engine) as session:
        review = session.get_one(m.LlmReview, review_id)
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
        review_id = save_review(session, outcome, ReviewTarget(None, "inline", NOW))
    with Session(engine) as session:
        assert session.scalars(select(m.JudgeReason).where(m.JudgeReason.llm_review_id == review_id)).all() == []
        review = session.get_one(m.LlmReview, review_id)
        assert review.calls[0]["rule"] == "L5.asset"  # a CI reason that cites no CI (pending F6.1 #64)
        assert review.mitigation_status == "absent"


def test_fallback_is_stored(engine: Engine) -> None:
    outcome = run([])  # API down
    assert outcome.status is ReviewStatus.NO_JUDGE_REVIEW
    with Session(engine) as session, session.begin():
        package_id = package_row(session, finding_package())
        review_id = save_review(session, outcome, ReviewTarget(package_id, "ref", NOW))
    with Session(engine) as session:
        review = session.get_one(m.LlmReview, review_id)
        assert review.status == "no_judge_review"
        assert review.proposed_adjustment is None
        assert review.parameters["failure"] == "transport"


@pytest.mark.parametrize(
    ("failure", "queued"),
    [
        (Failure.TRANSPORT, True),
        (Failure.REQUEST, True),
        (Failure.FORMAT, True),
        (Failure.BUDGET, True),
        (Failure.LADDER, False),
        (Failure.LIMIT, True),  # only mode 2 passes it: limits without a decision
        (None, False),
    ],
)
def test_which_failures_are_queued(engine: Engine, failure: Failure | None, queued: bool) -> None:
    with Session(engine) as session, session.begin():
        package_id = package_row(session, finding_package())
        assert sync_error_queue(session, package_id, failure, NOW) is queued
        rows = session.scalars(select(m.ErrorQueue).where(m.ErrorQueue.review_package_id == package_id)).all()
        assert len(rows) == int(queued)
        if queued:
            assert (rows[0].component, rows[0].status, rows[0].attempts) == ("judge", "pending", 0)
            assert rows[0].reason == f"judge {failure}"
        assert sync_error_queue(session, None, failure, NOW) is False


def later(hours: int) -> datetime:
    """The `now` of a later run."""
    return NOW + timedelta(hours=hours)


def test_queue_counts_attempts_gives_up_and_resolves(engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        package_id = package_row(session, finding_package())
        assert sync_error_queue(session, package_id, Failure.TRANSPORT, NOW)
        assert sync_error_queue(session, package_id, Failure.TRANSPORT, NOW)  # same run: still attempt 0
        assert sync_error_queue(session, package_id, Failure.FORMAT, later(1))  # next run: attempt 1
        assert not sync_error_queue(session, package_id, Failure.TRANSPORT, later(2))  # attempt 2: given up
        entry = session.scalars(select(m.ErrorQueue).where(m.ErrorQueue.review_package_id == package_id)).one()
        assert (entry.attempts, entry.status, entry.reason) == (2, "gave_up", "judge transport")
        other = package_row(session, finding_package())
        sync_error_queue(session, other, Failure.TRANSPORT, NOW)
        sync_error_queue(session, other, Failure.LADDER, NOW)  # skipped on purpose: still pending
        assert sync_error_queue(session, other, None, NOW) is False  # an answer resolves it
        resolved = session.scalars(select(m.ErrorQueue).where(m.ErrorQueue.review_package_id == other)).one()
        assert resolved.status == "resolved"


def test_a_given_up_entry_stays_single_and_is_resolved_by_a_later_success(engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        package_id = package_row(session, finding_package())
        for hours in range(3):
            sync_error_queue(session, package_id, Failure.TRANSPORT, later(hours))
        assert not sync_error_queue(session, package_id, Failure.FORMAT, later(3))  # still given up, no new row
        entries = session.scalars(select(m.ErrorQueue).where(m.ErrorQueue.review_package_id == package_id)).all()
        assert [(e.status, e.attempts, e.reason) for e in entries] == [("gave_up", 2, "judge format")]
        assert not sync_error_queue(session, package_id, None, NOW)
        assert entries[0].status == "resolved"
        assert sync_error_queue(session, package_id, Failure.TRANSPORT, NOW)  # a new outage opens a new entry


def test_second_review_is_linked(engine: Engine) -> None:
    first = run([tool_call_completion("finalize_review", {"summary": "Uno.", "mitigation_steps": []})])
    second = run([])
    with Session(engine) as session, session.begin():
        package_id = package_row(session, finding_package())
        target = ReviewTarget(package_id, "ref", NOW)
        one = save_review(session, first, target, status=ReviewStatus.JUDGE_DISAGREEMENT)
        two = save_review(session, second, target, second_review_of=one)
    with Session(engine) as session:
        assert session.get_one(m.LlmReview, one).status == "judge_disagreement"
        assert session.get_one(m.LlmReview, two).second_review_of_id == one
        assert session.scalars(select(m.ErrorQueue)).all() == []


def test_a_ci_missing_from_the_inventory_never_loses_the_paid_review(engine: Engine) -> None:
    """F6.1 #69: the CI left the inventory while the model answered; the review (tokens, cost) is still stored."""
    content = finding_package()
    content["group"]["cis"][1]["ci_id"] = "CI-404"
    outcome = run(
        [
            tool_call_completion("propose_reason", MASS, call_id="m"),
            tool_call_completion("propose_reason", CRITICAL_ASSET, call_id="a"),
            tool_call_completion(
                "finalize_review", {"summary": "Uno.", "mitigation_steps": [{**STEP, "ci_id": "CI-404"}]}
            ),
        ],
        content,
    )
    assert [r.status for r in outcome.reasons] == ["accepted", "accepted"]
    assert outcome.mitigation.status.value == "accepted"
    with Session(engine) as session, session.begin():
        review_id = save_review(session, outcome, ReviewTarget(None, "ref", NOW))
    with Session(engine) as session:
        review = session.get_one(m.LlmReview, review_id)
        assert (review.status, review.tokens_input, review.attempts) == ("applied", 30, 3)
        assert (review.mitigation_status, review.mitigation_discard_rule) == ("discarded", "JUE-MIT-04")
        reasons = session.scalars(select(m.JudgeReason).where(m.JudgeReason.llm_review_id == review_id)).all()
        assert [r.reason_code for r in reasons] == ["mass_exploitation"]  # the CI-less one stays only in calls
        assert [c["tool"] for c in review.calls] == ["propose_reason", "propose_reason", "finalize_review"]
        steps = session.scalars(
            select(m.MitigationDraftStep).where(m.MitigationDraftStep.llm_review_id == review_id)
        ).all()
        assert steps == []


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


def test_two_concurrent_failures_create_one_queue_entry(engine: Engine) -> None:

    with Session(engine) as session, session.begin():
        package_id = package_row(session, finding_package())
    first = Session(engine)
    first.begin()
    assert sync_error_queue(first, package_id, Failure.TRANSPORT, NOW)  # holds the package lock until commit
    done: list[bool] = []

    def second() -> None:
        with Session(engine) as other, other.begin():
            done.append(sync_error_queue(other, package_id, Failure.TRANSPORT, NOW))

    worker = threading.Thread(target=second)
    worker.start()
    worker.join(timeout=1)
    assert worker.is_alive()  # blocked by the advisory lock
    first.commit()
    first.close()
    worker.join(timeout=10)
    assert done == [True]
    with Session(engine) as session:
        entries = session.scalars(select(m.ErrorQueue).where(m.ErrorQueue.review_package_id == package_id)).all()
        assert [(e.status, e.attempts) for e in entries] == [("pending", 0)]  # same run: one attempt


def test_runs_finishing_out_of_order_each_count_once(engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        package_id = package_row(session, finding_package())
        sync_error_queue(session, package_id, Failure.TRANSPORT, NOW)
        assert sync_error_queue(session, package_id, Failure.TRANSPORT, later(2))  # run at +2h: attempt 1
        assert sync_error_queue(session, package_id, Failure.TRANSPORT, later(2))  # the same run again: no attempt
        assert not sync_error_queue(session, package_id, Failure.TRANSPORT, later(1))  # late +1h run: attempt 2
        entry = session.scalars(select(m.ErrorQueue).where(m.ErrorQueue.review_package_id == package_id)).one()
        assert (entry.attempts, entry.status) == (2, "gave_up")
