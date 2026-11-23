"""Supervised calibration against PostgreSQL: claim resolution, proposals, the weekly job and the decision routes."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from api.app import create_app
from api.auth import CurrentUser, Role, get_current_user
from core.calibration.claims import resolve_claims
from core.calibration.proposals import Decider, _blocked_keys, approve, reject, run_weekly
from core.calibration.settings import load_settings
from core.calibration.weights import MIN_CASES, best_candidate, load_cases, shifted, ticket_final
from core.config import Settings
from core.configuration import formula_store
from core.configuration.errors import ConflictError, ForbiddenParameterError, NotFoundError
from core.db import models as m
from core.db.seeds import NOW, seed
from core.scoring.engine import default_formula
from core.scoring.formula_repo import load_active_formula
from workers.jobs import WeeklyCalibrationJob

pytestmark = pytest.mark.integration
LATER = NOW + timedelta(days=1)
APPS: dict[int, Any] = {}


# --- fixtures ------------------------------------------------------------------------------------------------
@pytest.fixture
def world(engine: Engine) -> Engine:
    with Session(engine) as session, session.begin():
        seed(session, "demo")
        session.add(m.AppUser(firebase_uid="u1", email="u1@example.com", role="admin", active=True, created_at=NOW))
    return engine


def run(engine: Engine, statement: str, params: dict[str, Any] | None = None) -> None:
    with engine.begin() as conn:
        conn.execute(text(statement), params or {})


def rows(engine: Engine, statement: str) -> list[tuple[Any, ...]]:
    with engine.connect() as conn:
        return [tuple(r) for r in conn.execute(text(statement))]


def new_analysis(session: Session) -> uuid.UUID:
    """A news analysis for claims to hang from (the claim table needs one)."""
    scan = session.scalars(text("SELECT id FROM run LIMIT 1")).one()
    source = m.Source(
        code=f"feed_{uuid.uuid4().hex[:6]}",
        name="Fetcher",
        kind="rss",
        url="https://feed.example.test/rss",
        trust_tier="N4",
        is_structural=False,
        is_custom=True,
        enabled=True,
        created_at=NOW,
    )
    session.add(source)
    session.flush()
    fetch = m.SourceFetch(source_id=source.id, run_id=scan, started_at=NOW, status="ok", items_new=1)
    session.add(fetch)
    session.flush()
    article = m.RawArticle(
        source_fetch_id=fetch.id,
        canonical_url=f"https://news.example/{uuid.uuid4().hex}",
        title="t",
        published_at=NOW,
        captured_at=NOW,
        is_suspicious=False,
    )
    session.add(article)
    session.flush()
    story = m.Story(representative_article_id=article.id, relevance_status="relevant", created_at=NOW)
    session.add(story)
    session.flush()
    review = m.LlmReview(
        agent="news_analyst",
        model="m",
        response_model={},
        prompt_version="1",
        prompt_hash="h",
        schema_version="1",
        schema_hash="h",
        parameters={},
        input_ref="x",
        calls=[],
        status="applied",
        attempts=1,
        tokens_input=0,
        tokens_cached=0,
        tokens_output=0,
        tokens_reasoning=0,
        cost_usd=Decimal(0),
        latency_ms=1,
        ladder_level=0,
        created_at=NOW,
    )
    session.add(review)
    session.flush()
    analysis = m.NewsAnalysis(
        story_id=story.id, llm_review_id=review.id, summary="s", event_type="e", output={}, created_at=NOW
    )
    session.add(analysis)
    session.flush()
    return analysis.id


def add_source(engine: Engine, code: str, tier: str, *, structural: bool = False) -> uuid.UUID:
    source_id = uuid.uuid4()
    run(
        engine,
        "INSERT INTO source (id, code, name, kind, url, trust_tier, is_structural, is_custom, enabled, created_at) "
        "VALUES (:i, :c, :c, 'rss', 'https://feed.example.test/rss', :t, :s, :cu, true, now())",
        {"i": source_id, "c": code, "t": tier, "s": structural, "cu": not structural},
    )
    return source_id


def add_claims(engine: Engine, source_id: uuid.UUID, confirmed: int, refuted: int, *, resolved_at: Any = NOW) -> None:
    with Session(engine) as session, session.begin():
        analysis = new_analysis(session)
        for status, count in (("confirmed", confirmed), ("refuted", refuted)):
            for _ in range(count):
                session.add(
                    m.Claim(
                        analysis_id=analysis,
                        source_id=source_id,
                        claim_type="active_exploitation",
                        cve_id=None,
                        claimed_at=NOW - timedelta(days=30),
                        status=status,
                        resolved_at=resolved_at,
                    )
                )


def weekly(engine: Engine, now: Any = LATER, *, force: bool = False) -> Any:
    with Session(engine) as session, session.begin():
        return run_weekly(session, now, force=force)


# --- claim resolution ------------------------------------------------------------------------------------------
def test_claims_resolve_from_kev_exploit_references_vector_and_feedback(world: Engine) -> None:
    cve = "CVE-2026-10001"  # in KEV since 2026-11-15 (demo seed)
    source = add_source(world, "blog", "N3")
    run(world, "UPDATE cve SET cvss_vector = 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' WHERE id = :c", {"c": cve})
    run(
        world,
        "INSERT INTO cve_reference (id, cve_id, url) VALUES (gen_random_uuid(), :c, 'https://x.example/poc')",
        {"c": cve},
    )
    run(world, "INSERT INTO cve_reference_tag (reference_id, tag) SELECT id, 'Exploit' FROM cve_reference")
    with Session(world) as session, session.begin():
        analysis = new_analysis(session)
        kinds = ["active_exploitation", "public_poc", "requires_authentication", "used_in_assessment"]
        for kind in kinds:
            session.add(
                m.Claim(
                    analysis_id=analysis,
                    source_id=source,
                    claim_type=kind,
                    cve_id=cve,
                    claimed_at=NOW - timedelta(days=20),
                    status="pending",
                )
            )
        session.add(
            m.Claim(
                analysis_id=analysis,
                source_id=source,
                claim_type="active_exploitation",
                cve_id=cve,
                claimed_at=NOW - timedelta(days=400),
                status="pending",
            )
        )
    with Session(world) as session, session.begin():
        first = resolve_claims(session, LATER)
    states = dict(rows(world, "SELECT claim_type || claimed_at::date::text, status FROM claim"))
    assert first.confirmed == 3 and first.refuted == 0  # KEV, PoC and PR:L; the feedback claim waits
    assert (
        sum(1 for s in states.values() if s == "pending") == 2
    )  # feedback claim and the claim that predates KEV by 400 d


def test_feedback_resolves_used_in_assessment_and_the_vector_can_refute(world: Engine) -> None:
    cve = "CVE-2026-10001"
    source = add_source(world, "blog", "N3")
    run(world, "UPDATE cve SET cvss_vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' WHERE id = :c", {"c": cve})
    group = rows(world, "SELECT id FROM finding_group")[0][0]
    formula = rows(world, "SELECT id FROM formula_version WHERE status = 'active'")[0][0]
    scan = rows(world, "SELECT id FROM run")[0][0]
    user = rows(world, "SELECT id FROM app_user")[0][0]
    assessment = uuid.uuid4()
    run(
        world,
        'INSERT INTO assessment (id, finding_group_id, run_id, formula_version_id, "trigger", factor_s, factor_p, '
        "factor_t, judge_adjustment, assessed_at) VALUES (:i, :g, :r, :f, 'new_finding', 0.5, 0.5, 0.5, 0, :at)",
        {"i": assessment, "g": group, "r": scan, "f": formula, "at": NOW},
    )
    for verdict, at in (("relevant", NOW), ("false_positive", NOW + timedelta(hours=1))):
        run(
            world,
            "INSERT INTO feedback (assessment_id, app_user_id, channel, verdict, created_at, superseded_at) "
            "VALUES (:a, :u, 'frontend', :v, :at, CASE WHEN :v = 'relevant' THEN :at2 END)",
            {"a": assessment, "u": user, "v": verdict, "at": at, "at2": at + timedelta(minutes=1)},
        )
    with Session(world) as session, session.begin():
        analysis = new_analysis(session)
        for kind in ("used_in_assessment", "requires_authentication"):
            session.add(
                m.Claim(
                    analysis_id=analysis,
                    source_id=source,
                    claim_type=kind,
                    cve_id=cve,
                    claimed_at=NOW,
                    status="pending",
                )
            )
        resolved = resolve_claims(session, LATER)
    assert (
        resolved.refuted == 2 and resolved.confirmed == 0
    )  # the latest feedback is a false positive; PR:N refutes auth
    assert rows(world, "SELECT count(*) FROM claim WHERE status = 'pending'") == [(0,)]


# --- source level proposals --------------------------------------------------------------------------------------
def test_source_levels_move_one_step_with_enough_evidence(world: Engine) -> None:
    good = add_source(world, "good_blog", "N3")
    bad = add_source(world, "bad_blog", "N2")
    few = add_source(world, "few_claims", "N3")
    top = add_source(world, "top_blog", "N2")
    structural = add_source(world, "nvd_like", "N1", structural=True)
    add_claims(world, good, 30, 0)  # (30+2)/(30+4) = 0.94: raise N3 -> N2
    add_claims(world, bad, 3, 20)  # (3+2)/(23+4) = 0.19: lower N2 -> N3
    add_claims(world, few, 10, 0)  # fewer than 20 resolved: nothing
    add_claims(world, top, 40, 0)  # already N2: never proposed to N1
    add_claims(world, structural, 0, 40)  # structural sources are never touched
    result = weekly(world)
    assert len(result.created) == 2
    found = {
        r[0]: r[1:]
        for r in rows(
            world,
            "SELECT target_key, target_kind, previous_value ->> 'trust_tier', proposed_value ->> 'trust_tier', "
            "status FROM calibration_proposal",
        )
    }
    assert found == {
        "source:good_blog": ("source_trust", "N3", "N2", "proposed"),
        "source:bad_blog": ("source_trust", "N2", "N3", "proposed"),
    }
    evidence = rows(world, "SELECT evidence FROM calibration_proposal WHERE target_key = 'source:good_blog'")[0][0]
    assert "30 afirmaciones confirmadas" in evidence and "0.94" in evidence


def test_old_claims_do_not_count(world: Engine) -> None:
    source = add_source(world, "stale_blog", "N3")
    add_claims(world, source, 30, 0, resolved_at=NOW - timedelta(days=400))
    assert weekly(world).created == []


# --- weight proposals ---------------------------------------------------------------------------------------------
def seed_feedback(engine: Engine, count: int, wanted_weights: dict[str, Decimal] | None) -> None:
    """`count` wrong-priority feedbacks; the score people wanted is what a formula with `wanted_weights` gives."""
    group = rows(engine, "SELECT id FROM finding_group")[0][0]
    assets = [r[0] for r in rows(engine, "SELECT id FROM asset ORDER BY name")]
    formula_id = rows(engine, "SELECT id FROM formula_version WHERE status = 'active'")[0][0]
    scan = rows(engine, "SELECT id FROM run")[0][0]
    for n in range(count):
        user, assessment = uuid.uuid4(), uuid.uuid4()
        run(
            engine,
            "INSERT INTO app_user (id, firebase_uid, email, role, active, created_at) "
            "VALUES (:i, :u, :e, 'analyst', true, now())",
            {"i": user, "u": f"fb{user}", "e": f"fb{user}@example.com"},
        )
        factors = {
            "s": Decimal("0.3") + Decimal(n % 5) / 10,
            "p": Decimal("0.95") - Decimal(n % 3) / 10,
            "t": Decimal("0.2") + Decimal(n % 4) / 10,
        }
        run(
            engine,
            'INSERT INTO assessment (id, finding_group_id, run_id, formula_version_id, "trigger", factor_s, '
            "factor_p, factor_t, judge_adjustment, raw_in_kev, assessed_at) "
            "VALUES (:i, :g, :r, :f, 'new_finding', :s, :p, :t, 0, false, :at)",
            {"i": assessment, "g": group, "r": scan, "f": formula_id, "at": NOW, **factors},
        )
        for asset in assets:
            run(
                engine,
                "INSERT INTO asset_score (assessment_id, asset_id, factor_a, factor_d, version_factor, base, "
                "ci_adjustment, final, snap_criticality, snap_confidentiality, snap_exposed) "
                "VALUES (:a, :s, 0.6, 0.5, 1, 50, 0, 50, 'high', 'classified', false)",
                {"a": assessment, "s": asset},
            )
        run(
            engine,
            "INSERT INTO feedback (assessment_id, app_user_id, channel, verdict, proposed_level, proposed_score, "
            "created_at) VALUES (:a, :u, 'frontend', 'wrong_priority', 'high', 50, :at)",
            {"a": assessment, "u": user, "at": NOW},
        )
    if wanted_weights is not None:
        with Session(engine) as session, session.begin():
            _, formula = load_active_formula(session)
            wanted = replace(formula, weights=wanted_weights)
            ids = [r[0] for r in session.execute(text("SELECT id FROM feedback ORDER BY id"))]
            for feedback_id, case in zip(ids, load_cases(session, LATER), strict=True):
                session.execute(
                    text("UPDATE feedback SET proposed_score = :w WHERE id = :i"),
                    {"w": ticket_final(wanted, case), "i": feedback_id},
                )


def active_weights(engine: Engine) -> dict[str, Decimal]:
    with Session(engine) as session:
        return dict(load_active_formula(session)[1].weights)


def heavier_p(engine: Engine, relative: str = "0.10") -> dict[str, Decimal]:
    weights = shifted(active_weights(engine), "P", Decimal(relative))
    assert weights is not None
    return weights


def test_feedback_that_prefers_a_heavier_p_weight_makes_a_weight_proposal(world: Engine) -> None:
    weights = active_weights(world)
    seed_feedback(world, MIN_CASES, heavier_p(world))
    result = weekly(world)
    assert len(result.created) == 1
    key, kind, status, previous, proposed, backtest = rows(
        world,
        "SELECT target_key, target_kind, status, previous_value, proposed_value, backtest FROM calibration_proposal",
    )[0]
    assert (key, kind, status) == ("weights.P", "weight", "proposed")
    assert Decimal(proposed["weights.P"]) > Decimal(previous["weights.P"])
    assert sum(Decimal(v) for v in proposed.values()) == 1
    assert backtest["cases"] == MIN_CASES and Decimal(backtest["mae_after"]) < Decimal(backtest["mae_before"])
    assert active_weights(world) == weights  # a proposal changes nothing by itself
    assert rows(world, "SELECT kind, status FROM run WHERE kind = 'mode4'") == [("mode4", "succeeded")]


def test_a_weight_change_never_exceeds_the_weekly_limit(world: Engine) -> None:
    seed_feedback(world, MIN_CASES, heavier_p(world, "0.40"))
    weekly(world)
    previous, proposed = rows(world, "SELECT previous_value, proposed_value FROM calibration_proposal")[0]
    assert Decimal(proposed["weights.P"]) <= Decimal(previous["weights.P"]) * Decimal("1.10") + Decimal("0.0001")


def test_too_few_or_already_agreeing_feedback_proposes_nothing(world: Engine) -> None:
    seed_feedback(world, MIN_CASES - 1, heavier_p(world))
    assert weekly(world).created == []
    run(world, "DELETE FROM feedback")
    run(world, "DELETE FROM asset_score")
    run(world, "DELETE FROM assessment")
    seed_feedback(world, MIN_CASES, active_weights(world))  # people already want what the formula gives
    assert weekly(world, force=True).created == []


def test_the_week_cooldown_and_blocks_stop_repeats(world: Engine) -> None:
    seed_feedback(world, MIN_CASES, heavier_p(world))
    assert len(weekly(world).created) == 1
    assert weekly(world, LATER + timedelta(days=2)).run_id is None  # a run already exists this week
    again = weekly(world, LATER + timedelta(days=8))
    assert again.run_id is not None and again.created == []  # the first proposal is still open
    run(world, "UPDATE calibration_proposal SET status = 'applied', decided_at = :d", {"d": LATER + timedelta(days=8)})
    assert weekly(world, LATER + timedelta(days=16)).created == []  # changed less than 2 weeks ago
    run(
        world,
        "UPDATE calibration_proposal SET status = 'reverted', blocked_until = :b",
        {"b": (LATER + timedelta(days=90)).date()},
    )
    seed_feedback_again = weekly(world, LATER + timedelta(days=24), force=True)
    assert seed_feedback_again.created == []  # blocked for 8 weeks after a revert


# --- decisions ----------------------------------------------------------------------------------------------------
def make_weight_proposal(engine: Engine) -> str:
    seed_feedback(engine, MIN_CASES, heavier_p(engine))
    weekly(engine)
    return str(rows(engine, "SELECT id FROM calibration_proposal WHERE target_kind = 'weight'")[0][0])


def decider(engine: Engine) -> Decider:
    return Decider(rows(engine, "SELECT id FROM app_user WHERE firebase_uid = 'u1'")[0][0], LATER)


def edit_weights_by_hand(engine: Engine) -> None:
    """Somebody changes two weights through the configuration service after a proposal was made."""
    with Session(engine) as session, session.begin():
        active, formula = load_active_formula(session)
        change = {
            "weights.S": str(formula.weights["S"] - Decimal("0.01")),
            "weights.D": str(formula.weights["D"] + Decimal("0.01")),
        }
        edited = formula_store.apply_changes(formula, change)
        formula_store.save_new_version(session, active, edited, formula_store.NewVersion(None, LATER, "by hand"))


def test_approving_a_weight_proposal_creates_a_formula_version_and_audits_it(world: Engine) -> None:
    proposal = make_weight_proposal(world)
    before = active_weights(world)
    with Session(world) as session, session.begin():
        row = approve(session, proposal, decider(world))
        assert row.status == "applied" and row.decided_by is not None
    after = active_weights(world)
    assert after["P"] > before["P"] and sum(after.values()) == 1
    assert rows(world, "SELECT version_no, status, origin FROM formula_version ORDER BY version_no") == [
        (1, "superseded", "seed"),
        (2, "active", "mode4"),
    ]
    applied = rows(
        world, "SELECT status, formula_version_id IS NOT NULL, decided_by IS NOT NULL FROM calibration_proposal"
    )
    assert applied == [("applied", True, True)]
    actions = [r[0] for r in rows(world, "SELECT action FROM audit_log ORDER BY action")]
    assert actions == ["calibration.approve", "config.update"]


def test_a_stale_proposal_is_refused_and_a_decided_one_cannot_be_decided_again(world: Engine) -> None:
    proposal = make_weight_proposal(world)
    edit_weights_by_hand(world)
    with Session(world) as session, pytest.raises(ConflictError) as stale:
        approve(session, proposal, decider(world))
    assert stale.value.problems[0].issue == "stale_proposal"
    assert rows(world, "SELECT status FROM calibration_proposal") == [("proposed",)]
    with Session(world) as session, session.begin():
        reject(session, proposal, decider(world))
    with Session(world) as session, pytest.raises(ConflictError) as decided:
        approve(session, proposal, decider(world))
    assert decided.value.problems[0].issue == "already_decided"
    with Session(world) as session, pytest.raises(NotFoundError):
        reject(session, str(uuid.uuid4()), decider(world))
    with Session(world) as session, pytest.raises(NotFoundError):
        reject(session, "not-a-uuid", decider(world))


def test_rejecting_records_the_decision_and_changes_nothing_else(world: Engine) -> None:
    proposal = make_weight_proposal(world)
    before = active_weights(world)
    with Session(world) as session, session.begin():
        assert reject(session, proposal, decider(world)).status == "rejected"
    assert active_weights(world) == before
    row = rows(
        world,
        "SELECT status, decided_by IS NOT NULL, decided_at IS NOT NULL, formula_version_id FROM calibration_proposal",
    )
    assert row == [("rejected", True, True, None)]
    assert rows(world, "SELECT action FROM audit_log") == [("calibration.reject",)]


def test_approving_a_source_proposal_changes_its_level_unless_it_went_stale(world: Engine) -> None:
    source = add_source(world, "good_blog", "N3")
    add_claims(world, source, 30, 0)
    weekly(world)
    proposal = str(rows(world, "SELECT id FROM calibration_proposal")[0][0])
    run(world, "UPDATE source SET trust_tier = 'N4' WHERE code = 'good_blog'")  # changed by hand since the proposal
    with Session(world) as session, pytest.raises(ConflictError) as stale:
        approve(session, proposal, decider(world))
    assert stale.value.problems[0].issue == "stale_proposal"
    run(world, "UPDATE source SET trust_tier = 'N3' WHERE code = 'good_blog'")
    with Session(world) as session, session.begin():  # the level change, the status and both audits are one commit
        approve(session, proposal, decider(world))
    assert rows(world, "SELECT trust_tier FROM source WHERE code = 'good_blog'") == [("N2",)]
    assert {r[0] for r in rows(world, "SELECT action FROM audit_log")} == {"source.trust_tier", "calibration.approve"}


def test_only_an_admin_row_can_change_a_source_level(world: Engine) -> None:
    source = add_source(world, "good_blog", "N3")
    add_claims(world, source, 30, 0)
    weekly(world)
    proposal = str(rows(world, "SELECT id FROM calibration_proposal")[0][0])
    run(world, "UPDATE app_user SET role = 'analyst'")
    with Session(world) as session, pytest.raises(ForbiddenParameterError):
        approve(session, proposal, decider(world))
    assert rows(world, "SELECT trust_tier FROM source WHERE code = 'good_blog'") == [("N3",)]


def test_the_worker_job_writes_proposals_once_a_week(world: Engine) -> None:
    source = add_source(world, "good_blog", "N3")
    add_claims(world, source, 30, 0)
    job = WeeklyCalibrationJob(sessionmaker(world, expire_on_commit=False), clock=lambda: LATER)
    job()
    job()
    assert rows(world, "SELECT count(*) FROM calibration_proposal") == [(1,)]
    assert rows(world, "SELECT count(*) FROM run WHERE kind = 'mode4'") == [(1,)]


def test_autonomous_mode_setting_does_not_apply_anything(world: Engine) -> None:
    run(
        world,
        "INSERT INTO setting_value (setting_key, version, value, origin, changed_at) "
        "VALUES ('mode4_autonomous', 1, 'true'::jsonb, 'frontend', now())",
    )
    before = active_weights(world)
    make_weight_proposal(world)
    assert rows(world, "SELECT status FROM calibration_proposal") == [("proposed",)]
    assert active_weights(world) == before


# --- routes -----------------------------------------------------------------------------------------------------------
@pytest.fixture
def client(world: Engine) -> Iterator[TestClient]:
    settings = Settings(
        _env_file=None,
        database_url=SecretStr("postgresql://a:b@db/h"),
        firebase_project_id="p",
        cursor_signing_key=SecretStr("k" * 40),
    )
    app = create_app(settings)
    app.state.session_factory = sessionmaker(world, expire_on_commit=False)
    with TestClient(app, raise_server_exceptions=False) as test_client:
        APPS[id(test_client)] = app
        yield test_client


def as_role(client: TestClient, role: Role) -> None:
    APPS[id(client)].dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid="u1", email="u1@example.com", display_name=None, role=role
    )


def test_the_routes_list_approve_and_reject_real_proposals(client: TestClient, world: Engine) -> None:
    weight = make_weight_proposal(world)
    source = add_source(world, "good_blog", "N3")
    add_claims(world, source, 30, 0)
    weekly(world, LATER + timedelta(days=8))
    as_role(client, Role.READER)
    items = client.get("/api/calibration/proposals").json()["items"]
    assert {i["kind"] for i in items} == {"formula_weight", "source_level"}
    assert {i["status"] for i in items} == {"pending"}
    by_kind = {i["kind"]: i for i in items}
    assert by_kind["source_level"]["summary"] == "Cambiar el nivel de la fuente good_blog de N3 a N2"
    assert by_kind["formula_weight"]["target_key"] == "weights.P"
    assert by_kind["formula_weight"]["backtest"]["cases"] == MIN_CASES
    assert client.post(f"/api/calibration/proposals/{weight}/approve").status_code == 403  # admin only
    as_role(client, Role.ADMIN)
    approved = client.post(f"/api/calibration/proposals/{weight}/approve")
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved" and approved.json()["decided_at"] is not None
    rejected = client.post(f"/api/calibration/proposals/{by_kind['source_level']['id']}/reject")
    assert rejected.json()["status"] == "rejected"
    assert client.post(f"/api/calibration/proposals/{weight}/approve").status_code == 409
    assert client.post(f"/api/calibration/proposals/{uuid.uuid4()}/reject").status_code == 404
    assert client.post("/api/calibration/proposals/not-a-uuid/approve").status_code == 422  # F12.3: UUID path ids
    assert rows(world, "SELECT trust_tier FROM source WHERE code = 'good_blog'") == [("N3",)]  # rejected: unchanged


def test_a_stale_proposal_answers_409_from_the_route(client: TestClient, world: Engine) -> None:
    proposal = make_weight_proposal(world)
    edit_weights_by_hand(world)
    as_role(client, Role.ADMIN)
    response = client.post(f"/api/calibration/proposals/{proposal}/approve")
    assert response.status_code == 409 and response.json()["error"]["details"][0]["issue"] == "stale_proposal"
    assert rows(world, "SELECT status FROM calibration_proposal") == [("proposed",)]


def test_best_candidate_needs_enough_cases() -> None:
    assert best_candidate(default_formula(), [], Decimal("0.1"), frozenset()) is None


def test_an_applied_weight_change_puts_every_weight_on_cooldown(world: Engine) -> None:
    proposal = make_weight_proposal(world)
    with Session(world) as session, session.begin():
        approve(session, proposal, decider(world))
    with Session(world) as session:
        blocked = _blocked_keys(session, LATER + timedelta(days=2), load_settings(session))
    assert {f"weights.{f}" for f in "SPTAD"} <= blocked
