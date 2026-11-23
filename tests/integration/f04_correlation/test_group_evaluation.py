"""Evaluation, recalculation and simulation against the demo inventory (OpenSSL on two CIs, CVE-2026-10001 in KEV)."""

from __future__ import annotations

import dataclasses
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
from correlation_support import NOW, add_group, add_story, demo_group
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.correlation.engine import StoryFacts, correlate_story, load_active_groups, load_story_facts
from core.correlation.packages import build_dismissal_package, build_finding_package, store_package
from core.db import models as m
from core.db.ids import new_id
from core.scoring import inputs
from core.scoring.engine import Formula
from core.scoring.evaluate import (
    EngineScorer,
    EvaluationOptions,
    GroupNotActiveError,
    JudgeVerdict,
    evaluate_group,
    recalculate_open_groups,
    simulate,
)
from core.scoring.formula_repo import load_active_formula

pytestmark = pytest.mark.integration
CVE = "CVE-2026-10001"


class JudgeDouble:
    """Counts calls and stores what the real judge would: the package and a review that points at it."""

    def __init__(self, session: Session, adjustment: int | None = 12) -> None:
        self.session, self.adjustment, self.calls = session, adjustment, 0

    def review_for(self, package_row_id: uuid.UUID | None) -> m.LlmReview:
        review = m.LlmReview(
            id=new_id(),
            agent="judge",
            mode="scoring",
            review_package_id=package_row_id,
            model="test",
            response_model={},
            prompt_version="1",
            prompt_hash="h",
            schema_version="1",
            schema_hash="h",
            parameters={},
            input_ref="test",
            proposed_adjustment=self.adjustment,
            calls=[],
            status="applied",
            attempts=1,
            tokens_input=1,
            tokens_cached=0,
            tokens_output=1,
            tokens_reasoning=0,
            cost_usd=Decimal("0.01"),
            latency_ms=1,
            ladder_level=0,
            created_at=NOW,
        )
        self.session.add(review)
        self.session.flush()
        return review

    def __call__(self, package: dict[str, Any]) -> JudgeVerdict:
        self.calls += 1
        review = self.review_for(store_package(self.session, package, NOW).id)
        return JudgeVerdict(self.adjustment, review.id if self.adjustment is not None else None)


class TicketsDouble:
    def __init__(self) -> None:
        self.applied: list[uuid.UUID] = []

    def apply(self, session: Session, assessment_id: uuid.UUID) -> None:
        self.applied.append(assessment_id)


def run(session: Session) -> uuid.UUID:
    row = m.Run(id=new_id(), kind="scan", status="succeeded", progress=100, trigger_reason="manual")
    session.add(row)
    session.flush()
    return row.id


def finals(session: Session, assessment_id: uuid.UUID) -> dict[str, int]:
    rows = session.execute(
        select(m.Asset.itop_ci_id, m.AssetScore.final)
        .join(m.AssetScore, m.AssetScore.asset_id == m.Asset.id)
        .where(m.AssetScore.assessment_id == assessment_id)
    )
    return dict(rows.all())


def opts(session: Session, judge: JudgeDouble | None = None, **extra: Any) -> EvaluationOptions:
    return EvaluationOptions(judge=judge, now=NOW + timedelta(hours=2), **extra)


def test_without_a_judge_the_final_is_the_base_and_the_kev_floor_still_applies(session: Session) -> None:
    group = demo_group(session)
    evaluation = evaluate_group(session, group, run(session), "new_finding", opts(session))
    assert evaluation.changed
    assert evaluation.result.no_judge_review
    assessment = session.get(m.Assessment, evaluation.assessment_id)
    assert assessment is not None
    assert (assessment.factor_s, assessment.factor_p, assessment.factor_t) == (
        Decimal("0.9800"),
        Decimal(1),
        Decimal(0),
    )
    assert (assessment.raw_cvss_score, assessment.raw_in_kev, assessment.raw_epss_percentile) == (
        Decimal("9.8"),
        True,
        Decimal("0.99000"),
    )
    assert (assessment.llm_review_id, assessment.judge_adjustment) == (None, 0)
    scores = session.scalars(select(m.AssetScore).where(m.AssetScore.assessment_id == assessment.id)).all()
    assert len(scores) == 2
    exposed = next(s for s in scores if s.snap_exposed)
    assert exposed.final >= 90  # KEV on an exposed CI: floor
    assert all(s.version_factor == Decimal("1.00") and s.ci_adjustment == 0 for s in scores)


def test_the_judge_is_called_once_and_its_adjustment_reused_while_the_fingerprint_holds(session: Session) -> None:
    group = demo_group(session)
    story = add_story(session, cves={CVE: "active"})
    correlate_story(session, story.id, NOW)
    judge = JudgeDouble(session, adjustment=-12)
    first = evaluate_group(session, group, run(session), "news", opts(session, judge))
    assert (judge.calls, first.judge_called, first.judge_reused) == (1, True, False)
    stored = session.get(m.Assessment, first.assessment_id)
    assert stored is not None
    assert (stored.judge_adjustment, stored.llm_review_id is not None) == (-12, True)
    again = evaluate_group(session, group, run(session), "manual", opts(session, judge))
    assert (judge.calls, again.judge_called, again.judge_reused, again.changed) == (1, False, True, False)
    # a new linked story changes the fingerprint: the judge is called again
    correlate_story(session, add_story(session, cves={CVE: "mass"}).id, NOW)
    third = evaluate_group(session, group, run(session), "news", opts(session, judge))
    assert (judge.calls, third.judge_called) == (2, True)


def test_a_dead_zone_adjustment_is_stored_as_zero(session: Session) -> None:
    judge = JudgeDouble(session, adjustment=3)
    evaluation = evaluate_group(session, demo_group(session), run(session), "new_finding", opts(session, judge))
    assessment = session.get(m.Assessment, evaluation.assessment_id)
    assert assessment is not None
    assert assessment.judge_adjustment == 0
    assert assessment.llm_review_id is not None
    assert not evaluation.result.no_judge_review


def test_a_judge_that_failed_validation_leaves_the_base(session: Session) -> None:
    judge = JudgeDouble(session, adjustment=None)
    evaluation = evaluate_group(session, demo_group(session), run(session), "new_finding", opts(session, judge))
    assert judge.calls == 1
    assert evaluation.result.no_judge_review


def test_a_nightly_recalculation_never_calls_the_judge_and_keeps_the_last_adjustment(session: Session) -> None:
    group = demo_group(session)
    judge = JudgeDouble(session, adjustment=-20)
    first = evaluate_group(session, group, run(session), "new_finding", opts(session, judge))
    assert first.assessment_id is not None
    nightly = evaluate_group(session, group, run(session), "nightly", opts(session, judge))
    assert (judge.calls, nightly.judge_called, nightly.judge_reused) == (1, False, True)
    assert nightly.changed is False  # nothing moved: no new assessment


def test_threat_context_ages_into_the_assessment_and_decays(session: Session) -> None:
    session.add(m.ProfileSector(sector_code="healthcare", is_primary=True))
    session.add(m.ProfileCountry(country_code="MX"))
    session.flush()
    story = add_story(
        session, cves={CVE: "active"}, victims=[{"name": "Clinic", "sector_code": "healthcare", "country_code": "MX"}]
    )
    correlate_story(session, story.id, NOW)
    group = demo_group(session)
    fresh = evaluate_group(session, group, run(session), "news", EvaluationOptions(now=NOW))
    assert fresh.result.t == Decimal("0.7")  # sector + region with a vector in the stack
    old = evaluate_group(session, group, run(session), "nightly", EvaluationOptions(now=NOW + timedelta(days=40)))
    assert old.result.t == Decimal("0.21")  # decay x0.3 after day 30
    assert old.changed


def test_peer_exploited_and_trend_levels(session: Session) -> None:
    peer = m.PeerCompany(id=new_id(), name="Globex Corp", created_at=NOW)
    session.add(peer)
    session.flush()
    for code in ("a", "b", "c", "d"):
        story = add_story(session, cves={CVE: "limited"}, victims=[{"name": "Globex Corp"}], source_code=code)
        correlate_story(session, story.id, NOW)
    result = evaluate_group(session, demo_group(session), run(session), "news", EvaluationOptions(now=NOW)).result
    assert result.t == Decimal("1.0")
    assert {e.level_code for e in result.inputs.evidence} == {"peer_exploited_with_vector", "trend_4_or_more_sources"}


def test_severity_falls_back_to_the_inferred_vector_then_to_unrated(session: Session) -> None:
    cve = session.get(m.Cve, CVE)
    assert cve is not None
    cve.cvss_score = None
    session.flush()
    unrated = evaluate_group(session, demo_group(session), run(session), "manual", EvaluationOptions(now=NOW))
    assert unrated.result.factors.s == Decimal("0.8")
    assert unrated.result.factors.s_origin.value == "unrated"
    review = JudgeDouble(session).review_for(None)
    session.add(
        m.CveAnalysis(
            id=new_id(),
            cve_id=CVE,
            llm_review_id=review.id,
            inferred_cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            output={},
            created_at=NOW,
        )
    )
    session.flush()
    estimated = evaluate_group(session, demo_group(session), run(session), "manual", EvaluationOptions(now=NOW))
    assert estimated.result.factors.s == Decimal("0.75")
    assert estimated.result.factors.s_origin.value == "estimated"


def test_exploit_reference_and_the_news_poc_signal_give_the_poc_level(session: Session) -> None:
    group = demo_group(session)
    kev = session.get(m.KevEntry, CVE)
    assert kev is not None
    session.delete(kev)
    session.execute(m.EpssScore.__table__.delete())
    session.flush()
    plain = evaluate_group(session, group, run(session), "manual", EvaluationOptions(now=NOW))
    assert plain.result.factors.p_level == "other"
    ref = m.CveReference(id=new_id(), cve_id=CVE, url="https://example.com/poc")
    session.add(ref)
    session.flush()
    session.add(m.CveReferenceTag(reference_id=ref.id, tag="Exploit"))
    session.flush()
    with_ref = evaluate_group(session, group, run(session), "manual", EvaluationOptions(now=NOW))
    assert with_ref.result.factors.p_level == "public_poc"


def test_tickets_are_applied_to_every_stored_assessment_and_not_to_unchanged_ones(session: Session) -> None:
    tickets = TicketsDouble()
    group = demo_group(session)
    first = evaluate_group(session, group, run(session), "new_finding", opts(session, tickets=tickets))
    second = evaluate_group(session, group, run(session), "manual", opts(session, tickets=tickets))
    assert tickets.applied == [first.assessment_id]
    assert second.assessment_id is None


def test_a_group_without_current_findings_cannot_be_evaluated(session: Session) -> None:
    with pytest.raises(GroupNotActiveError):
        evaluate_group(session, uuid.uuid4(), run(session), "manual", EvaluationOptions(now=NOW))


def test_the_engine_scorer_fills_review_packages(session: Session) -> None:
    (group,) = load_active_groups(session)
    scorer = EngineScorer(load_active_formula(session)[1], NOW)
    package = build_finding_package(session, group, [], scorer)
    assert package["base"]["S"] == pytest.approx(0.98)
    assert package["base"]["score"] >= 70
    assert all("score" in ci["base"] for ci in package["group"]["cis"])
    story = add_story(session, event_types=["active_exploitation"])
    dismissal = build_dismissal_package(session, story.id, scorer)
    assert 0 <= dismissal["base"]["score"] <= 100


def test_a_weights_change_with_ten_open_groups_recalculates_with_zero_judge_calls(session: Session) -> None:
    judge = JudgeDouble(session, adjustment=-10)
    groups = [demo_group(session)] + [add_group(session, f"CVE-2026-2{n:04d}").id for n in range(9)]
    for group in groups:
        evaluate_group(session, group, run(session), "new_finding", opts(session, judge))
    assert judge.calls == 10
    version_id, formula = load_active_formula(session)
    reweighted = dataclasses.replace(
        formula,
        weights={
            "S": Decimal("0.50"),
            "P": Decimal("0.10"),
            "T": Decimal("0.10"),
            "A": Decimal("0.20"),
            "D": Decimal("0.10"),
        },
    )
    before = session.scalar(select(func.count()).select_from(m.Assessment))
    report = recalculate_open_groups(
        session,
        "formula_change",
        EvaluationOptions(formula=(version_id, reweighted), now=NOW + timedelta(hours=3)),
        commit=False,
    )
    assert judge.calls == 10  # recalculating never reaches the judge (COR-05)
    assert report.groups == 10
    assert report.changed >= 1
    assert session.scalar(select(func.count()).select_from(m.Assessment)) == before + report.changed
    run_row = session.get(m.Run, report.run_id)
    assert run_row is not None
    assert (run_row.kind, run_row.status, run_row.trigger_reason) == ("recalculation", "succeeded", "formula_change")
    # the judge adjustment of each group was kept
    latest = session.scalars(select(m.Assessment).where(m.Assessment.trigger == "formula_change")).all()
    assert {a.judge_adjustment for a in latest} == {-10}
    nightly = recalculate_open_groups(
        session,
        "nightly",
        EvaluationOptions(formula=(version_id, reweighted), now=NOW + timedelta(hours=4)),
        commit=False,
    )
    assert nightly.changed == 0
    nightly_run = session.get(m.Run, nightly.run_id)
    assert nightly_run is not None
    assert nightly_run.kind == "nightly"


def test_the_simulation_counts_level_changes_and_writes_nothing(session: Session) -> None:
    group = demo_group(session)
    evaluate_group(session, group, run(session), "new_finding", opts(session))
    _version, formula = load_active_formula(session)
    assessments = session.scalar(select(func.count()).select_from(m.Assessment))
    scores = session.scalar(select(func.count()).select_from(m.AssetScore))
    same = simulate(session, formula, now=NOW + timedelta(hours=2))
    assert (same.findings, same.changed_level) == (2, 0)
    gentler = dataclasses.replace(
        formula,
        weights={
            "S": Decimal("0.80"),
            "P": Decimal("0.05"),
            "T": Decimal("0.05"),
            "A": Decimal("0.05"),
            "D": Decimal("0.05"),
        },
        kev_exposed_floor=80,
        urgency_bands={1: 95, 2: 90, 3: 60, 4: 0},
    )
    result = simulate(session, gentler, now=NOW + timedelta(hours=2))
    assert result.findings == 2
    assert result.changed_level >= 1
    change = result.changes[0]
    assert change.before_urgency != change.after_urgency
    assert change.cve_id == CVE
    assert session.scalar(select(func.count()).select_from(m.Assessment)) == assessments
    assert session.scalar(select(func.count()).select_from(m.AssetScore)) == scores


def test_simulation_skips_groups_that_were_never_assessed(session: Session) -> None:
    _version, formula = load_active_formula(session)
    assert simulate(session, formula, now=NOW).findings == 0
    assert isinstance(formula, Formula)


def test_inputs_cover_sector_only_actor_history_signals_and_incomplete_stories(session: Session) -> None:
    session.add(m.ProfileSector(sector_code="healthcare", is_primary=True))
    session.flush()
    only_sector = add_story(session, cves={CVE: "attempted"}, victims=[{"name": "Clinic", "sector_code": "healthcare"}])
    add_story(session, actors=["Lockbit"], victims=[{"name": "Old clinic", "sector_code": "healthcare"}])
    actor_story = add_story(
        session, cves={CVE: "none"}, actors=["Lockbit"], victims=[{"name": "Elsewhere", "sector_code": "retail"}]
    )
    analysis = session.scalars(select(m.NewsAnalysis).where(m.NewsAnalysis.story_id == actor_story.id)).one()
    analysis.output = {**analysis.output, "signals": {"public_poc": True}}
    bare = m.Story(
        id=new_id(),
        representative_article_id=only_sector.representative_article_id,
        relevance_status="relevant",
        created_at=NOW,
    )
    session.add(bare)
    session.flush()
    stories = [
        only_sector.id,
        actor_story.id,
        bare.id,
        uuid.uuid4(),
    ]  # a story without analysis and one that is unknown
    group = load_active_groups(session)[0]
    data = inputs.load_group_inputs(session, group, stories, NOW)
    assert data.public_poc
    assert data.grade.value == "attempted"
    levels = {e.level_code for e in data.evidence}
    assert {"sector_only", "sector_region_with_vector"} <= levels  # R4 raises the actor story to the 0.7 level


def test_unknown_values_take_the_neutral_levels() -> None:
    assert inputs.parse_grade("active").value == "active"
    assert inputs.parse_grade("weird").value == "none"
    assert inputs.parse_grade(None).value == "none"


def test_an_asset_with_unrecognized_itop_values_scores_with_neutral_factors(session: Session) -> None:
    formula = load_active_formula(session)[1]
    asset = m.Asset(
        id=new_id(), itop_ci_id="CI-901", itop_class="Server", name="odd", criticality="weird",
        confidentiality="weird", synced_at=NOW,
    )  # fmt: skip
    a, d = inputs.asset_factors(formula, asset)
    assert (a, d) == (Decimal("0.5"), Decimal("0.5"))


def test_a_dead_zone_change_applies_the_judges_original_proposal(session: Session) -> None:
    group = demo_group(session)
    judge = JudgeDouble(session, adjustment=4)
    first = evaluate_group(session, group, run(session), "new_finding", opts(session, judge))
    stored = session.get(m.Assessment, first.assessment_id)
    assert stored is not None
    assert stored.judge_adjustment == 0  # +4 sits inside the default dead zone of 4
    version_id, formula = load_active_formula(session)
    narrower = dataclasses.replace(formula, dead_zone=2)
    report = recalculate_open_groups(
        session,
        "formula_change",
        EvaluationOptions(formula=(version_id, narrower), now=NOW + timedelta(hours=3)),
        commit=False,
    )
    assert report.changed == 1
    latest = session.scalars(select(m.Assessment).where(m.Assessment.trigger == "formula_change")).one()
    assert latest.judge_adjustment == 4
    assert judge.calls == 1


def test_the_alert_version_factor_follows_this_storys_alert(session: Session) -> None:
    formula = load_active_formula(session)[1]
    scorer = EngineScorer(formula, NOW)
    story = add_story(session, products=[("openssl", "openssl", "3.0.7")])
    outcome = correlate_story(session, story.id, NOW)
    assert outcome is not None
    assert outcome.alert_id is None  # the demo group matches: no alert
    other = add_story(session, event_types=["active_exploitation"])
    asset_ids = list(session.scalars(select(m.Asset.id)))
    facts = _facts(session, other.id)
    unknown = scorer.score_story(session, facts, asset_ids)
    assert unknown["E"] == Decimal("0.6")
    alert = m.Alert(id=new_id(), story_id=other.id, relevance="R2", status="open", created_at=NOW)
    session.add(alert)
    session.flush()
    session.add(
        m.AlertAsset(alert_id=alert.id, asset_id=asset_ids[0], installed_software_id=None, version_confirmed=True)
    )
    session.flush()
    assert scorer.score_story(session, facts, asset_ids)["E"] == Decimal("1.0")
    # another story's confirmed alert does not leak into this one
    third = add_story(session, event_types=["active_exploitation"])
    assert scorer.score_story(session, _facts(session, third.id), asset_ids)["E"] == Decimal("0.6")


def _facts(session: Session, story_id: uuid.UUID) -> StoryFacts:
    facts = load_story_facts(session, story_id)
    assert facts is not None
    return facts


def test_a_review_that_did_not_apply_its_proposal_is_not_reused(session: Session) -> None:
    group = demo_group(session)
    judge = JudgeDouble(session, adjustment=15)
    first = evaluate_group(session, group, run(session), "new_finding", opts(session, judge))
    stored = session.get(m.Assessment, first.assessment_id)
    assert stored is not None
    assert stored.judge_adjustment == 15
    review = session.get(m.LlmReview, stored.llm_review_id)
    assert review is not None
    review.status = "judge_disagreement"  # the proposal is still on the review, but the final was the base
    session.flush()
    nightly = evaluate_group(session, group, run(session), "nightly", opts(session))
    assert nightly.result.no_judge_review
    assert nightly.result.applied_adjustment == 0


def test_the_ticket_score_comes_from_the_highest_current_ci(session: Session) -> None:
    evaluation = evaluate_group(session, demo_group(session), run(session), "new_finding", opts(session))
    formula = load_active_formula(session)[1]
    ticket = evaluation.result.ticket(formula)
    assert ticket is not None
    assert ticket.score == max(ci.final.final for ci in evaluation.result.cis)
    assert ticket.driven_by == "srv-pagos-01"
    assert ticket.urgency == 1


def test_without_a_given_clock_the_current_time_is_used(session: Session) -> None:
    evaluation = evaluate_group(session, demo_group(session), run(session), "new_finding")
    assessment = session.get(m.Assessment, evaluation.assessment_id)
    assert assessment is not None
    assert abs((assessment.assessed_at - datetime.now(UTC)).total_seconds()) < 60


def test_a_recalculation_without_judge_after_an_unreviewed_assessment_stays_unreviewed(session: Session) -> None:
    group = demo_group(session)
    evaluate_group(session, group, run(session), "new_finding", opts(session))
    again = evaluate_group(session, group, run(session), "manual", opts(session))
    assert again.result.no_judge_review
    assert again.changed is False


def test_a_recalculation_commits_unless_told_not_to(session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    commits: list[int] = []
    monkeypatch.setattr(session, "commit", lambda: commits.append(1))
    report = recalculate_open_groups(session, "nightly", EvaluationOptions(now=NOW))
    assert report.groups >= 1
    assert len(commits) == report.groups + 2  # the run, one per group, then the finished run


def test_a_ci_that_appeared_after_the_last_assessment_is_not_simulated(session: Session) -> None:
    group = add_group(session, "CVE-2026-30001")
    evaluate_group(session, group.id, run(session), "new_finding", opts(session))
    other = session.scalars(select(m.InstalledSoftware).order_by(m.InstalledSoftware.itop_instance_id.desc())).first()
    scan = session.scalars(select(m.Run).where(m.Run.kind == "scan")).first()
    assert other is not None
    assert scan is not None
    finding = m.Finding(
        id=new_id(), finding_group_id=group.id, installed_software_id=other.id, match_source="nvd_cpe", created_at=NOW
    )
    session.add(finding)
    session.flush()
    session.add(
        m.FindingStatusChange(
            id=new_id(),
            finding_id=finding.id,
            run_id=scan.id,
            status="new",
            observed_version=other.version,
            changed_at=NOW,
        )
    )
    session.flush()
    formula = load_active_formula(session)[1]
    assert simulate(session, formula, now=NOW).findings == 1


def test_a_changed_context_without_a_judge_does_not_reuse_the_old_adjustment(session: Session) -> None:
    group = demo_group(session)
    judge = JudgeDouble(session, adjustment=20)
    evaluate_group(session, group, run(session), "new_finding", opts(session, judge))
    correlate_story(session, add_story(session, cves={CVE: "mass"}).id, NOW)  # a new linked story: new fingerprint
    again = evaluate_group(session, group, run(session), "news", opts(session))
    assert again.result.no_judge_review
    assert again.result.applied_adjustment == 0
    assert judge.calls == 1


def test_two_installations_on_one_ci_make_one_score(session: Session) -> None:
    group = add_group(session, "CVE-2026-40001")
    first = session.scalars(select(m.InstalledSoftware).order_by(m.InstalledSoftware.itop_instance_id)).first()
    scan = session.scalars(select(m.Run).where(m.Run.kind == "scan")).first()
    assert first is not None
    assert scan is not None
    twin = m.InstalledSoftware(
        id=new_id(), itop_instance_id="SI-900", asset_id=first.asset_id, software_product_id=first.software_product_id,
        version="3.0.1", synced_at=NOW,
    )  # fmt: skip
    session.add(twin)
    session.flush()
    finding = m.Finding(
        id=new_id(), finding_group_id=group.id, installed_software_id=twin.id, match_source="nvd_cpe", created_at=NOW
    )
    session.add(finding)
    session.flush()
    session.add(
        m.FindingStatusChange(
            id=new_id(), finding_id=finding.id, run_id=scan.id, status="new", observed_version="3.0.1", changed_at=NOW
        )
    )
    session.flush()
    evaluation = evaluate_group(session, group.id, run(session), "new_finding", opts(session))
    assert len(evaluation.result.cis) == 1
    (ctx,) = load_active_groups(session, only={group.id})
    assert len(ctx.cis) == 2
    package = build_finding_package(session, ctx, [], EngineScorer(load_active_formula(session)[1], NOW))
    assert len(package["group"]["cis"]) == 1  # the fingerprint sees one entry per CI


def test_a_recalculation_keeps_the_adjustment_even_when_the_context_changed(session: Session) -> None:
    group = demo_group(session)
    judge = JudgeDouble(session, adjustment=-20)
    evaluate_group(session, group, run(session), "new_finding", opts(session, judge))
    asset = session.scalars(select(m.Asset).order_by(m.Asset.itop_ci_id)).first()
    assert asset is not None
    asset.description = "changed after the review"  # the fingerprint covers iTop attributes
    session.flush()
    nightly = evaluate_group(session, group, run(session), "nightly", opts(session))
    assert nightly.result.applied_adjustment == -20
    assert not nightly.result.no_judge_review
    version_id, formula = load_active_formula(session)
    after_formula = evaluate_group(
        session,
        group,
        run(session),
        "formula_change",
        EvaluationOptions(formula=(version_id, formula), now=NOW + timedelta(hours=5)),
    )
    assert after_formula.result.applied_adjustment == -20
    assert judge.calls == 1
