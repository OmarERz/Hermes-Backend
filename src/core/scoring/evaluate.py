"""Evaluation of a finding group (docs/06 §3 and §4, EVA-05, COR-05, COR-06) and the `BaseScorer` of the packages.

`evaluate_group` stores one `assessment` (group factors, judge adjustment, raw snapshot) and one `asset_score` per
current CI. The judge adjustment is reused when the package fingerprint did not change (COR-06), and the judge is
never called by a recalculation (COR-05): a recalculation reuses the last adjustment and only recomputes what the
formula and the clock change.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Protocol

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from core.correlation.engine import GroupCtx, StoryFacts, load_active_groups, load_match_types
from core.correlation.packages import NewsMatch, ScoredGroup, build_finding_package
from core.db import models as m
from core.db.ids import new_id
from core.scoring import inputs
from core.scoring.engine import (
    CiScore,
    Factors,
    FinalScore,
    FindingStatus,
    Formula,
    TicketScore,
    base_score,
    exploitation_level,
    final_score,
    floor_eligible,
    threat,
    ticket_score,
    urgency,
)
from core.scoring.formula_repo import load_active_formula

log = logging.getLogger("scoring")

JUDGE_TRIGGERS = frozenset({"new_finding", "news", "level_change", "manual"})  # a recalculation never calls the judge
FOUR_PLACES = Decimal("0.0001")
APPLIED_REVIEW_STATUSES = ("applied", "partial_review")  # reviews whose proposal reached the score; others did not


class GroupNotActiveError(LookupError):
    """The group does not exist or has no current finding."""


@dataclass(frozen=True)
class JudgeVerdict:
    """What the judge returned for a package: the group adjustment (None when it failed validation) and its review."""

    adjustment: int | None
    llm_review_id: uuid.UUID | None


JudgeFn = Callable[[dict[str, Any]], JudgeVerdict]


class TicketApplier(Protocol):
    """F5.2 `TicketLifecycle`: turns a stored assessment into ticket changes."""

    def apply(self, session: Session, assessment_id: uuid.UUID) -> object: ...


@dataclass(frozen=True)
class CiResult:
    asset_id: uuid.UUID
    name: str
    a: Decimal
    d: Decimal
    base: int
    final: FinalScore
    status: FindingStatus
    floor: bool


@dataclass(frozen=True)
class GroupResult:
    group_id: uuid.UUID
    factors: inputs.GroupFactors
    t: Decimal
    inputs: inputs.GroupInputs
    cis: tuple[CiResult, ...]
    applied_adjustment: int
    no_judge_review: bool

    def ticket(self, formula: Formula) -> TicketScore | None:
        return ticket_score(formula, [CiScore(ci.name, ci.final.final, ci.status) for ci in self.cis])


@dataclass(frozen=True)
class Evaluation:
    group_id: uuid.UUID
    assessment_id: uuid.UUID | None  # None when nothing changed since the last assessment
    changed: bool
    judge_called: bool
    judge_reused: bool
    result: GroupResult


def utc_now() -> datetime:
    return datetime.now(UTC)


def _status(session: Session, group_id: uuid.UUID, installed_id: uuid.UUID) -> FindingStatus:
    row = session.execute(
        text(
            "SELECT fc.status FROM finding f JOIN finding_current fc ON fc.finding_id = f.id "
            "WHERE f.finding_group_id = :g AND f.installed_software_id = :i"
        ),
        {"g": group_id, "i": installed_id},
    ).first()
    return FindingStatus(row[0]) if row else FindingStatus.NEW


@dataclass(frozen=True)
class Basis:
    """What a computation rests on: the formula, the correlated stories, the judge adjustment and the clock."""

    formula: Formula
    story_ids: list[uuid.UUID]
    judge_adjustment: int | None
    now: datetime


def compute_group(session: Session, group: GroupCtx, basis: Basis) -> GroupResult:
    """Factors, base and final per CI. Pure with respect to the database: nothing is written."""
    formula, judge_adjustment = basis.formula, basis.judge_adjustment
    data = inputs.load_group_inputs(session, group, basis.story_ids, basis.now)
    factors = inputs.group_factors(formula, data)
    t = threat(formula, data.evidence)
    dead = judge_adjustment is not None and abs(judge_adjustment) <= formula.dead_zone
    applied = 0 if judge_adjustment is None or dead else judge_adjustment
    results: list[CiResult] = []
    for ci in group.cis:
        asset = session.get_one(m.Asset, ci.asset_id)
        a, d = inputs.asset_factors(formula, asset)
        base = base_score(formula, Factors(factors.s, factors.p, t, a, d))
        floor = floor_eligible(in_kev=data.in_kev, exposed=asset.exposed)
        final = final_score(formula, base, judge_adjustment=judge_adjustment, floor=floor)
        results.append(
            CiResult(
                asset.id, asset.name, a, d, base, final, _status(session, group.id, ci.installed_software_id), floor
            )
        )
    return GroupResult(group.id, factors, t, data, tuple(results), applied, judge_adjustment is None)


def _matches(session: Session, group_id: uuid.UUID) -> list[NewsMatch]:
    types = load_match_types(session)
    rows = session.execute(
        select(m.Correlation.story_id, m.Correlation.match_type, m.Correlation.relevance).where(
            m.Correlation.finding_group_id == group_id
        )
    )
    return [NewsMatch(story_id, types[code], relevance) for story_id, code, relevance in rows]


def _details(result: GroupResult) -> list[str]:
    data = result.inputs
    lines = [f"CVSS {data.cvss}" if data.cvss is not None else "Sin CVSS: " + result.factors.s_origin.value]
    if data.in_kev:
        lines.append("En KEV")
    lines.append(f"Explotación: {data.grade.value} (nivel P: {result.factors.p_level})")
    lines.append(f"Contexto de amenaza T = {result.t}")
    return lines


class EngineScorer:
    """`BaseScorer` of the review packages: the base of each CI and of the group, without any judge adjustment."""

    def __init__(self, formula: Formula, now: datetime | None = None) -> None:
        self.formula = formula
        self.now = now or utc_now()

    def score_group(self, session: Session, group: GroupCtx, matches: list[NewsMatch]) -> ScoredGroup:
        result = compute_group(session, group, Basis(self.formula, [n.story_id for n in matches], None, self.now))
        per_ci = {
            ci.asset_id: {
                "A": float(ci.a),
                "D": float(ci.d),
                "score": ci.base,
                "floor_applicable": ci.floor,
            }
            for ci in result.cis
        }
        top = max(result.cis, key=lambda ci: ci.base) if result.cis else None
        base = {
            "S": float(result.factors.s),
            "P": float(result.factors.p),
            "T": float(result.t),
            "A": float(top.a) if top else 0.0,
            "D": float(top.d) if top else 0.0,
            "score": top.base if top else 0,
            "details": _details(result),
            "floor_applicable": any(ci.floor for ci in result.cis),
        }
        return ScoredGroup(base, per_ci)

    def score_story(self, session: Session, facts: StoryFacts, asset_ids: list[uuid.UUID]) -> dict[str, Any]:
        """Base of an alert or a dismissal candidate: no CVSS (unrated S), grade of the news, E by version."""
        formula = self.formula
        grade = inputs.parse_grade(
            (session.get(m.NewsAnalysis, facts.analysis_id) or m.NewsAnalysis()).output.get("exploitation_level")
        )
        p_level = exploitation_level(in_kev=False, grade=grade, public_poc=False, epss_percentile=None)
        assets = [a for a in (session.get(m.Asset, asset_id) for asset_id in asset_ids) if a is not None]
        confirmed = bool(
            asset_ids
            and session.scalar(
                select(func.bool_or(m.AlertAsset.version_confirmed))
                .join(m.Alert, m.Alert.id == m.AlertAsset.alert_id)
                .where(m.Alert.story_id == facts.story_id, m.AlertAsset.asset_id.in_(asset_ids))
            )
        )  # E = 1.0 when any CI this story's alert touches runs the version the news names
        e = formula.level("E", "version_confirmed" if confirmed else "version_unknown")
        pairs = [inputs.asset_factors(formula, asset) for asset in assets] or [
            (formula.level("A", "normal_internal_or_unknown"), formula.level("D", "unclassified"))
        ]
        a, d = max(pairs, key=lambda pair: pair[0] * formula.weights["A"] + pair[1] * formula.weights["D"])
        s, p = formula.s_without_cvss, formula.level("P", p_level)
        score = base_score(formula, Factors(s, p, Decimal(0), a, d), e)
        return {
            "S": float(s),
            "P": float(p),
            "T": 0.0,
            "A": float(a),
            "D": float(d),
            "E": float(e),
            "score": score,
            "details": [f"Alerta sin hallazgo: E = {e}", f"Explotación: {grade.value}"],
            "floor_applicable": False,
        }


def _previous(session: Session, group_id: uuid.UUID) -> m.Assessment | None:
    return session.scalars(
        select(m.Assessment)
        .where(m.Assessment.finding_group_id == group_id)
        .order_by(m.Assessment.assessed_at.desc(), m.Assessment.id.desc())
        .limit(1)
    ).first()


def _fingerprint_of(session: Session, assessment: m.Assessment) -> str | None:
    if assessment.llm_review_id is None:
        return None
    return session.scalar(
        select(m.ReviewPackage.fingerprint)
        .join(m.LlmReview, m.LlmReview.review_package_id == m.ReviewPackage.id)
        .where(m.LlmReview.id == assessment.llm_review_id)
    )


def _snapshot(result: GroupResult, formula_id: uuid.UUID, review_id: uuid.UUID | None) -> tuple[object, ...]:
    return (
        formula_id,
        review_id,
        result.factors.s.quantize(FOUR_PLACES),
        result.factors.p.quantize(FOUR_PLACES),
        result.t.quantize(FOUR_PLACES),
        result.applied_adjustment,
        tuple(sorted((str(ci.asset_id), ci.base, ci.final.final) for ci in result.cis)),
    )


def _unchanged(session: Session, previous: m.Assessment, current: tuple[object, ...]) -> bool:
    rows = session.execute(
        select(m.AssetScore.asset_id, m.AssetScore.base, m.AssetScore.final).where(
            m.AssetScore.assessment_id == previous.id
        )
    )
    before = (
        previous.formula_version_id,
        previous.llm_review_id,
        previous.factor_s,
        previous.factor_p,
        previous.factor_t,
        previous.judge_adjustment,
        tuple(sorted((str(asset), base, final) for asset, base, final in rows)),
    )
    return before == current


@dataclass(frozen=True)
class EvaluationOptions:
    """The seams of an evaluation: who judges, who applies tickets, which formula and which clock."""

    judge: JudgeFn | None = None
    tickets: TicketApplier | None = None
    formula: tuple[uuid.UUID, Formula] | None = None
    now: datetime | None = None


@dataclass(frozen=True)
class _Plan:
    ctx: GroupCtx
    matches: list[NewsMatch]
    trigger: str
    previous: m.Assessment | None
    judge: JudgeFn | None
    formula: Formula
    now: datetime


def _proposal(session: Session, assessment: m.Assessment | None) -> int | None:
    """The judge's own proposal behind an assessment (before the dead zone, which is a formula parameter): the
    stored `judge_adjustment` is already dead-zoned, so a formula change must start from the proposal."""
    if assessment is None or assessment.llm_review_id is None:
        return None
    return session.scalar(
        select(m.LlmReview.proposed_adjustment).where(
            m.LlmReview.id == assessment.llm_review_id, m.LlmReview.status.in_(APPLIED_REVIEW_STATUSES)
        )
    )


def _decide_adjustment(session: Session, plan: _Plan) -> tuple[int | None, uuid.UUID | None, bool, bool]:
    """(adjustment, llm_review_id, judge_called, reused) for this evaluation (COR-05, COR-06)."""
    previous = plan.previous
    reusable = _proposal(session, previous)
    reusable_review = previous.llm_review_id if previous is not None and reusable is not None else None
    if plan.judge is None or plan.trigger not in JUDGE_TRIGGERS:
        return reusable, reusable_review, False, reusable is not None
    package = build_finding_package(session, plan.ctx, plan.matches, EngineScorer(plan.formula, plan.now))
    if previous is not None and reusable is not None and _fingerprint_of(session, previous) == package["fingerprint"]:
        return reusable, reusable_review, False, True
    verdict = plan.judge(package)
    return verdict.adjustment, verdict.llm_review_id, True, False


@dataclass(frozen=True)
class _Stamp:
    run_id: uuid.UUID
    trigger: str
    version_id: uuid.UUID
    review_id: uuid.UUID | None
    now: datetime


def _store(session: Session, result: GroupResult, stamp: _Stamp) -> m.Assessment:
    data = result.inputs
    assessment = m.Assessment(
        id=new_id(),
        finding_group_id=result.group_id,
        run_id=stamp.run_id,
        formula_version_id=stamp.version_id,
        llm_review_id=stamp.review_id,
        trigger=stamp.trigger,
        factor_s=result.factors.s.quantize(FOUR_PLACES),
        factor_p=result.factors.p.quantize(FOUR_PLACES),
        factor_t=result.t.quantize(FOUR_PLACES),
        judge_adjustment=result.applied_adjustment,
        raw_cvss_score=data.cvss,
        raw_cvss_version=data.cvss_version,
        raw_epss=data.epss,
        raw_epss_percentile=data.epss_percentile,
        raw_in_kev=data.in_kev,
        assessed_at=stamp.now,
    )
    session.add(assessment)
    session.flush()
    for ci in result.cis:
        asset = session.get_one(m.Asset, ci.asset_id)
        session.add(
            m.AssetScore(
                assessment_id=assessment.id,
                asset_id=ci.asset_id,
                factor_a=ci.a.quantize(FOUR_PLACES),
                factor_d=ci.d.quantize(FOUR_PLACES),
                version_factor=Decimal("1.00"),
                base=ci.base,
                ci_adjustment=0,
                final=ci.final.final,
                snap_criticality=asset.criticality,
                snap_exposed=asset.exposed,
                snap_confidentiality=asset.confidentiality,
                snap_personal_data=asset.personal_data,
                snap_owner_person_id=asset.owner_person_id,
                snap_custodian_team_id=asset.custodian_team_id,
            )
        )
    session.flush()
    return assessment


def evaluate_group(
    session: Session, group_id: uuid.UUID, run_id: uuid.UUID, trigger: str, options: EvaluationOptions | None = None
) -> Evaluation:
    """Score a group and store the assessment when something changed; flushes, the caller commits.

    The judge is called only for a trigger in `JUDGE_TRIGGERS`, when a judge is given and the package fingerprint
    changed. A nightly or formula-change recalculation never reaches it. Without a usable review the final is the
    base (`no_judge_review`), and the KEV floor still applies (EVA-04).
    """
    options = options or EvaluationOptions()
    now = options.now or utc_now()
    version_id, formula = options.formula or load_active_formula(session)
    groups = load_active_groups(session, only={group_id})
    if not groups:
        raise GroupNotActiveError(str(group_id))
    ctx = groups[0]
    matches = _matches(session, group_id)
    previous = _previous(session, group_id)
    adjustment, review_id, called, reused = _decide_adjustment(
        session, _Plan(ctx, matches, trigger, previous, options.judge, formula, now)
    )
    result = compute_group(session, ctx, Basis(formula, [n.story_id for n in matches], adjustment, now))
    snapshot = _snapshot(result, version_id, review_id)
    if previous is not None and _unchanged(session, previous, snapshot):
        return Evaluation(group_id, None, False, called, reused, result)
    assessment = _store(session, result, _Stamp(run_id, trigger, version_id, review_id, now))
    if options.tickets is not None:
        options.tickets.apply(session, assessment.id)
    log.info("assessed group %s (%s): %d CIs", group_id, trigger, len(result.cis))
    return Evaluation(group_id, assessment.id, True, called, reused, result)


@dataclass(frozen=True)
class RecalculationReport:
    run_id: uuid.UUID
    groups: int
    changed: int


def recalculate_open_groups(
    session: Session,
    trigger: str = "formula_change",
    options: EvaluationOptions | None = None,
    commit: bool = True,
) -> RecalculationReport:
    """Recompute every active group with the formula and the clock, **without calling the judge** (COR-05): a
    weights change or the nightly decay reuses each group's last adjustment. Commits unless `commit` is False."""
    given = options or EvaluationOptions()
    moment = given.now or utc_now()
    run = m.Run(
        id=new_id(),
        kind="recalculation" if trigger == "formula_change" else "nightly",
        status="running",
        progress=0,
        trigger_reason="formula_change" if trigger == "formula_change" else "schedule",
        started_at=moment,
    )
    session.add(run)
    session.flush()
    options = EvaluationOptions(judge=None, tickets=given.tickets, formula=given.formula, now=moment)
    groups = load_active_groups(session)
    changed = 0
    for group in groups:
        evaluation = evaluate_group(session, group.id, run.id, trigger, options)
        changed += evaluation.changed
    run.status, run.progress, run.finished_at = "succeeded", 100, moment
    if commit:
        session.commit()
    else:
        session.flush()
    return RecalculationReport(run.id, len(groups), changed)


@dataclass(frozen=True)
class SimulatedChange:
    group_id: uuid.UUID
    asset_id: uuid.UUID
    cve_id: str
    before_final: int
    after_final: int
    before_urgency: int
    after_urgency: int


@dataclass(frozen=True)
class Simulation:
    findings: int  # current findings of open groups that have a stored assessment
    changed_level: int  # how many would move to another urgency band
    changes: tuple[SimulatedChange, ...]


def _last_finals(session: Session, group_id: uuid.UUID) -> tuple[m.Assessment, dict[uuid.UUID, int]] | None:
    previous = _previous(session, group_id)
    if previous is None:
        return None
    rows = session.execute(
        select(m.AssetScore.asset_id, m.AssetScore.final).where(m.AssetScore.assessment_id == previous.id)
    )
    return previous, dict(rows.all())


def simulate(
    session: Session, proposed: Formula, current: Formula | None = None, now: datetime | None = None
) -> Simulation:
    """FRO-06: how many open findings would change level with `proposed`, with nothing written. The stored judge
    adjustments are kept (no judge call), the levels are the urgency bands of each formula."""
    moment = now or utc_now()
    active = current or load_active_formula(session)[1]
    total = 0
    changes: list[SimulatedChange] = []
    for group in load_active_groups(session):
        last = _last_finals(session, group.id)
        if last is None:
            continue
        previous, finals = last
        adjustment = _proposal(session, previous)
        stories = [n.story_id for n in _matches(session, group.id)]
        result = compute_group(session, group, Basis(proposed, stories, adjustment, moment))
        for ci in result.cis:
            if ci.asset_id not in finals:
                continue
            total += 1
            before, after = finals[ci.asset_id], ci.final.final
            band_before, band_after = urgency(active, before), urgency(proposed, after)
            if band_before != band_after:
                changes.append(
                    SimulatedChange(group.id, ci.asset_id, group.cve_id, before, after, band_before, band_after)
                )
    return Simulation(total, len(changes), tuple(changes))
