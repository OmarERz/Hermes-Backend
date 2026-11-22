"""The findings scenario: the `edge` seed plus assessments, a fixed group, a decommissioned CI and a ticket.

group   CVE              CIs (final in the latest assessment, status)
G1      CVE-2026-10001   CI-1 90 new · CI-2 62 fixed · CI-4 99 (decommissioned)   KEV, ticket R-000777
G2      CVE-2026-10002   CI-3 75 new · CI-1 70 new                                 no CVSS
G3      CVE-2026-10003   CI-2 30 fixed                                             every finding fixed
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.seeds import seed

T0 = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
T1 = T0 + timedelta(days=1)
T2 = T0 + timedelta(days=2)


@dataclass
class Scenario:
    formula_id: uuid.UUID
    run_id: uuid.UUID
    assets: dict[str, uuid.UUID] = field(default_factory=dict)  # by iTop CI id
    groups: dict[str, uuid.UUID] = field(default_factory=dict)  # G1, G2, G3
    findings: dict[tuple[str, str], uuid.UUID] = field(default_factory=dict)  # (group, CI)
    assessments: dict[str, uuid.UUID] = field(default_factory=dict)  # A1 to A4
    teams: dict[str, uuid.UUID] = field(default_factory=dict)  # by name


def _asset(session: Session, ci: str) -> m.Asset:
    return session.scalars(select(m.Asset).where(m.Asset.itop_ci_id == ci)).one()


@dataclass(frozen=True)
class Spec:
    """One assessment of a group: per CI (base, ci_adjustment, final), the group factors and the raw snapshot."""

    group: str
    at: datetime
    scores: dict[str, tuple[int, int, int]]
    judge: int = 0
    review: uuid.UUID | None = None
    cvss: Decimal | None = Decimal("9.8")
    in_kev: bool = True
    factors: tuple[str, str, str] = ("0.98", "1.0", "0.0")
    snapshots: dict[str, str] = field(default_factory=dict)  # CI -> confidentiality at evaluation


def add_assessment(session: Session, sc: Scenario, spec: Spec) -> uuid.UUID:
    assessment = m.Assessment(
        finding_group_id=sc.groups[spec.group],
        run_id=sc.run_id,
        formula_version_id=sc.formula_id,
        llm_review_id=spec.review,
        trigger="new_finding",
        factor_s=Decimal(spec.factors[0]),
        factor_p=Decimal(spec.factors[1]),
        factor_t=Decimal(spec.factors[2]),
        judge_adjustment=spec.judge,
        raw_cvss_score=spec.cvss,
        raw_cvss_version="3.1" if spec.cvss is not None else None,
        raw_epss=Decimal("0.91"),
        raw_epss_percentile=Decimal("0.99"),
        raw_in_kev=spec.in_kev,
        assessed_at=spec.at,
    )
    session.add(assessment)
    session.flush()
    for ci, (base, ci_adjustment, final) in spec.scores.items():
        asset = _asset(session, ci)
        session.add(
            m.AssetScore(
                assessment_id=assessment.id,
                asset_id=asset.id,
                factor_a=Decimal("1.0") if asset.criticality == "high" else Decimal("0.5"),
                factor_d=Decimal("1.0") if asset.confidentiality == "highly_classified" else Decimal("0.5"),
                version_factor=Decimal("1.00"),
                base=base,
                ci_adjustment=ci_adjustment,
                final=final,
                snap_criticality=asset.criticality,
                snap_exposed=asset.exposed,
                snap_confidentiality=spec.snapshots.get(ci, asset.confidentiality),
                snap_personal_data=asset.personal_data,
                snap_owner_person_id=asset.owner_person_id,
                snap_custodian_team_id=asset.custodian_team_id,
            )
        )
    session.flush()
    return assessment.id


def add_review(session: Session, *, mitigation: bool = True) -> uuid.UUID:
    """An applied judge review with one accepted reason (+8) and, when asked, an accepted mitigation draft."""
    review = m.LlmReview(
        agent="judge",
        mode="scoring",
        model="deepseek-v4-pro",
        response_model={},
        prompt_version="judge-mode1-v1",
        prompt_hash="h",
        schema_version="1",
        schema_hash="h",
        parameters={},
        input_ref="pkg",
        calls=[],
        status="applied",
        attempts=1,
        summary="Explotación masiva reportada.",
        proposed_adjustment=8,
        mitigation_status="accepted" if mitigation else "absent",
        tokens_input=100,
        tokens_cached=0,
        tokens_output=50,
        tokens_reasoning=0,
        cost_usd=Decimal("0.010000"),
        latency_ms=900,
        ladder_level=0,
        created_at=T1,
    )
    session.add(review)
    session.flush()
    session.add(
        m.JudgeReason(
            llm_review_id=review.id,
            seq=1,
            reason_code="mass_exploitation",
            points=8,
            element_id="news-1",
            quote="explotación masiva",
            status="accepted",
        )
    )
    session.add(
        m.JudgeReason(
            llm_review_id=review.id,
            seq=2,
            reason_code="unverified_poc",
            points=-5,
            element_id="news-2",
            quote="sin verificar",
            status="rejected",
            rejection_rule="L6",
        )
    )
    if mitigation:
        for order, action in enumerate(("Aislar srv-pagos-01.", "Actualizar OpenSSL a 3.0.8."), start=1):
            session.add(
                m.MitigationDraftStep(
                    llm_review_id=review.id, step_order=order, action=action, element_id="cve", quote="3.0.8"
                )
            )
    session.flush()
    return review.id


def _status(session: Session, sc: Scenario, finding: uuid.UUID, status: str, at: datetime) -> None:
    session.add(
        m.FindingStatusChange(
            finding_id=finding, run_id=sc.run_id, status=status, observed_version="3.0.7", changed_at=at
        )
    )


def _finding(session: Session, sc: Scenario, group: str, install: m.InstalledSoftware, ci: str) -> uuid.UUID:
    finding = m.Finding(
        finding_group_id=sc.groups[group], installed_software_id=install.id, match_source="nvd_cpe", created_at=T0
    )
    session.add(finding)
    session.flush()
    _status(session, sc, finding.id, "new", T0)
    sc.findings[(group, ci)] = finding.id
    return finding.id


def build_scenario(session: Session) -> Scenario:
    seed(session, "edge")
    formula_id = session.scalars(select(m.FormulaVersion.id).where(m.FormulaVersion.status == "active")).one()
    run_id = session.scalars(select(m.Run.id)).one()
    sc = Scenario(formula_id=formula_id, run_id=run_id)
    for team in session.scalars(select(m.Team)):
        sc.teams[team.name] = team.id
    for ci in ("CI-1", "CI-2", "CI-3"):
        sc.assets[ci] = _asset(session, ci).id
    for name, cve in (("G1", "CVE-2026-10001"), ("G2", "CVE-2026-10002")):
        sc.groups[name] = session.scalars(select(m.FindingGroup.id).where(m.FindingGroup.cve_id == cve)).one()
    sc.findings.update(_seeded_findings(session))
    product_id = session.scalars(select(m.SoftwareProduct.id).where(m.SoftwareProduct.itop_name == "OpenSSL")).one()

    # A decommissioned CI in G1 with the highest score: it must not count anywhere.
    retired = m.Asset(
        itop_ci_id="CI-4",
        itop_class="Server",
        name="srv-retirado",
        criticality="high",
        exposed=True,
        confidentiality="public",
        synced_at=T0,
        decommissioned_at=T1,
    )
    session.add(retired)
    session.flush()
    sc.assets["CI-4"] = retired.id
    retired_install = m.InstalledSoftware(
        itop_instance_id="SI-4", asset_id=retired.id, software_product_id=product_id, version="3.0.7", synced_at=T0
    )
    session.add(retired_install)
    session.flush()
    _finding(session, sc, "G1", retired_install, "CI-4")

    # G3: a fixed group on CI-2 only.
    session.add(m.Cve(id="CVE-2026-10003", description="CVE corregido en la demo", published_at=T0, fetched_at=T0))
    g3 = m.FindingGroup(cve_id="CVE-2026-10003", software_product_id=product_id, created_at=T0)
    session.add(g3)
    session.flush()
    sc.groups["G3"] = g3.id
    ci2_install = session.scalars(
        select(m.InstalledSoftware).where(m.InstalledSoftware.asset_id == sc.assets["CI-2"])
    ).one()
    g3_finding = _finding(session, sc, "G3", ci2_install, "CI-2")
    _status(session, sc, g3_finding, "fixed", T1)

    sc.assessments["A1"] = add_assessment(session, sc, Spec("G1", T0, {"CI-1": (80, 0, 80), "CI-2": (60, 0, 60)}))
    sc.assessments["A2"] = add_assessment(
        session,
        sc,
        Spec(
            "G1",
            T1,
            {"CI-1": (82, 0, 90), "CI-2": (62, 0, 62), "CI-4": (99, 0, 99)},
            judge=8,
            review=add_review(session),
            snapshots={"CI-2": "public"},
        ),
    )
    sc.assessments["A3"] = add_assessment(
        session,
        sc,
        Spec(
            "G2",
            T1,
            {"CI-3": (75, 0, 75), "CI-1": (70, 0, 70)},
            cvss=None,
            in_kev=False,
            factors=("0.8", "0.2", "0.0"),
        ),
    )
    sc.assessments["A4"] = add_assessment(
        session,
        sc,
        Spec("G3", T0, {"CI-2": (30, 0, 30)}, cvss=Decimal("5.0"), in_kev=False, factors=("0.5", "0.2", "0.0")),
    )
    # CI-2's G1 finding is fixed after the last assessment.
    _status(session, sc, sc.findings[("G1", "CI-2")], "fixed", T2)

    ticket = m.Ticket(
        finding_group_id=sc.groups["G1"],
        custodian_team_id=sc.teams["Infraestructura Linux"],
        itop_ticket_id="777",
        itop_ref="R-000777",
        status="open",
        current_urgency=1,
        suggestions_enabled=True,
        created_at=T1,
        itop_created_at=T1,
    )
    session.add(ticket)
    session.flush()
    for ci in ("CI-1", "CI-2"):
        session.add(m.TicketFinding(ticket_id=ticket.id, finding_id=sc.findings[("G1", ci)], added_at=T1))
    session.flush()
    _add_feedback(session, sc)
    return sc


def _add_feedback(session: Session, sc: Scenario) -> None:
    """On A1: Ana's first verdict (superseded), her current one and Luis's from Slack. On A2: one from Ana."""
    ana = m.AppUser(
        firebase_uid="u-ana",
        email="ana@example.test",
        display_name="Ana Analista",
        role="analyst",
        active=True,
        created_at=T0,
    )
    luis = m.AppUser(firebase_uid="u-luis", email="luis@example.test", role="analyst", active=True, created_at=T0)
    session.add_all([ana, luis])
    session.flush()
    hour = timedelta(hours=1)
    session.add_all(
        [
            m.Feedback(
                assessment_id=sc.assessments["A1"],
                app_user_id=ana.id,
                channel="frontend",
                verdict="wrong_priority",
                proposed_level="high",
                created_at=T0 + hour,
                superseded_at=T1 + hour,
            ),
            m.Feedback(
                assessment_id=sc.assessments["A1"],
                app_user_id=ana.id,
                channel="frontend",
                verdict="relevant",
                comment="Confirmado.",
                created_at=T1 + hour,
            ),
            m.Feedback(
                assessment_id=sc.assessments["A1"],
                app_user_id=luis.id,
                channel="slack",
                verdict="false_positive",
                created_at=T1 + 2 * hour,
            ),
            m.Feedback(
                assessment_id=sc.assessments["A2"],
                app_user_id=ana.id,
                channel="frontend",
                verdict="investigating",
                created_at=T2,
            ),
        ]
    )
    session.flush()


def _seeded_findings(session: Session) -> dict[tuple[str, str], uuid.UUID]:
    rows = session.execute(
        select(m.Finding.id, m.FindingGroup.cve_id, m.Asset.itop_ci_id)
        .join(m.FindingGroup, m.FindingGroup.id == m.Finding.finding_group_id)
        .join(m.InstalledSoftware, m.InstalledSoftware.id == m.Finding.installed_software_id)
        .join(m.Asset, m.Asset.id == m.InstalledSoftware.asset_id)
    ).all()
    names = {"CVE-2026-10001": "G1", "CVE-2026-10002": "G2"}
    return {(names[cve], ci): finding_id for finding_id, cve, ci in rows}
