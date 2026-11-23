"""A small detection scenario for the lifecycle tests: assets, findings, scans and assessments with chosen finals."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal

from f05data import T0, make_group, make_team
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.seeds import seed_catalogs, seed_formula


def formula_version(session: Session) -> uuid.UUID:
    """The seeded formula version (bands 90/75/50, hysteresis 5/2/7), created once per database."""
    existing = session.scalar(select(m.FormulaVersion.id).where(m.FormulaVersion.version_no == 1))
    if existing is not None:
        return existing
    seed_catalogs(session)
    return seed_formula(session)


@dataclass
class Scenario:
    """One group (CVE + product) with CIs; `scan` records a scan result and `assess` an assessment."""

    session: Session
    group: m.FindingGroup = field(init=False)
    product: str = field(init=False)
    formula_id: uuid.UUID = field(init=False)
    findings: dict[str, m.Finding] = field(default_factory=dict)
    assets: dict[str, m.Asset] = field(default_factory=dict)
    clock: datetime = T0

    def __post_init__(self) -> None:
        self.formula_id = formula_version(self.session)
        self.product = f"nginx-{uuid.uuid4().hex[:6]}"
        self.group = make_group(self.session, product=self.product)

    def team(self, name: str) -> m.Team:
        return make_team(self.session, name)

    def default_team(self) -> m.Team:
        team = self.session.scalars(select(m.Team).where(m.Team.is_default.is_(True))).first()
        if team is None:
            team = m.Team(itop_team_id=f"T-def-{uuid.uuid4().hex[:6]}", name="Seguridad", is_default=True, synced_at=T0)
            self.session.add(team)
            self.session.flush()
        return team

    def person(self, name: str) -> m.Person:
        tag = uuid.uuid4().hex[:8]
        person = m.Person(itop_person_id=f"P-{tag}", name=name, email=f"{tag}@example.test", synced_at=T0)
        self.session.add(person)
        self.session.flush()
        return person

    def ci(self, name: str, team: m.Team | None, owner: m.Person | None = None, *, critical: bool = False) -> m.Asset:
        asset = m.Asset(
            itop_ci_id=f"CI-{uuid.uuid4().hex[:8]}",
            itop_class="Server",
            name=name,
            criticality="high" if critical else "medium",
            exposed=critical,
            confidentiality="classified",
            personal_data=False,
            owner_person_id=owner.id if owner else None,
            custodian_team_id=team.id if team else None,
            synced_at=T0,
        )
        self.session.add(asset)
        self.session.flush()
        instance = m.InstalledSoftware(
            itop_instance_id=f"SI-{uuid.uuid4().hex[:8]}",
            asset_id=asset.id,
            software_product_id=self.group.software_product_id,
            version="1.24.0",
            synced_at=T0,
        )
        self.session.add(instance)
        self.session.flush()
        finding = m.Finding(
            finding_group_id=self.group.id, installed_software_id=instance.id, match_source="nvd_cpe", created_at=T0
        )
        self.session.add(finding)
        self.session.flush()
        self.assets[name] = asset
        self.findings[name] = finding
        return asset

    def run(self, kind: str = "scan") -> m.Run:
        run = m.Run(kind=kind, status="succeeded", progress=100, trigger_reason="manual", started_at=self.clock)
        self.session.add(run)
        self.session.flush()
        return run

    def scan(self, statuses: dict[str, str], run: m.Run | None = None) -> m.Run:
        run = run or self.run()
        for name, status in statuses.items():
            self.session.add(
                m.FindingStatusChange(
                    finding_id=self.findings[name].id,
                    run_id=run.id,
                    status=status,
                    observed_version="1.24.0",
                    changed_at=self.clock,
                )
            )
        self.session.flush()
        return run

    def assess(self, finals: dict[str, int], run: m.Run, *, judge: int = 0) -> m.Assessment:
        assessment = m.Assessment(
            finding_group_id=self.group.id,
            run_id=run.id,
            formula_version_id=self.formula_id,
            trigger="new_finding",
            factor_s=Decimal("0.8"),
            factor_p=Decimal("0.5"),
            factor_t=Decimal("0.2"),
            judge_adjustment=judge,
            assessed_at=self.clock,
        )
        self.session.add(assessment)
        self.session.flush()
        for name, final in finals.items():
            asset = self.assets[name]
            self.session.add(
                m.AssetScore(
                    assessment_id=assessment.id,
                    asset_id=asset.id,
                    factor_a=Decimal("0.8"),
                    factor_d=Decimal("0.5"),
                    version_factor=Decimal("1.00"),
                    base=max(final - judge, 0),
                    ci_adjustment=0,
                    final=final,
                    snap_criticality=asset.criticality,
                    snap_exposed=asset.exposed,
                    snap_confidentiality=asset.confidentiality,
                    snap_personal_data=asset.personal_data,
                    snap_owner_person_id=asset.owner_person_id,
                    snap_custodian_team_id=asset.custodian_team_id,
                )
            )
        self.session.flush()
        return assessment

    def later(self, **delta: float) -> None:
        self.clock += timedelta(**delta)
