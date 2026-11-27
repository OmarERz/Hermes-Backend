"""Seed scenarios load on the migrated database and satisfy every constraint (deferred ones at commit)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from dbprovision import provisioned_database
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.seeds import SCENARIOS, seed
from core.db.session import make_engine

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def migrated(postgres_url: str) -> Iterator[str]:
    with provisioned_database(postgres_url, "seeds") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        yield db.superuser_url


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_scenario_commits(migrated: str, scenario: str) -> None:
    engine = make_engine(migrated)
    try:
        with Session(engine) as session, session.begin():
            seed(session, scenario)
        with Session(engine) as session:
            active = session.scalars(select(m.FormulaVersion).where(m.FormulaVersion.status == "active")).one()
            weights = session.scalar(
                select(func.sum(m.FormulaWeight.weight)).where(m.FormulaWeight.formula_version_id == active.id)
            )
            assert weights == 1
            assert session.scalar(select(func.count()).select_from(m.JudgeReasonType)) == 9
            assert session.scalar(select(func.count()).select_from(m.SettingDefinition)) > 30
            findings = session.scalar(select(func.count()).select_from(m.Finding))
            assert findings == {"empty": 0, "demo": 2, "edge": 4}[scenario]
            keys = set(session.scalars(select(m.SettingDefinition.key)))
            assert {"mode4.weekly_limit", "mode4.cooldown_weeks", "mode4.block_weeks"} <= keys
            assert {"reliability.window_days", "reliability.min_resolved", "reliability.raise"} <= keys
            assert "reliability.lower" in keys
    finally:
        engine.dispose()


def test_demo_group_is_active_and_edge_has_inventory_issues(migrated: str) -> None:
    engine = make_engine(migrated)
    try:
        with Session(engine) as session, session.begin():
            seed(session, "edge")
        with engine.connect() as conn:
            statuses = conn.execute(text("SELECT status FROM finding_group_status")).scalars().all()
            assert statuses == ["active", "active"]
            # The orphan CI and the CVE without CVSS reach evaluation: both have findings.
            edge_findings = conn.execute(
                text(
                    "SELECT a.name, g.cve_id FROM finding f JOIN finding_group g ON g.id = f.finding_group_id "
                    "JOIN installed_software i ON i.id = f.installed_software_id JOIN asset a ON a.id = i.asset_id "
                    "WHERE g.cve_id = 'CVE-2026-10002' ORDER BY a.name"
                )
            ).all()
            assert [tuple(r) for r in edge_findings] == [
                ("srv-pagos-01", "CVE-2026-10002"),
                ("srv-sin-custodio", "CVE-2026-10002"),
            ]
            issues = {r[0] for r in conn.execute(text("SELECT issue FROM inventory_issue"))}
        assert {"software_unmapped", "exposure_unknown", "unclassified", "owner_missing", "custodian_missing"} <= issues
    finally:
        engine.dispose()


def test_seeding_twice_is_refused(migrated: str) -> None:
    engine = make_engine(migrated)
    try:
        with Session(engine) as session, session.begin():
            seed(session, "empty")
        with Session(engine) as session, pytest.raises(RuntimeError, match="already seeded"):
            seed(session, "empty")
    finally:
        engine.dispose()


def test_unknown_scenario() -> None:
    with pytest.raises(ValueError, match="Unknown scenario"):
        seed(None, "nope")  # type: ignore[arg-type]


def test_demo_inventory_carries_an_itop_licence(migrated: str) -> None:
    """F18.3 (D-088): without iTop the front still sees one installation with its licence."""
    engine = make_engine(migrated)
    try:
        with Session(engine) as session, session.begin():
            seed(session, "demo")
        with engine.connect() as conn:
            licensed = conn.execute(
                text(
                    "SELECT a.itop_ci_id, i.itop_instance_id, l.name, l.perpetual, l.removed_at "
                    "FROM installed_software i JOIN asset a ON a.id = i.asset_id "
                    "JOIN software_licence l ON l.id = i.software_licence_id "
                    "WHERE l.software_product_id = i.software_product_id"
                )
            ).all()
        assert [tuple(r) for r in licensed] == [("CI-1", "SI-1", "Soporte OpenSSL", False, None)]
    finally:
        engine.dispose()
