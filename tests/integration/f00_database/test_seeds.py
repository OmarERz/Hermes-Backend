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
            assert findings == (0 if scenario == "empty" else 2)
    finally:
        engine.dispose()


def test_demo_group_is_active_and_edge_has_inventory_issues(migrated: str) -> None:
    engine = make_engine(migrated)
    try:
        with Session(engine) as session, session.begin():
            seed(session, "edge")
        with engine.connect() as conn:
            assert conn.execute(text("SELECT status FROM finding_group_status")).scalar_one() == "active"
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
