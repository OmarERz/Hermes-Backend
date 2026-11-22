"""The reason catalog is read from the active formula version (judge_reason_type + formula_reason_range)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

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
from core.judge.catalog import CatalogError, Direction, load_reason_catalog

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def engine(postgres_url: str) -> Iterator[Engine]:
    with provisioned_database(postgres_url, "judgecat") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        engine = make_engine(db.superuser_url)
        try:
            yield engine
        finally:
            engine.dispose()


def test_no_active_formula_is_an_error(engine: Engine) -> None:
    with Session(engine) as session, pytest.raises(CatalogError, match="no active formula"):
        load_reason_catalog(session)


def test_catalog_reflects_edited_ranges_and_disabled_reasons(engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        seed(session, "empty")
    with Session(engine) as session, session.begin():
        active = session.scalars(select(m.FormulaVersion).where(m.FormulaVersion.status == "active")).one()
        ranges = {
            r.reason_code: r
            for r in session.scalars(
                select(m.FormulaReasonRange).where(m.FormulaReasonRange.formula_version_id == active.id)
            )
        }
        ranges["mass_exploitation"].max_points = 25
        ranges["unverified_poc"].enabled = False
        # an inactive version with different values must not leak into the catalog
        draft = m.FormulaVersion(
            id=new_id(),
            version_no=active.version_no + 1,
            status="draft",
            based_on_id=active.id,
            origin="frontend",
            s_without_cvss=active.s_without_cvss,
            kev_exposed_floor=active.kev_exposed_floor,
            hysteresis_margin=active.hysteresis_margin,
            hysteresis_evaluations=active.hysteresis_evaluations,
            hysteresis_days=active.hysteresis_days,
            created_at=active.created_at,
        )
        session.add(draft)
        session.flush()
        session.add_all(
            m.FormulaReasonRange(
                formula_version_id=draft.id,
                reason_code=code,
                min_points=r.min_points,
                max_points=r.max_points if code != "mass_exploitation" else 40,
                enabled=code != "zero_day",
            )
            for code, r in ranges.items()
        )
    with Session(engine) as session:
        catalog = load_reason_catalog(session)
    assert len(catalog.reasons) == 9
    mass = catalog.reasons["mass_exploitation"]
    assert (mass.min_points, mass.max_points, mass.enabled) == (5, 25, True)
    assert not catalog.reasons["unverified_poc"].enabled
    assert catalog.reasons["zero_day"].enabled
    assert catalog.reasons["other"].direction is Direction.BOTH
    assert [code for code, r in catalog.reasons.items() if r.applies_to_asset] == ["more_critical_asset"]
    assert catalog.reasons["requires_authentication"].max_points == -5
