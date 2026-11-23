"""The seeded formula v1 loads into the engine and reproduces the docs/06 §8 cases from the database."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from dbprovision import provisioned_database
from sqlalchemy import delete, event, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from core.db.seeds import seed
from core.db.session import make_engine
from core.scoring.engine import Factors, FormulaError, base_score, default_formula
from core.scoring.formula_repo import (
    FormulaVersionNotFoundError,
    NoActiveFormulaError,
    load_active_formula,
    load_formula,
)

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def sessions(postgres_url: str) -> Iterator[sessionmaker[Session]]:
    with provisioned_database(postgres_url, "formula") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        engine = make_engine(db.superuser_url)
        try:
            yield sessionmaker(engine, expire_on_commit=False)
        finally:
            engine.dispose()


def test_seeded_formula_equals_the_default(sessions: sessionmaker[Session]) -> None:
    with sessions.begin() as session:
        seed(session, "empty")
    with sessions() as session:
        version_id, formula = load_active_formula(session)
        active_id = session.scalar(select(m.FormulaVersion.id).where(m.FormulaVersion.status == "active"))
    reference = default_formula()
    assert version_id == active_id
    assert formula.s_without_cvss == reference.s_without_cvss
    assert formula.weights == reference.weights
    assert {f: dict(v) for f, v in formula.levels.items()} == {f: dict(v) for f, v in reference.levels.items()}
    assert (formula.personal_data_bonus, formula.dead_zone, formula.kev_exposed_floor) == (Decimal("0.2"), 4, 90)
    assert dict(formula.urgency_bands) == dict(reference.urgency_bands)
    assert tuple(formula.decay) == tuple(reference.decay)
    assert (
        base_score(formula, Factors(Decimal("0.70"), Decimal("1.0"), Decimal("1.0"), Decimal("0.8"), Decimal("0.5")))
        == 85
    )


def test_dead_zone_comes_from_the_setting(sessions: sessionmaker[Session]) -> None:
    with sessions.begin() as session:
        seed(session, "empty")
        session.execute(
            text(
                "INSERT INTO setting_value (setting_key, version, value, origin, changed_at) "
                "VALUES ('dead_zone', 1, '6'::jsonb, 'frontend', now())"
            )
        )
    with sessions() as session:
        assert load_active_formula(session)[1].dead_zone == 6


def test_no_active_version(sessions: sessionmaker[Session]) -> None:
    with sessions() as session, pytest.raises(NoActiveFormulaError):
        load_active_formula(session)


def test_a_broken_version_fails_loudly(sessions: sessionmaker[Session]) -> None:
    with sessions.begin() as session:
        seed(session, "empty")
    with sessions.begin() as session:
        version_id = session.scalar(select(m.FormulaVersion.id))
        assert version_id is not None
        # The database already enforces weights and level order; a missing bonus level is caught by the loader.
        session.execute(
            delete(m.FormulaLevel).where(
                m.FormulaLevel.formula_version_id == version_id, m.FormulaLevel.is_bonus.is_(True)
            )
        )
    with sessions() as session, pytest.raises(FormulaError):
        load_formula(session, version_id)


def test_unknown_version_id(sessions: sessionmaker[Session]) -> None:
    with sessions() as session, pytest.raises(FormulaVersionNotFoundError) as info:
        load_formula(session, uuid.uuid4())
    assert not isinstance(info.value, NoActiveFormulaError)


def test_a_draft_version_loads_by_id(sessions: sessionmaker[Session]) -> None:
    with sessions.begin() as session:
        seed(session, "empty")
    with sessions.begin() as session:
        session.execute(update(m.FormulaVersion).values(status="draft"))
    with sessions() as session:
        version_id = session.scalar(select(m.FormulaVersion.id))
        assert version_id is not None
        with pytest.raises(NoActiveFormulaError):
            load_active_formula(session)
        assert load_formula(session, version_id).kev_exposed_floor == 90


@pytest.mark.parametrize("raw", ['"abc"', "true", "[1]"])
def test_non_integer_dead_zone_is_a_formula_error(sessions: sessionmaker[Session], raw: str) -> None:
    with sessions.begin() as session:
        seed(session, "empty")
        session.execute(
            text(
                "INSERT INTO setting_value (setting_key, version, value, origin, changed_at) "
                "VALUES ('dead_zone', 1, CAST(:raw AS jsonb), 'frontend', now())"
            ),
            {"raw": raw},
        )
    with sessions() as session, pytest.raises(FormulaError, match="dead_zone"):
        load_active_formula(session)


def test_string_dead_zone_is_accepted(sessions: sessionmaker[Session]) -> None:
    with sessions.begin() as session:
        seed(session, "empty")
        session.execute(
            text(
                "INSERT INTO setting_value (setting_key, version, value, origin, changed_at) "
                "VALUES ('dead_zone', 1, '\"5\"'::jsonb, 'frontend', now())"
            )
        )
    with sessions() as session:
        assert load_active_formula(session)[1].dead_zone == 5


def test_missing_dead_zone_definition_uses_the_documented_default(sessions: sessionmaker[Session]) -> None:
    with sessions.begin() as session:
        seed(session, "empty")
        session.execute(text("DELETE FROM setting_definition WHERE key = 'dead_zone'"))
    with sessions() as session:
        assert load_active_formula(session)[1].dead_zone == 4


def test_the_formula_is_read_in_a_single_statement(sessions: sessionmaker[Session]) -> None:
    """One statement is one snapshot under READ COMMITTED: a formula change committed while it loads can never mix
    two versions, or a version with another dead zone (pending #107)."""
    with sessions.begin() as session:
        seed(session, "empty")
    statements: list[str] = []

    def count(_conn: object, _cursor: object, statement: str, *_args: object) -> None:
        statements.append(statement)

    engine = sessions.kw["bind"]
    event.listen(engine, "before_cursor_execute", count)
    try:
        with sessions() as session:
            version_id, _ = load_active_formula(session)
            load_formula(session, version_id)
    finally:
        event.remove(engine, "before_cursor_execute", count)
    assert len(statements) == 2  # one per call, each with the version, its rows and the dead zone
    assert all("formula_version" in s and "setting_current" in s for s in statements)
