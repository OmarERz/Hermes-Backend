"""The recalculation commits per group (real transactions, own database): a formula saved by an administrator after
the first group is committed is the one the next group uses (F-17)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from correlation_support import NOW, add_group
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from core.configuration import service
from core.db import models as m
from core.db.session import make_engine
from core.pipeline.wiring import engine_recalculate
from core.scoring import evaluate

pytestmark = pytest.mark.integration
SKEWED = {"weights.S": "0.60", "weights.P": "0.10", "weights.T": "0.10", "weights.A": "0.10", "weights.D": "0.10"}


def assessed_with(factory: sessionmaker[Session], group_id: uuid.UUID, run_id: uuid.UUID) -> list[uuid.UUID]:
    with factory() as other:
        return list(
            other.scalars(
                select(m.Assessment.formula_version_id).where(
                    m.Assessment.finding_group_id == group_id, m.Assessment.run_id == run_id
                )
            )
        )


def test_a_formula_saved_after_the_first_group_reaches_the_second(
    migrated_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = make_engine(migrated_url)
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as session, session.begin():
        first, second = add_group(session, "CVE-2026-40001").id, add_group(session, "CVE-2026-40002").id
        old_version = evaluate.load_active_formula(session)[0]
        assert service.current_values(session)["weights.S"] != SKEWED["weights.S"]
    order = [first, second]
    load, real_evaluate = evaluate.load_active_groups, evaluate.evaluate_group
    new_versions: list[uuid.UUID] = []

    def two(session: Session, only: Any = None) -> Any:
        if only is not None:
            return load(session, only=only)
        return sorted((g for g in load(session) if g.id in order), key=lambda g: order.index(g.id))

    def evaluate_between(session: Session, group_id: uuid.UUID, run_id: uuid.UUID, *args: Any) -> Any:
        if group_id == second:
            # The first group is committed (seen from another connection) with the formula of that moment...
            assert assessed_with(factory, first, run_id) == [old_version]
            # ...then an administrator saves new weights before the second group is scored.
            with factory() as admin, admin.begin():
                actor = service.Actor(user_id=None, role="admin", now=NOW)
                service.update(admin, actor, service.current_version(admin), SKEWED)
                new_versions.append(evaluate.load_active_formula(admin)[0])
        return real_evaluate(session, group_id, run_id, *args)

    monkeypatch.setattr("core.scoring.evaluate.load_active_groups", two)
    monkeypatch.setattr("core.scoring.evaluate.evaluate_group", evaluate_between)
    try:
        with factory() as session:
            report = engine_recalculate(None)(session)  # the nightly entry point of the worker
        assert report.groups == len(order)
        assert new_versions and new_versions[0] != old_version
        assert assessed_with(factory, second, report.run_id) == new_versions
        with factory() as other:
            assert other.get_one(m.Run, report.run_id).status == "succeeded"
    finally:
        engine.dispose()
