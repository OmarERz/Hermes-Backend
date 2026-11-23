"""Smoke test of F13: factory values on a fresh database and one full demo cycle (scan to events), no network."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import sessionmaker

from core.devtools.admin import run_bootstrap
from core.devtools.demo import run_cycle

pytestmark = pytest.mark.integration
NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)


def rows(engine: Engine, statement: str) -> list[tuple[Any, ...]]:
    with engine.connect() as conn:
        return [tuple(r) for r in conn.execute(text(statement))]


def url(engine: Engine) -> str:
    return engine.url.render_as_string(hide_password=False)


COUNTS = (
    "SELECT (SELECT count(*) FROM assessment), (SELECT count(*) FROM asset_score), (SELECT count(*) FROM ticket), "
    "(SELECT count(*) FROM itop_outbox), (SELECT count(*) FROM notification_event), (SELECT count(*) FROM finding), "
    "(SELECT count(*) FROM correlation)"
)
CATALOGS = (
    "SELECT (SELECT count(*) FROM formula_version), (SELECT count(*) FROM source), "
    "(SELECT count(*) FROM setting_definition)"
)


def counts(engine: Engine) -> dict[str, int]:
    names = ("assessment", "asset_score", "ticket", "itop_outbox", "notification_event", "finding", "correlation")
    return dict(zip(names, rows(engine, COUNTS)[0], strict=True))


def test_bootstrap_loads_the_factory_values_once(engine: Engine) -> None:
    assert rows(engine, "SELECT count(*) FROM formula_version") == [(0,)]
    first = run_bootstrap(url(engine), NOW)
    assert first.startswith("factory values loaded") and "source(s) added" in first
    snapshot = rows(engine, CATALOGS)
    again = run_bootstrap(url(engine), NOW)
    assert again.startswith("factory values already present") and "0 source(s) added" in again
    assert rows(engine, CATALOGS) == snapshot
    assert rows(engine, "SELECT status FROM formula_version") == [("active",)]


def test_the_demo_cycle_reaches_assessments_tickets_the_outbox_and_events(engine: Engine) -> None:
    run_bootstrap(url(engine), NOW)
    report = run_cycle(sessionmaker(engine, expire_on_commit=False), NOW)
    assert report.scan_new >= 1 and report.stories == 2 and report.matches >= 1
    assert report.assessments == 2  # one per vulnerability group
    assert report.tickets >= 2  # two custodians across the two groups
    assert report.outbox >= report.tickets and report.events >= report.tickets
    state = counts(engine)
    assert state["asset_score"] >= 3 and state["finding"] >= 3 and state["correlation"] >= 1
    # the demo judge is a stand-in: one accepted reason, no tokens
    assert rows(
        engine, "SELECT model, tokens_input + tokens_output, cost_usd::text FROM llm_review WHERE agent = 'judge'"
    ) == [("demo-double", 0, "0.000000")]
    assert rows(engine, "SELECT reason_code, points, status FROM judge_reason") == [
        ("mass_exploitation", 8, "accepted")
    ]
    # the iTop operations are only stored: nothing is sent
    assert {r[0] for r in rows(engine, "SELECT status FROM itop_outbox")} <= {"pending"}
    assert {r[0] for r in rows(engine, "SELECT event_type FROM notification_event")} == {"new_ticket"}
    # every front view has something to show
    assert rows(engine, "SELECT count(*) FROM finding_group_status WHERE status = 'active'")[0][0] == 2
    assert rows(engine, "SELECT count(*) FROM alert")[0][0] >= 0
    assert rows(engine, "SELECT count(*) FROM inventory_issue")[0][0] >= 1  # the demo server has no owner


def test_running_the_cycle_again_adds_an_assessment_but_no_second_ticket_or_data(engine: Engine) -> None:
    run_bootstrap(url(engine), NOW)
    factory = sessionmaker(engine, expire_on_commit=False)
    run_cycle(factory, NOW)
    first = counts(engine)
    run_cycle(factory, NOW.replace(hour=13))
    second = counts(engine)
    assert second["assessment"] == first["assessment"] + 2
    assert second["ticket"] == first["ticket"] and second["finding"] == first["finding"]
    assert second["correlation"] == first["correlation"]
    assert rows(engine, "SELECT count(*) FROM raw_article")[0][0] == 2
