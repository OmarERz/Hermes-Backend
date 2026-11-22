"""Dashboard service for GET /api/metrics: latest value per metric, folded dimensions, ladder level."""

from __future__ import annotations

from datetime import date
from decimal import Decimal

import f08data as d
import pytest
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from core.metrics.dashboard import build_dashboard, format_value

pytestmark = pytest.mark.integration


def put(session: Session, day: date, code: str, value: str, dimension: str = "") -> None:
    session.add(m.DailyMetric(metric_date=day, metric_code=code, dimension=dimension, value=Decimal(value)))


def test_the_dashboard_shows_the_latest_values_formatted(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        put(session, date(2026, 11, 20), "precision", "0.5")
        put(session, date(2026, 11, 21), "precision", "0.875")
        put(session, date(2026, 11, 21), "cost_usd", "0.125", "agent:judge")
        put(session, date(2026, 11, 21), "cost_usd", "0.010", "agent:news_analyst")
        put(session, date(2026, 11, 21), "source_hours_since_ok", "2", "source:thn")
        put(session, date(2026, 11, 21), "source_hours_since_ok", "7.25", "source:tenable")
        put(session, date(2026, 11, 21), "first_pass_validation", "0.9", "agent:judge")
        put(session, date(2026, 11, 21), "first_pass_validation", "0.99", "agent:cve_analyst")
        put(session, date(2026, 11, 21), "notification_failed", "2")
        put(session, date(2026, 11, 21), "unknown_metric", "1")
        session.add(m.JudgeLadderChange(level=2, reason="x", changed_at=d.NOW))
        session.flush()
        dashboard = build_dashboard(session, d.NOW)

    shown = {metric.key: (metric.label, metric.value, metric.unit) for metric in dashboard.metrics}
    assert dashboard.generated_at == d.NOW
    assert shown["precision"] == ("Precisión", "87.5", "%")
    assert shown["cost_usd"] == ("Costo de LLM del día", "0.14", "USD")
    assert shown["source_hours_since_ok"] == ("Fuente más atrasada", "7.3", "h")
    assert shown["first_pass_validation"][1] == "90.0"
    assert shown["notification_failed"] == ("Eventos en error", "2", None)
    assert shown["judge_ladder_level"] == ("Nivel de la escalera del juez", "2 · Cauteloso", None)
    assert "unknown_metric" not in shown
    assert next(x for x in dashboard.metrics if x.key == "precision").as_of == date(2026, 11, 21)


def test_an_empty_database_shows_only_the_ladder(factory: sessionmaker[Session]) -> None:
    with factory() as session:
        dashboard = build_dashboard(session, d.NOW)
    assert [(x.key, x.value) for x in dashboard.metrics] == [("judge_ladder_level", "0 · Normal")]


def test_value_formats() -> None:
    assert format_value(Decimal("0.12345"), "ratio") == "12.3"
    assert format_value(Decimal("3.5"), "count") == "4"
    assert format_value(Decimal("1.005"), "usd") == "1.01"
    assert format_value(Decimal("-4.25"), "points") == "-4.3"
