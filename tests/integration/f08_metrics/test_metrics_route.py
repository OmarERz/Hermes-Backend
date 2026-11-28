"""GET /api/metrics reads the F8 dashboard from the database (FRO-21)."""

from __future__ import annotations

from datetime import date
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy.orm import Session, sessionmaker

from api.app import create_app
from api.auth import CurrentUser, Role, get_current_user
from core.config import Settings
from core.db import models as m

pytestmark = pytest.mark.integration
SETTINGS = Settings(
    _env_file=None,
    database_url=SecretStr("postgresql://a:b@db/h"),
    firebase_project_id="p",
    cursor_signing_key=SecretStr("k" * 40),
)


def test_the_route_returns_the_stored_metrics(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        session.add(
            m.DailyMetric(metric_date=date(2026, 11, 21), metric_code="precision", dimension="", value=Decimal("0.9"))
        )
    app = create_app(SETTINGS)
    app.state.session_factory = factory
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid="u", email="reader@example.test", display_name=None, role=Role.READER
    )

    with TestClient(app) as client:
        body = client.get("/api/metrics").json()

    assert {
        "key": "precision",
        "label": "Precisión",
        "value": "90.0",
        "unit": "%",
        "as_of": "2026-11-21",
        "description": None,
    } in body["metrics"]
    assert body["metrics"][-1] == {
        "key": "judge_ladder_level",
        "label": "Nivel de la escalera del juez",
        "value": "0 · Normal",
        "unit": None,
        "as_of": None,
        "description": None,
    }
    assert body["generated_at"].endswith("Z")


def test_the_route_returns_the_accepted_original_score(factory: sessionmaker[Session]) -> None:
    """RE-9 (F18.2): «Aceptar puntaje original» is on the board, in the judge section next to «Prioridad incorrecta»."""
    with factory() as session, session.begin():
        for code, value in (("wrong_priority_judged", "0.25"), ("original_score_accepted", "0.5")):
            session.add(
                m.DailyMetric(metric_date=date(2026, 11, 21), metric_code=code, dimension="", value=Decimal(value))
            )
    app = create_app(SETTINGS)
    app.state.session_factory = factory
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid="u", email="reader@example.test", display_name=None, role=Role.READER
    )

    with TestClient(app) as client:
        metrics = client.get("/api/metrics").json()["metrics"]

    assert [x["key"] for x in metrics] == ["wrong_priority_judged", "original_score_accepted", "judge_ladder_level"]
    assert metrics[1] == {
        "key": "original_score_accepted",
        "label": "«Aceptar puntaje original» en ajustes del juez",
        "value": "50.0",
        "unit": "%",
        "as_of": "2026-11-21",
        "description": None,
    }


def test_the_noise_avoided_metric_says_its_scope_and_date(factory: sessionmaker[Session]) -> None:
    """Rehearsal 2, P2-C: the comparison screen said 34 (live, every current finding) and the board 0 (the nightly
    value of the previous UTC day). The numbers stay; the board now says what its figure covers and for which day."""
    with factory() as session, session.begin():
        session.add(
            m.DailyMetric(metric_date=date(2026, 11, 27), metric_code="noise_avoided", dimension="", value=Decimal(0))
        )
    app = create_app(SETTINGS)
    app.state.session_factory = factory
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid="u", email="reader@example.test", display_name=None, role=Role.READER
    )

    with TestClient(app) as client:
        metrics = client.get("/api/metrics").json()["metrics"]

    noise = next(x for x in metrics if x["key"] == "noise_avoided")
    assert (noise["value"], noise["as_of"]) == ("0", "2026-11-27")
    assert noise["description"] == (
        "Puntajes de CI con CVSS de 9.0 o más y final menor a 50, entre las evaluaciones del día UTC anterior, al "
        "cierre de la noche anterior. La pantalla de comparación la calcula en vivo sobre los hallazgos vigentes, así "
        "que puede dar otra cifra."
    )
