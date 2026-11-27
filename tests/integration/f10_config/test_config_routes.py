"""F10.1: configuration, profile, peers and source routes over PostgreSQL with the real role table."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from api.app import create_app
from api.auth import CurrentUser, Role, get_current_user
from core.config import Settings
from core.configuration import service
from core.db import models as m
from core.db.seeds import NOW, seed
from core.ingestion.catalog import sync_default_sources
from core.ingestion.ssrf import system_resolver
from core.judge.catalog import load_reason_catalog
from core.pipeline.wiring import engine_recalculate_queued

pytestmark = pytest.mark.integration
APPS: dict[int, Any] = {}


def make_settings() -> Settings:
    return Settings(
        _env_file=None,
        database_url=SecretStr("postgresql://a:b@db/h"),
        firebase_project_id="p",
        cursor_signing_key=SecretStr("k" * 40),
    )


@pytest.fixture
def client(engine: Engine) -> Iterator[TestClient]:
    with Session(engine) as session, session.begin():
        seed(session, "empty")
        sync_default_sources(session, datetime(2026, 11, 20, tzinfo=UTC))
    app = create_app(make_settings())
    app.state.session_factory = sessionmaker(engine, expire_on_commit=False)
    app.state.source_resolver = lambda _host: ["93.184.216.34"]  # a public address: no DNS in tests
    with TestClient(app, raise_server_exceptions=False) as test_client:
        APPS[id(test_client)] = app
        yield test_client


def as_role(client: TestClient, role: Role, uid: str = "u1") -> None:
    APPS[id(client)].dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid=uid, email=f"{uid}@example.com", display_name=None, role=role
    )


def run(engine: Engine, statement: str, params: dict[str, Any] | None = None) -> None:
    with engine.begin() as conn:
        conn.execute(text(statement), params or {})


def rows(engine: Engine, statement: str) -> list[tuple[Any, ...]]:
    with engine.connect() as conn:
        return [tuple(r) for r in conn.execute(text(statement))]


def add_user(engine: Engine, uid: str, role: str) -> None:
    run(
        engine,
        "INSERT INTO app_user (firebase_uid, email, role, active, created_at) VALUES (:u, :e, :r, true, now())",
        {"u": uid, "e": f"{uid}@example.com", "r": role},
    )


def put(client: TestClient, version: int, **changes: str) -> Any:
    return client.put("/api/config", json={"expected_version": version, "changes": changes})


# --- configuration -----------------------------------------------------------------------------------------
def test_schema_lists_the_formula_and_the_settings_catalog(client: TestClient) -> None:
    as_role(client, Role.READER)
    schema = {p["key"]: p for p in client.get("/api/config/schema").json()}
    assert schema["weights.P"]["group"] == "formula" and schema["weights.P"]["min_role"] == "admin"
    assert schema["weights.P"]["validations"] == ["weights_sum_to_one"]
    assert (
        schema["formula.kev_exposed_floor"]["min"] == "80" and schema["formula.kev_exposed_floor"]["type"] == "integer"
    )
    assert schema["levels.D.personal_data_bonus"]["type"] == "decimal"
    assert schema["dead_zone"]["type"] == "integer" and schema["dead_zone"]["level"] in {"free", "validated"}
    assert schema["sensitivity_profile"]["type"] == "enum"
    assert schema["complex_reasoning_mode"]["type"] == "boolean"
    assert "decay.1.multiplier" in schema and "bands.1" in schema
    assert schema["sensitivity_profile"]["options"] == ["broad", "minimal", "normal"]
    assert schema["dead_zone"]["options"] == [] and schema["weights.S"]["options"] == []


def test_get_config_starts_at_the_factory_version(client: TestClient) -> None:
    as_role(client, Role.READER)
    body = client.get("/api/config").json()
    assert body["version"] == 1
    assert body["values"]["weights.S"] and body["values"]["dead_zone"] == "4"
    assert body["values"]["complex_reasoning_mode"] in {"true", "false"}
    versions = client.get("/api/config/versions").json()["items"]
    assert [(v["version"], v["author"]) for v in versions] == [(1, "sistema")]


def test_a_setting_change_makes_a_new_version_and_is_audited(client: TestClient, engine: Engine) -> None:
    add_user(engine, "u1", "admin")
    as_role(client, Role.ADMIN)
    response = put(client, 1, dead_zone="6", sensitivity_profile="broad")
    assert response.status_code == 200, response.text
    assert response.json()["version"] == 2 and response.json()["values"]["dead_zone"] == "6"
    assert client.get("/api/config").json()["values"]["sensitivity_profile"] == "broad"
    audit = rows(
        engine, "SELECT action, entity_id, before ->> 'dead_zone', after -> 'values' ->> 'dead_zone' FROM audit_log"
    )
    assert audit == [("config.update", "2", "4", "6")]
    history = client.get("/api/config/versions").json()["items"]
    assert [v["version"] for v in history] == [2, 1]
    assert history[0]["author"] == "u1@example.com" and history[0]["summary"].startswith("Cambió: ")
    assert rows(engine, "SELECT origin, changed_by IS NOT NULL FROM setting_value ORDER BY setting_key") == [
        ("frontend", True),
        ("frontend", True),
    ]


def test_a_stale_version_is_a_conflict_and_nothing_changes(client: TestClient, engine: Engine) -> None:
    as_role(client, Role.ADMIN)
    assert put(client, 1, dead_zone="6").status_code == 200
    stale = put(client, 1, dead_zone="7")
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "version_conflict"
    assert client.get("/api/config").json()["values"]["dead_zone"] == "6"


def test_identical_values_do_not_make_a_version(client: TestClient) -> None:
    as_role(client, Role.ADMIN)
    assert put(client, 1, dead_zone="4").json()["version"] == 1


@pytest.mark.parametrize(
    ("changes", "issue"),
    [
        ({"nope": "1"}, "unknown_parameter"),
        ({"dead_zone": "abc"}, "invalid_number"),
        ({"dead_zone": "2.5"}, "invalid_number"),
        ({"dead_zone": "99"}, "out_of_range"),
        ({"sensitivity_profile": "gigantic"}, "not_an_option"),
        ({"complex_reasoning_mode": "yes"}, "invalid_boolean"),
        ({"judge_model": "   "}, "empty"),
        ({"weights.Z": "0.1"}, "unknown_parameter"),
        ({"levels.P.nonsense": "0.1"}, "unknown_parameter"),
        ({"weights.S": "oops"}, "invalid_decimal"),
    ],
)
def test_invalid_values_are_422_naming_the_rule(client: TestClient, changes: dict[str, str], issue: str) -> None:
    as_role(client, Role.ADMIN)
    response = put(client, 1, **changes)
    assert response.status_code == 422, response.text
    assert issue in {d["issue"] for d in response.json()["error"]["details"]}


def test_each_parameter_has_its_own_minimum_role(client: TestClient, engine: Engine) -> None:
    as_role(client, Role.ANALYST)
    analyst_keys = [r[0] for r in rows(engine, "SELECT key FROM setting_definition WHERE min_role = 'analyst'")]
    assert analyst_keys, "the seed catalog has parameters an analyst may edit"
    denied = put(client, 1, judge_model="other-model")
    assert denied.status_code == 403 and denied.json()["error"]["details"][0]["issue"] == "requires_admin"
    assert put(client, 1, **{"weights.S": "0.5"}).status_code == 403
    as_role(client, Role.READER)
    assert put(client, 1, dead_zone="6").status_code == 403


FORMULA_ISSUES = [
    ({"weights.S": "0.5"}, "weights_sum_to_one"),
    ({"weights.S": "1.5"}, "weight_out_of_range"),
    ({"levels.P.other": "0.9"}, "levels_not_monotonic"),
    ({"levels.P.kev_or_exploited": "1.2"}, "level_out_of_range"),
    ({"formula.kev_exposed_floor": "70"}, "floor_out_of_range"),
    ({"formula.s_without_cvss": "0.2"}, "s_without_cvss_out_of_range"),
    ({"bands.2": "95"}, "bands_not_ordered"),
    ({"decay.3.multiplier": "0.9"}, "decay_not_decreasing"),
]


@pytest.mark.parametrize(("changes", "issue"), FORMULA_ISSUES)
def test_formula_rules_of_fro_05_are_enforced_by_the_engine(
    client: TestClient, changes: dict[str, str], issue: str
) -> None:
    as_role(client, Role.ADMIN)
    response = put(client, 1, **changes)
    assert response.status_code == 422, response.text
    assert issue in {d["issue"] for d in response.json()["error"]["details"]}
    assert client.get("/api/config").json()["version"] == 1  # nothing was written


def test_a_formula_change_creates_a_new_active_formula_version(client: TestClient, engine: Engine) -> None:
    add_user(engine, "u1", "admin")
    as_role(client, Role.ADMIN)
    values = client.get("/api/config").json()["values"]
    s, d = values["weights.S"], values["weights.D"]
    shift = "0.0500"
    new_s = str(Decimal(s) - Decimal(shift))
    new_d = str(Decimal(d) + Decimal(shift))
    response = put(client, 1, **{"weights.S": new_s, "weights.D": new_d})
    assert response.status_code == 200, response.text
    assert response.json()["version"] == 2
    assert rows(engine, "SELECT version_no, status, origin FROM formula_version ORDER BY version_no") == [
        (1, "superseded", "seed"),
        (2, "active", "frontend"),
    ]
    assert rows(
        engine,
        "SELECT sum(weight)::text FROM formula_weight fw "
        "JOIN formula_version v ON v.id = fw.formula_version_id WHERE v.version_no = 2",
    ) == [("1.0000",)]
    assert rows(
        engine,
        "SELECT count(*) FROM formula_reason_range r "
        "JOIN formula_version v ON v.id = r.formula_version_id WHERE v.version_no = 2",
    ) == rows(
        engine,
        "SELECT count(*) FROM formula_reason_range r "
        "JOIN formula_version v ON v.id = r.formula_version_id WHERE v.version_no = 1",
    )
    assert client.get("/api/config").json()["values"]["weights.S"] == new_s


def test_restore_makes_an_old_version_current_as_a_new_one(client: TestClient, engine: Engine) -> None:
    add_user(engine, "u1", "admin")
    as_role(client, Role.ADMIN)
    values = client.get("/api/config").json()["values"]
    changes = {
        "dead_zone": "7",
        "weights.S": str(Decimal(values["weights.S"]) - Decimal("0.05")),
        "weights.D": str(Decimal(values["weights.D"]) + Decimal("0.05")),
    }
    assert put(client, 1, **changes).json()["version"] == 2
    restored = client.post("/api/config/versions/1/restore", json={"expected_version": 2})
    assert restored.status_code == 200, restored.text
    assert restored.json()["version"] == 3
    assert (
        restored.json()["values"]["dead_zone"] == "4" and restored.json()["values"]["weights.S"] == values["weights.S"]
    )
    assert rows(engine, "SELECT version_no, status FROM formula_version ORDER BY version_no") == [
        (1, "superseded"),
        (2, "superseded"),
        (3, "active"),
    ]
    history = client.get("/api/config/versions").json()["items"]
    assert [v["version"] for v in history] == [3, 2, 1] and history[0]["summary"] == "Restauró la versión 1"
    assert rows(engine, "SELECT action FROM audit_log ORDER BY created_at") == [("config.update",), ("config.restore",)]
    # restoring the state that is already current changes nothing
    assert client.post("/api/config/versions/3/restore", json={"expected_version": 3}).json()["version"] == 3


def test_restore_errors(client: TestClient) -> None:
    as_role(client, Role.ADMIN)
    assert client.post("/api/config/versions/1/restore", json={"expected_version": 9}).status_code == 409
    assert client.post("/api/config/versions/99/restore", json={"expected_version": 1}).status_code == 404
    assert client.post("/api/config/versions/0/restore", json={"expected_version": 1}).status_code == 404
    assert client.post("/api/config/versions/-1/restore", json={"expected_version": 1}).status_code == 404
    assert client.post("/api/config/versions/1/restore").status_code == 422


def test_simulate_validates_against_the_active_formula(client: TestClient) -> None:
    as_role(client, Role.ADMIN)
    assert client.post("/api/formula/simulate", json={"changes": {"weights.S": "0.9"}}).status_code == 422
    ok = client.post("/api/formula/simulate", json={"changes": {"formula.kev_exposed_floor": "95"}})
    assert ok.status_code == 200 and ok.json()["not_simulable"] == []
    assert client.get("/api/config").json()["version"] == 1  # a preview never writes


def simulate(client: TestClient, **changes: str) -> Any:
    return client.post("/api/formula/simulate", json={"changes": changes})


def test_simulate_estimates_the_judge_settings_and_lists_the_rest(client: TestClient) -> None:
    """FRO-04: the profile, the dead zone and the reason switches are simulated; other known parameters come back as
    not simulable; an unknown key or an invalid value is still a 422."""
    as_role(client, Role.ADMIN)
    judge = {"sensitivity_profile": "broad", "dead_zone": "2", "reasons.mass_exploitation.enabled": "false"}
    ok = simulate(
        client, **judge, judge_model="otro", **{"weights.S": client.get("/api/config").json()["values"]["weights.S"]}
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["not_simulable"] == ["judge_model"]
    for bad, issue in (
        ({"nope": "1"}, "unknown_parameter"),
        ({"dead_zone": "11"}, "out_of_range"),
        ({"sensitivity_profile": "wild"}, "not_an_option"),
        ({"reasons.mass_exploitation.enabled": "maybe"}, "invalid_boolean"),
        ({"reasons.nope.enabled": "false"}, "unknown_parameter"),
        ({"reasons.mass_exploitation.points": "5"}, "unknown_parameter"),
    ):
        response = simulate(client, **bad)
        assert response.status_code == 422, bad
        assert issue in {d["issue"] for d in response.json()["error"]["details"]}
    assert client.get("/api/config").json()["version"] == 1


def test_a_simulated_profile_resolves_the_dead_zone_as_a_save_would(client: TestClient, engine: Engine) -> None:
    """FRO-04: the preview shows what saving the same changes stores. A profile alone keeps the dead zone (saving it
    does too); the profile's own dead zone (docs/07 §12) is previewed and saved when it is sent."""
    add_user(engine, "u1", "admin")
    as_role(client, Role.ADMIN)
    assert client.get("/api/config").json()["values"]["dead_zone"] == "4"
    with Session(engine) as session:
        assert service.simulation_input(session, {"sensitivity_profile": "broad"}).formula.dead_zone == 4
        assert (
            service.simulation_input(session, {"sensitivity_profile": "broad", "dead_zone": "2"}).formula.dead_zone == 2
        )
        given = service.simulation_input(session, {"sensitivity_profile": "broad", "dead_zone": "5"})
        assert given.formula.dead_zone == 5 and given.estimate is not None
        only_reasons = service.simulation_input(session, {REASON: "false"})
        assert only_reasons.formula.dead_zone == 4 and only_reasons.estimate is not None
        assert service.simulation_input(session, {"dead_zone": "3"}).estimate is None  # stored proposals kept
    saved = put(client, 1, sensitivity_profile="broad").json()["values"]
    assert saved["sensitivity_profile"] == "broad" and saved["dead_zone"] == "4"  # as previewed


# --- judge reason switches (FRO-03) ----------------------------------------------------------------------------
REASON = "reasons.mass_exploitation.enabled"


def test_schema_and_values_list_one_switch_per_judge_reason(client: TestClient) -> None:
    as_role(client, Role.READER)
    schema = {p["key"]: p for p in client.get("/api/config/schema").json()}
    switch = schema[REASON]
    assert (switch["group"], switch["type"], switch["min_role"], switch["default"]) == (
        "judge",
        "boolean",
        "admin",
        "true",
    )
    assert switch["description"] == "Motivo del juez activo: Explotación masiva con evidencia de los últimos 30 días"
    assert len([k for k in schema if k.startswith("reasons.")]) == 9
    assert client.get("/api/config").json()["values"][REASON] == "true"


def test_switching_a_reason_off_saves_a_formula_version_without_rescoring(client: TestClient, engine: Engine) -> None:
    add_user(engine, "u1", "admin")
    as_role(client, Role.ADMIN)
    response = put(client, 1, **{REASON: "false"})
    assert response.status_code == 200, response.text
    assert response.json()["version"] == 2 and response.json()["values"][REASON] == "false"
    assert rows(
        engine,
        "SELECT r.enabled FROM formula_reason_range r JOIN formula_version v ON v.id = r.formula_version_id "
        "WHERE v.status = 'active' AND r.reason_code = 'mass_exploitation'",
    ) == [(False,)]
    assert rows(engine, "SELECT count(*) FROM formula_version") == [(2,)]
    assert rows(engine, "SELECT count(*) FROM run WHERE kind = 'recalculation'") == [(0,)]  # scores do not use it
    with Session(engine) as session:
        spec = load_reason_catalog(session).get("mass_exploitation")
        assert spec is not None and spec.enabled is False  # the next judge review sees it at once
    assert put(client, 2, **{REASON: "false"}).json()["version"] == 2  # no change, no version
    restored = client.post("/api/config/versions/1/restore", json={"expected_version": 2})
    assert restored.status_code == 200 and restored.json()["values"][REASON] == "true"
    assert restored.json()["version"] == 3
    assert rows(engine, "SELECT count(*) FROM run WHERE kind = 'recalculation'") == [(0,)]


@pytest.mark.parametrize("claimed", [False, True])
def test_a_reason_switch_never_cancels_a_formula_recalculation(
    client: TestClient, engine: Engine, claimed: bool
) -> None:
    """FRO-08: a weights save queues its pass; a reason switch saved before the worker checks the request (still
    queued, or already claimed) supersedes that version without queueing its own. The worker sees the same engine
    formula, runs the pass with the active version and records it on the run."""
    add_user(engine, "u1", "admin")
    as_role(client, Role.ADMIN)
    values = client.get("/api/config").json()["values"]
    shifted = {
        "weights.S": str(Decimal(values["weights.S"]) - Decimal("0.05")),
        "weights.D": str(Decimal(values["weights.D"]) + Decimal("0.05")),
    }
    assert put(client, 1, **shifted).json()["version"] == 2
    ((request,),) = rows(engine, "SELECT id FROM run WHERE kind = 'recalculation' AND status = 'queued'")
    if claimed:  # the worker took it but has not checked the formula yet
        run(engine, "UPDATE run SET status = 'running' WHERE id = :i", {"i": request})
    assert put(client, 2, **{REASON: "false"}).json()["version"] == 3
    assert rows(engine, "SELECT count(*) FROM run WHERE kind = 'recalculation'") == [(1,)]  # the switch queued none
    with Session(engine) as session:
        report = engine_recalculate_queued(None)(session, request)
    assert report is not None  # the pass ran instead of finishing as superseded
    assert rows(
        engine,
        "SELECT r.status, r.formula_version_id = v.id FROM run r JOIN formula_version v ON v.status = 'active' "
        "WHERE r.kind = 'recalculation'",
    ) == [("succeeded", True)]


def test_a_request_superseded_by_another_formula_still_finishes_without_a_pass(
    client: TestClient, engine: Engine
) -> None:
    """A later save that changes the engine formula queued its own pass: the older request has nothing left to do."""
    add_user(engine, "u1", "admin")
    as_role(client, Role.ADMIN)
    assert put(client, 1, **{"formula.kev_exposed_floor": "95"}).json()["version"] == 2
    ((older,),) = rows(engine, "SELECT id FROM run WHERE kind = 'recalculation' AND status = 'queued'")
    assert put(client, 2, **{"formula.kev_exposed_floor": "96"}).json()["version"] == 3
    with Session(engine) as session:
        assert engine_recalculate_queued(None)(session, older) is None
    with engine.connect() as conn:
        assert conn.execute(text("SELECT status FROM run WHERE id = :i"), {"i": older}).scalar_one() == "succeeded"


def test_a_reason_switch_with_a_formula_edit_saves_one_version(client: TestClient, engine: Engine) -> None:
    add_user(engine, "u1", "admin")
    as_role(client, Role.ADMIN)
    response = put(client, 1, **{REASON: "false", "formula.kev_exposed_floor": "95"})
    assert response.status_code == 200 and response.json()["version"] == 2
    assert rows(engine, "SELECT count(*) FROM formula_version") == [(2,)]
    assert rows(engine, "SELECT count(*) FROM run WHERE kind = 'recalculation'") == [(1,)]


def test_reason_switches_need_an_admin_and_a_boolean(client: TestClient) -> None:
    as_role(client, Role.ANALYST)
    assert put(client, 1, **{REASON: "false"}).status_code == 403
    as_role(client, Role.ADMIN)
    for key, value, issue in (
        (REASON, "no", "invalid_boolean"),
        ("reasons.nope.enabled", "false", "unknown_parameter"),
        ("reasons.mass_exploitation", "false", "unknown_parameter"),
    ):
        response = put(client, 1, **{key: value})
        assert response.status_code == 422 and issue in {d["issue"] for d in response.json()["error"]["details"]}


# --- profile ---------------------------------------------------------------------------------------------------
def sector_codes(engine: Engine) -> list[str]:
    return [r[0] for r in rows(engine, "SELECT code FROM sector ORDER BY code")]


def test_profile_round_trip_with_versions_and_audit(client: TestClient, engine: Engine) -> None:
    add_user(engine, "u1", "admin")
    as_role(client, Role.ADMIN)
    first = client.get("/api/profile").json()
    assert first == {"sector": "", "subsectors": [], "countries": [], "language": "es", "version": 1}
    primary, other = sector_codes(engine)[:2]
    body = {
        "expected_version": 1,
        "sector": primary,
        "subsectors": [other],
        "countries": ["MX", "US"],
        "language": "es",
    }
    saved = client.put("/api/profile", json=body)
    assert saved.status_code == 200, saved.text
    assert saved.json() == {
        "sector": primary,
        "subsectors": [other],
        "countries": ["MX", "US"],
        "language": "es",
        "version": 2,
    }
    assert client.get("/api/profile").json() == saved.json()
    assert client.put("/api/profile", json=body).status_code == 409  # stale
    assert rows(engine, "SELECT action, entity_id FROM audit_log") == [("profile.update", "1")]
    again = client.put("/api/profile", json={**body, "expected_version": 2, "subsectors": [], "countries": ["MX"]})
    assert again.json()["version"] == 3 and again.json()["countries"] == ["MX"]
    assert rows(engine, "SELECT count(*) FROM profile_sector") == [(1,)]


@pytest.mark.parametrize(
    "override",
    [
        {"sector": "no-such-sector"},
        {"countries": ["mx"]},
        {"countries": ["MX", "MX"]},
        {"language": "español!"},
    ],
)
def test_profile_validation(client: TestClient, engine: Engine, override: dict[str, Any]) -> None:
    as_role(client, Role.ADMIN)
    body = {
        "expected_version": 1,
        "sector": sector_codes(engine)[0],
        "subsectors": [],
        "countries": ["MX"],
        "language": "es",
        **override,
    }
    assert client.put("/api/profile", json=body).status_code == 422


def test_profile_subsector_cannot_repeat_the_sector(client: TestClient, engine: Engine) -> None:
    as_role(client, Role.ADMIN)
    code = sector_codes(engine)[0]
    body = {"expected_version": 1, "sector": code, "subsectors": [code], "countries": [], "language": "es"}
    assert client.put("/api/profile", json=body).status_code == 422


# --- peers -------------------------------------------------------------------------------------------------------
def peer_body(engine: Engine, **override: Any) -> dict[str, Any]:
    return {
        "name": "Tienda Ejemplo",
        "aliases": ["TiendaEj"],
        "domain": "tienda.example.test",
        "sector": sector_codes(engine)[0],
        "country": "MX",
        **override,
    }


def test_peer_crud_with_audit(client: TestClient, engine: Engine) -> None:
    add_user(engine, "u1", "admin")
    as_role(client, Role.ADMIN)
    created = client.post("/api/peer-companies", json=peer_body(engine))
    assert created.status_code == 201, created.text
    peer = created.json()
    uuid.UUID(peer["id"])
    assert peer["aliases"] == ["TiendaEj"]
    listed = client.get("/api/peer-companies").json()["items"]
    assert [p["id"] for p in listed] == [peer["id"]]
    updated = client.put(
        f"/api/peer-companies/{peer['id']}",
        json=peer_body(engine, name="Tienda Nueva", aliases=["B", "A", "A"], domain=None),
    )
    assert updated.status_code == 200 and updated.json()["aliases"] == ["A", "B"] and updated.json()["domain"] is None
    assert client.delete(f"/api/peer-companies/{peer['id']}").status_code == 204
    assert client.get("/api/peer-companies").json()["items"] == []
    assert [r[0] for r in rows(engine, "SELECT action FROM audit_log ORDER BY created_at")] == [
        "peer_company.create",
        "peer_company.update",
        "peer_company.delete",
    ]
    assert rows(engine, "SELECT count(*) FROM peer_company_alias") == [(0,)]


def test_peer_errors(client: TestClient, engine: Engine) -> None:
    as_role(client, Role.ADMIN)
    first = client.post("/api/peer-companies", json=peer_body(engine)).json()
    assert client.post("/api/peer-companies", json=peer_body(engine, name="tienda ejemplo")).status_code == 409
    bad_sector = peer_body(engine, name="V1", aliases=[], sector="nope")
    bad_country = peer_body(engine, name="V2", aliases=[], country="mx")
    assert client.post("/api/peer-companies", json=bad_sector).status_code == 422
    assert client.post("/api/peer-companies", json=bad_country).status_code == 422
    clash = client.post("/api/peer-companies", json=peer_body(engine, name="Otra"))
    assert clash.status_code == 409 and clash.json()["error"]["details"][0]["issue"] == "duplicate_alias"
    other = client.post("/api/peer-companies", json=peer_body(engine, name="Otra", aliases=["Otra Co"])).json()
    assert client.put(f"/api/peer-companies/{other['id']}", json=peer_body(engine)).status_code == 409
    assert client.put(f"/api/peer-companies/{uuid.uuid4()}", json=peer_body(engine, name="Z")).status_code == 404
    assert client.put("/api/peer-companies/not-a-uuid", json=peer_body(engine, name="Z")).status_code == 422  # F12.3
    assert client.delete(f"/api/peer-companies/{uuid.uuid4()}").status_code == 404
    assert (
        client.put(f"/api/peer-companies/{first['id']}", json=peer_body(engine, name="Tienda Ejemplo")).status_code
        == 200
    )


def test_a_peer_cited_by_news_cannot_be_deleted(client: TestClient, engine: Engine) -> None:
    as_role(client, Role.ADMIN)
    peer = client.post("/api/peer-companies", json=peer_body(engine)).json()
    with Session(engine) as session, session.begin():
        scan = m.Run(kind="scan", status="succeeded", progress=100, trigger_reason="manual", started_at=NOW)
        source = session.scalars(text("SELECT id FROM source LIMIT 1")).one()
        session.add(scan)
        session.flush()
        fetch = m.SourceFetch(source_id=source, run_id=scan.id, started_at=NOW, status="ok", items_new=1)
        session.add(fetch)
        session.flush()
        article = m.RawArticle(
            source_fetch_id=fetch.id,
            canonical_url="https://news.example/a",
            title="t",
            published_at=NOW,
            captured_at=NOW,
            is_suspicious=False,
        )
        session.add(article)
        session.flush()
        story = m.Story(representative_article_id=article.id, relevance_status="relevant", created_at=NOW)
        session.add(story)
        session.flush()
        review = m.LlmReview(
            agent="news_analyst",
            model="m",
            response_model={},
            prompt_version="1",
            prompt_hash="h",
            schema_version="1",
            schema_hash="h",
            parameters={},
            input_ref="x",
            calls=[],
            status="applied",
            attempts=1,
            tokens_input=0,
            tokens_cached=0,
            tokens_output=0,
            tokens_reasoning=0,
            cost_usd=Decimal(0),
            latency_ms=1,
            ladder_level=0,
            created_at=NOW,
        )
        session.add(review)
        session.flush()
        analysis = m.NewsAnalysis(
            story_id=story.id, llm_review_id=review.id, summary="s", event_type="e", output={}, created_at=NOW
        )
        session.add(analysis)
        session.flush()
        session.add(
            m.NewsVictim(analysis_id=analysis.id, name="Tienda", peer_company_id=uuid.UUID(peer["id"]), quote="q")
        )
    response = client.delete(f"/api/peer-companies/{peer['id']}")
    assert response.status_code == 409 and response.json()["error"]["code"] == "conflict"
    assert len(client.get("/api/peer-companies").json()["items"]) == 1


# --- sources -----------------------------------------------------------------------------------------------------
def source_ids(client: TestClient) -> dict[str, dict[str, Any]]:
    return {s["name"]: s for s in client.get("/api/sources").json()["items"]}


def test_sources_list_shows_structural_ones_first(client: TestClient) -> None:
    as_role(client, Role.READER)
    items = client.get("/api/sources").json()["items"]
    assert items and items[0]["structural"] is True and items[0]["type"] == "official"
    assert {s["health"] for s in items} == {"ok"} and all(s["last_capture"] is None for s in items)


def test_a_new_feed_enters_as_n4_and_is_audited(client: TestClient, engine: Engine) -> None:
    add_user(engine, "u1", "admin")
    as_role(client, Role.ADMIN)
    created = client.post("/api/sources", json={"name": "Feed de Prueba", "url": "https://feed.example.test/rss"})
    assert created.status_code == 201, created.text
    body = created.json()
    assert (body["level"], body["structural"], body["type"], body["active"]) == ("N4", False, "feed", False)
    assert rows(engine, "SELECT code, trust_tier, is_custom FROM source WHERE name = 'Feed de Prueba'") == [
        ("feed_de_prueba", "N4", True)
    ]
    assert rows(engine, "SELECT kind, enabled FROM source WHERE code = 'feed_de_prueba'") == [("rss", False)]
    json_feed = client.post("/api/sources", json={"name": "Json", "url": "https://feed.example.test/j", "kind": "json"})
    assert json_feed.status_code == 201
    assert rows(engine, "SELECT kind FROM source WHERE code = 'json'") == [("json",)]
    again = client.post("/api/sources", json={"name": "Feed de Prueba", "url": "https://feed.example.test/rss"})
    assert again.status_code == 201 and rows(engine, "SELECT count(*) FROM source WHERE is_custom") == [(3,)]
    assert rows(engine, "SELECT action FROM audit_log WHERE entity_type = 'source' ORDER BY created_at")[0] == (
        "source.create",
    )


def test_new_feed_rules(client: TestClient, engine: Engine) -> None:
    add_user(engine, "u1", "admin")
    as_role(client, Role.ADMIN)
    assert client.post("/api/sources", json={"name": "X", "url": "http://insecure.test"}).status_code == 422
    secret = client.post("/api/sources", json={"name": "Con llave", "url": "https://feed.example.test/rss?api_key=abc"})
    assert secret.status_code == 422 and secret.json()["error"]["code"] == "validation_error"
    APPS[id(client)].state.source_resolver = lambda _host: ["10.0.0.5"]
    private = client.post("/api/sources", json={"name": "Interno", "url": "https://intranet.example.test/rss"})
    assert private.status_code == 422
    # The real resolver refuses a host that is not a valid name before any DNS lookup (was a 500, Schemathesis).
    APPS[id(client)].state.source_resolver = system_resolver
    garbled = client.post("/api/sources", json={"name": "Conexiones", "url": "https:// \u0087q\u00b6"})
    assert (garbled.status_code, garbled.json()["error"]["code"]) == (422, "validation_error")
    assert rows(engine, "SELECT count(*) FROM source WHERE is_custom") == [(0,)]


def test_a_user_without_an_app_user_row_cannot_write_sources(client: TestClient) -> None:
    as_role(client, Role.ADMIN, uid="ghost")
    denied = client.post("/api/sources", json={"name": "Feed", "url": "https://feed.example.test/rss"})
    assert denied.status_code == 403 and denied.json()["error"]["code"] == "forbidden"


def test_switching_sources_and_levels(client: TestClient, engine: Engine) -> None:
    add_user(engine, "u1", "admin")
    add_user(engine, "u2", "analyst")
    as_role(client, Role.ADMIN)
    own = client.post("/api/sources", json={"name": "Mio", "url": "https://feed.example.test/rss"}).json()
    structural = next(s for s in client.get("/api/sources").json()["items"] if s["structural"])
    as_role(client, Role.ANALYST, uid="u2")
    off = client.patch(f"/api/sources/{own['id']}", json={"active": False})
    assert off.status_code == 200 and off.json()["active"] is False
    assert client.patch(f"/api/sources/{own['id']}", json={"level": "N2"}).status_code == 403
    blocked = client.patch(f"/api/sources/{structural['id']}", json={"active": False})
    assert blocked.status_code == 409 and blocked.json()["error"]["code"] == "structural_source"
    as_role(client, Role.ADMIN)
    assert client.patch(f"/api/sources/{own['id']}", json={"active": True}).json()["active"] is True
    assert client.patch(f"/api/sources/{own['id']}", json={"active": False}).json()["active"] is False
    raised = client.patch(f"/api/sources/{own['id']}", json={"level": "N2"})
    assert raised.status_code == 200 and (raised.json()["level"], raised.json()["type"]) == ("N2", "research")
    assert (
        client.patch(f"/api/sources/{own['id']}", json={"level": "N1"}).status_code == 422
    )  # N1 is for official sources
    assert client.patch(f"/api/sources/{uuid.uuid4()}", json={"active": True}).status_code == 404
    assert client.patch("/api/sources/not-a-uuid", json={"active": True}).status_code == 422  # F12.3: UUID path ids
    actions = [
        r[0] for r in rows(engine, "SELECT action FROM audit_log WHERE entity_type = 'source' ORDER BY created_at")
    ]
    assert actions == ["source.create", "source.enable", "source.disable", "source.trust_tier"]


def test_source_health_comes_from_the_fetch_history(client: TestClient, engine: Engine) -> None:
    as_role(client, Role.READER)
    code = rows(engine, "SELECT id FROM source WHERE enabled ORDER BY code LIMIT 1")[0][0]
    run(
        engine,
        "INSERT INTO run (kind, status, progress, trigger_reason, started_at) "
        "VALUES ('news', 'succeeded', 100, 'schedule', now())",
    )
    run_id = rows(engine, "SELECT id FROM run")[0][0]
    for status, items, minute in (("ok", 7, 1), ("error", 0, 2), ("error", 0, 3), ("error", 0, 4)):
        run(
            engine,
            "INSERT INTO source_fetch (source_id, run_id, started_at, finished_at, status, items_new) "
            "VALUES (:s, :r, '2026-11-20T10:00:00Z'::timestamptz + make_interval(mins => :m), now(), :st, :i)",
            {"s": code, "r": run_id, "st": status, "i": items, "m": minute},
        )
    source = next(s for s in client.get("/api/sources").json()["items"] if s["id"] == str(code))
    assert source["health"] == "failing" and source["items_per_run"] == 0 and source["last_capture"] is not None


@pytest.mark.parametrize("bad", ["a\x00b", "line\nbreak"])
def test_control_characters_and_broken_text_are_refused_everywhere(
    client: TestClient, engine: Engine, bad: str
) -> None:
    add_user(engine, "u1", "admin")
    as_role(client, Role.ADMIN)
    assert put(client, 1, judge_model=bad).status_code == 422
    assert client.put("/api/config", json={"expected_version": 1, "changes": {bad: "1"}}).status_code == 422
    assert client.post("/api/peer-companies", json=peer_body(engine, name=bad)).status_code == 422
    assert client.post("/api/peer-companies", json=peer_body(engine, name="Ok", aliases=[bad])).status_code == 422
    assert client.post("/api/peer-companies", json=peer_body(engine, name="Ok", domain=bad)).status_code == 422
    assert client.post("/api/peer-companies", json=peer_body(engine, name="Ok", sector=bad)).status_code == 422
    profile = {"expected_version": 1, "sector": bad, "subsectors": [], "countries": [], "language": "es"}
    assert client.put("/api/profile", json=profile).status_code == 422
    assert client.post("/api/sources", json={"name": bad, "url": "https://feed.example.test/rss"}).status_code == 422
    assert client.get("/api/config").json()["version"] == 1


def test_a_rejected_patch_changes_nothing(client: TestClient, engine: Engine) -> None:
    add_user(engine, "u1", "admin")
    as_role(client, Role.ADMIN)
    structural = next(s for s in client.get("/api/sources").json()["items"] if s["structural"])
    refused = client.patch(f"/api/sources/{structural['id']}", json={"level": "N2", "active": False})
    assert refused.status_code == 409
    assert next(s for s in client.get("/api/sources").json()["items"] if s["id"] == structural["id"])["level"] == "N1"


def test_a_fresh_install_without_factory_values_answers_a_clear_conflict(client: TestClient, engine: Engine) -> None:
    run(engine, "UPDATE formula_version SET status = 'superseded'")
    as_role(client, Role.ADMIN)
    for url in ("/api/config", "/api/config/schema"):
        response = client.get(url)
        assert response.status_code == 409 and response.json()["error"]["code"] == "conflict"
    assert (
        client.post("/api/formula/simulate", json={"changes": {"formula.kev_exposed_floor": "95"}}).status_code == 409
    )
    assert put(client, 1, dead_zone="5").status_code == 409


def test_formula_values_with_more_places_than_the_database_keeps_are_refused(client: TestClient) -> None:
    as_role(client, Role.ADMIN)
    response = put(client, 1, **{"weights.S": "0.25004", "weights.P": "0.30004", "weights.T": "0.19992"})
    assert response.status_code == 422
    assert "too_many_decimals" in {d["issue"] for d in response.json()["error"]["details"]}


def test_every_formula_save_or_restore_queues_its_own_recalculation_run(client: TestClient, engine: Engine) -> None:
    add_user(engine, "u1", "admin")
    as_role(client, Role.ADMIN)
    queued = "SELECT kind, status, trigger_reason FROM run WHERE kind = 'recalculation' AND status = 'queued'"
    assert put(client, 1, double_review_threshold="16").json()["version"] == 2  # no scoring effect
    assert rows(engine, queued) == []
    values = client.get("/api/config").json()["values"]
    shifted = {
        "weights.S": str(Decimal(values["weights.S"]) - Decimal("0.05")),
        "weights.D": str(Decimal(values["weights.D"]) + Decimal("0.05")),
    }
    assert put(client, 2, **shifted).json()["version"] == 3
    assert rows(engine, queued) == [("recalculation", "queued", "formula_change")]
    with engine.begin() as conn:  # the worker served it
        conn.execute(text("UPDATE run SET status = 'succeeded', finished_at = now() WHERE kind = 'recalculation'"))
    restored = client.post("/api/config/versions/1/restore", json={"expected_version": 3})
    assert restored.status_code == 200, restored.text
    assert rows(engine, queued) == [("recalculation", "queued", "formula_change")]  # the restore queued its own
    again = client.post("/api/config/versions/1/restore", json={"expected_version": 4})
    assert again.status_code == 200 and again.json()["version"] == 4  # nothing differs: no new version, no request
    assert rows(engine, "SELECT count(*) FROM run WHERE kind = 'recalculation'") == [(2,)]


def test_changing_only_the_dead_zone_also_queues_a_recalculation(client: TestClient, engine: Engine) -> None:
    add_user(engine, "u1", "admin")
    as_role(client, Role.ADMIN)
    assert put(client, 1, dead_zone="6").json()["version"] == 2
    assert rows(engine, "SELECT status, formula_version_id IS NOT NULL FROM run WHERE kind = 'recalculation'") == [
        ("queued", True)
    ]


def test_the_schema_publishes_what_each_sensitivity_profile_sets(client: TestClient) -> None:
    """F18.6 (pendientes F12 #199): the front reads each profile's values instead of repeating 6/4/2."""
    as_role(client, Role.READER)
    schema = {p["key"]: p for p in client.get("/api/config/schema").json()}
    values = schema["sensitivity_profile"]["option_values"]
    assert sorted(values) == schema["sensitivity_profile"]["options"]
    assert {name: v["dead_zone"] for name, v in values.items()} == {"broad": "2", "minimal": "6", "normal": "4"}
    assert values["minimal"] == {
        "judge.range_multiplier": "0.5",
        "judge.allow_lowering": "false",
        "dead_zone": "6",
        "mode2.min_confidence": "0.8",
    }
    assert all(p["option_values"] == {} for key, p in schema.items() if key != "sensitivity_profile")
