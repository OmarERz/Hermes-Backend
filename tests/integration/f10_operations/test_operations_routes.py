"""Connections, setup wizard and audit trail against PostgreSQL (D-042, SEG-23, API-06)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from f10ops import T0, FakeProbes
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

pytestmark = pytest.mark.integration


def execute(engine: Engine, statement: str, **params: object) -> None:
    with engine.begin() as conn:
        conn.execute(text(statement), params)


def test_connections_status_and_test_never_carry_a_key(client: TestClient, probes: FakeProbes) -> None:
    probes.down = {"ransomwarelive"}
    status = client.get("/api/connections/status").json()
    assert [s["name"] for s in status] == ["itop", "deepseek", "nvd", "abusech", "ransomwarelive", "firebase"]
    itop = status[0]
    assert (itop["ok"], itop["latency_ms"], itop["message"], itop["missing_variable"]) == (
        True,
        12,
        "Conexión correcta",
        None,
    )
    assert itop["checked_at"].endswith("Z") and itop["last_ok_at"] == itop["checked_at"]
    assert (status[4]["ok"], status[4]["missing_variable"], status[4]["last_ok_at"]) == (False, "X", None)
    assert status[4]["message"] == "Variable faltante: X"
    calls = probes.calls
    client.get("/api/connections/status")
    assert probes.calls == calls  # fresh results are reused
    tested = client.post("/api/connections/test", json={"names": ["nvd"]}).json()
    assert [t["name"] for t in tested] == ["nvd"]
    assert client.post("/api/connections/test", json={"names": ["secret_vault"]}).status_code == 422


def test_setup_steps_follow_the_data_and_the_marks(client: TestClient, engine: Engine, probes: FakeProbes) -> None:
    probes.down = {"deepseek"}
    client.post("/api/connections/test", json={})
    steps = client.get("/api/setup/status").json()
    assert [s["name"] for s in steps][:2] == ["Conexiones", "Perfil de la empresa"]
    assert [(s["n"], s["done"], s["skipped"]) for s in steps] == [(n, False, False) for n in range(1, 8)]
    assert all(s["done_source"] is None for s in steps)  # F18.6: nothing is done yet

    skipped = client.put("/api/setup/steps/3", json={"done": True, "skipped": True}).json()
    assert (skipped["n"], skipped["done"], skipped["skipped"]) == (3, False, True)  # skipping wins
    assert skipped["done_source"] is None
    done = client.put("/api/setup/steps/4", json={}).json()
    assert (done["done"], done["skipped"], done["done_source"]) == (True, False, "manual")  # only the mark
    assert client.put("/api/setup/steps/8", json={}).status_code == 404
    assert client.put("/api/setup/steps/0", json={}).status_code == 404

    # Evidence in the data: an inventory and a successful scan; a peer company overrides the skip.
    execute(
        engine,
        "INSERT INTO asset (itop_ci_id, itop_class, name, criticality, confidentiality, synced_at) "
        "VALUES ('CI-1', 'Server', 'srv-1', 'high', 'public', now())",
    )
    execute(
        engine,
        "INSERT INTO run (kind, status, progress, trigger_reason, started_at, finished_at) "
        "VALUES ('scan', 'succeeded', 100, 'manual', now(), now())",
    )
    execute(engine, "INSERT INTO peer_company (name, created_at) VALUES ('Par Uno', now())")
    probes.down = set()
    client.post("/api/connections/test", json={})
    status = {s["n"]: (s["done"], s["skipped"]) for s in client.get("/api/setup/status").json()}
    assert status == {
        1: (True, False),
        2: (False, False),
        3: (True, False),
        4: (True, False),
        5: (True, False),
        6: (False, False),
        7: (True, False),
    }
    # F18.6: the data makes steps 1, 3, 5 and 7 done; step 4 only has its mark
    sources = {s["n"]: s["done_source"] for s in client.get("/api/setup/status").json()}
    assert sources == {1: "data", 2: None, 3: "data", 4: "manual", 5: "data", 6: None, 7: "data"}
    with engine.connect() as conn:
        marks = conn.execute(
            text(
                "SELECT l.entity_id, l.after, u.email FROM audit_log l JOIN app_user u ON u.id = l.app_user_id "
                "WHERE l.action = 'setup.step' ORDER BY l.created_at, l.id"
            )
        ).all()
    assert [(r.entity_id, r.after, r.email) for r in marks] == [
        ("3", {"done": False, "skipped": True}, "luis@example.test"),
        ("4", {"done": True, "skipped": False}, "luis@example.test"),
    ]
    # F18.6: marking a step not done undoes a mark, never what the data shows
    unmarked = client.put("/api/setup/steps/4", json={"done": False}).json()
    assert (unmarked["done"], unmarked["done_source"]) == (False, None)
    kept = client.put("/api/setup/steps/5", json={"done": False}).json()
    assert (kept["done"], kept["done_source"]) == (True, "data")


@pytest.fixture
def audit_rows(engine: Engine) -> None:
    execute(engine, "DELETE FROM audit_log")
    rows = [
        ("luis@example.test", "config.update", "setting", "weights.D", T0),
        ("ana@example.test", "source.enable", "source", "rss_demo", T0 + timedelta(hours=1)),
        (None, "source.down", "source", "nvd", T0 + timedelta(hours=2)),
        ("luis@example.test", "profile.update", "company_profile", "1", T0 + timedelta(days=1)),
    ]
    for email, action, entity_type, entity_id, at in rows:
        execute(
            engine,
            "INSERT INTO audit_log (app_user_id, action, entity_type, entity_id, before, after, created_at) "
            "VALUES ((SELECT id FROM app_user WHERE email = :email), :action, :entity_type, :entity_id, "
            "'{\"secret\": 1}', '{\"secret\": 2}', :at)",
            email=email,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            at=at,
        )


def actions(client: TestClient, **params: object) -> list[str]:
    response = client.get("/api/audit", params=params)
    assert response.status_code == 200, response.text
    return [e["action"] for e in response.json()["items"]]


@pytest.mark.usefixtures("audit_rows")
def test_audit_trail_newest_first_without_values(client: TestClient) -> None:
    body = client.get("/api/audit").json()
    assert [e["action"] for e in body["items"]] == ["profile.update", "source.down", "source.enable", "config.update"]
    first = body["items"][0]
    assert (first["actor"], first["target"], first["created_at"]) == (
        "luis@example.test",
        "company_profile:1",
        "2026-11-21T12:00:00Z",
    )
    assert body["items"][1]["actor"] == "sistema"
    assert "secret" not in client.get("/api/audit").text


@pytest.mark.usefixtures("audit_rows")
@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"actor": "luis@example.test"}, ["profile.update", "config.update"]),
        ({"actor": "LUIS@example.test"}, ["profile.update", "config.update"]),
        ({"actor": "Luis Admin"}, ["profile.update", "config.update"]),
        ({"actor": "sistema"}, ["source.down"]),
        ({"action": "source.enable"}, ["source.enable"]),
        ({"date_from": "2026-11-20T12:30:00Z", "date_to": "2026-11-20T14:00:00Z"}, ["source.down", "source.enable"]),
        ({"actor": "nobody\u0000"}, []),
    ],
)
def test_audit_filters(client: TestClient, params: dict[str, str], expected: list[str]) -> None:
    assert actions(client, **params) == expected


@pytest.mark.usefixtures("audit_rows")
def test_audit_pages_chain_and_refuse_a_foreign_cursor(client: TestClient) -> None:
    seen: list[str] = []
    cursor = None
    while True:
        body = client.get("/api/audit", params={"limit": 3, **({"cursor": cursor} if cursor else {})}).json()
        seen += [e["action"] for e in body["items"]]
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert seen == ["profile.update", "source.down", "source.enable", "config.update"]


def test_audit_refuses_a_cursor_of_another_list(client: TestClient, engine: Engine) -> None:
    for _ in range(2):  # the run list reads the run table (F13.0): two rows give a next page
        execute(
            engine,
            "INSERT INTO run (kind, status, progress, trigger_reason) VALUES ('nightly', 'succeeded', 100, 'schedule')",
        )
    runs_cursor = client.get("/api/runs", params={"limit": 1}).json()["next_cursor"]
    response = client.get("/api/audit", params={"cursor": runs_cursor})
    assert (response.status_code, response.json()["error"]["code"]) == (400, "invalid_cursor")


def test_texts_follow_the_configured_output_language(client: TestClient, engine: Engine, probes: FakeProbes) -> None:
    probes.down = {"nvd"}
    execute(
        engine,
        "INSERT INTO company_profile (id, company_name, output_language, updated_at) VALUES (1, 'X', 'en', now())",
    )
    try:
        tested = client.post("/api/connections/test", json={"names": ["nvd", "itop"]}).json()
        assert [t["message"] for t in tested] == ["Connection OK", "Missing variable: X"]
        assert client.get("/api/setup/status").json()[0]["name"] == "Connections"
    finally:
        execute(engine, "DELETE FROM company_profile")
