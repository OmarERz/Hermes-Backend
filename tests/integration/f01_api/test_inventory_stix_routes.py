"""F1.5: the inventory, CPE mapping and STIX export routes over PostgreSQL, with the real role table."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from api.app import create_app
from api.auth import CurrentUser, Role, get_current_user
from core.config import Settings
from core.db.seeds import seed

pytestmark = pytest.mark.integration


def make_settings() -> Settings:
    return Settings(
        _env_file=None,
        database_url=SecretStr("postgresql://a:b@db/h"),
        firebase_project_id="p",
        cursor_signing_key=SecretStr("k" * 40),
    )


@pytest.fixture
def client(engine: Engine) -> Iterator[TestClient]:
    app = create_app(make_settings())
    app.state.session_factory = sessionmaker(engine, expire_on_commit=False)
    app.state.cpe_dictionary = None  # no network in tests
    with TestClient(app, raise_server_exceptions=False) as test_client:
        APPS[id(test_client)] = app
        yield test_client


APPS: dict[int, Any] = {}


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


def seed_inventory(engine: Engine) -> uuid.UUID:
    nginx = uuid.uuid4()
    run(engine, "INSERT INTO team (itop_team_id, name, is_default, synced_at) VALUES ('t1', 'Ops', false, now())")
    run(
        engine,
        "INSERT INTO asset (itop_ci_id, itop_class, name, criticality, confidentiality, synced_at) "
        "VALUES ('CI-77', 'Server', 'orphan-01', 'high', 'unclassified', now())",
    )
    run(engine, "INSERT INTO software_product (id, itop_name, first_seen_at) VALUES (:p, 'nginx', now())", {"p": nginx})
    run(
        engine,
        "INSERT INTO installed_software (itop_instance_id, asset_id, software_product_id, version, synced_at) "
        "SELECT 'i1', a.id, :p, '1.24.0', now() FROM asset a",
        {"p": nginx},
    )
    return nginx


def test_roles_are_enforced_on_the_new_routes(client: TestClient, engine: Engine) -> None:
    product = seed_inventory(engine)
    assert client.get("/api/pending/inventory").status_code == 401
    as_role(client, Role.READER)
    assert client.get("/api/pending/inventory").status_code == 200
    assert client.get("/api/cpe/candidates", params={"q": "nginx"}).status_code == 403
    cpe = {"cpe": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}
    assert client.put(f"/api/mappings/{product}", json=cpe).status_code == 403
    assert client.post("/api/stix/export", json={"scope": "run", "run_id": str(uuid.uuid4())}).status_code == 403
    as_role(client, Role.ANALYST)
    assert client.get("/api/cpe/candidates", params={"q": "nginx"}).status_code == 200


def test_pending_inventory_lists_items_by_kind(client: TestClient, engine: Engine) -> None:
    seed_inventory(engine)
    as_role(client, Role.READER)
    body = client.get("/api/pending/inventory").json()
    assert body["software_without_cpe"][0]["name"] == "nginx"
    assert body["software_without_cpe"][0]["detail"] == "Software sin CPE (1 instalaciones)"
    assert [i["ci_id"] for i in body["without_classification"]] == ["CI-77"]
    assert body["without_owner"][0]["detail"] == "Sin dueño asignado"
    assert body["without_exposure"][0]["name"] == "orphan-01"
    assert body["outside_delivery_model"] == []


def test_mapping_a_product_removes_it_from_the_pending_list(client: TestClient, engine: Engine) -> None:
    product = seed_inventory(engine)
    run(
        engine,
        "INSERT INTO app_user (firebase_uid, email, role, active, created_at) "
        "VALUES ('u1', 'u1@example.com', 'analyst', true, now())",
    )
    as_role(client, Role.ANALYST)
    cpe = "cpe:2.3:a:F5:nginx:1.24.0:*:*:*:*:*:*:*"
    response = client.put(f"/api/mappings/{product}", json={"cpe": cpe})
    assert response.status_code == 200 and response.json() == {"software": str(product), "cpe": cpe}
    assert client.get("/api/pending/inventory").json()["software_without_cpe"] == []
    stored = rows(engine, "SELECT nvd_vendor, nvd_product, origin, mapped_by IS NOT NULL FROM cpe_mapping")
    assert stored == [("f5", "nginx", "manual", True)]
    again = client.put(f"/api/mappings/{product}", json={"cpe": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"})
    assert again.status_code == 200
    assert rows(engine, "SELECT nvd_vendor FROM cpe_mapping") == [("nginx",)]


def test_mapping_errors(client: TestClient, engine: Engine) -> None:
    product = seed_inventory(engine)
    as_role(client, Role.ANALYST)
    good = {"cpe": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}
    assert client.put("/api/mappings/not-a-uuid", json=good).status_code == 404
    assert client.put(f"/api/mappings/{uuid.uuid4()}", json=good).status_code == 404
    assert client.put(f"/api/mappings/{product}", json={"cpe": "nope"}).status_code == 422  # the model's own pattern
    wildcard = client.put(f"/api/mappings/{product}", json={"cpe": "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*"})
    assert wildcard.status_code == 422 and wildcard.json()["error"]["code"] == "validation_error"
    odd = client.put(f"/api/mappings/{product}", json={"cpe": "cpe:2.3:a:f 5:nginx:*:*:*:*:*:*:*:*"})
    assert odd.status_code == 422
    assert rows(engine, "SELECT count(*) FROM cpe_mapping") == [(0,)]


def test_cpe_candidates_come_from_loaded_data_and_validate_the_query(client: TestClient, engine: Engine) -> None:
    run(engine, "INSERT INTO cve (id) VALUES ('CVE-2026-0001')")
    run(
        engine,
        "INSERT INTO cve_affected_range (cve_id, source, vendor, product) "
        "VALUES ('CVE-2026-0001', 'nvd_cpe', 'f5', 'nginx')",
    )
    as_role(client, Role.ANALYST)
    found = client.get("/api/cpe/candidates", params={"q": "nginx"}).json()
    assert found == [{"cpe": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "title": "f5 nginx", "score": 0.5}]
    assert client.get("/api/cpe/candidates", params={"q": "x"}).status_code == 422
    assert client.get("/api/cpe/candidates", params={"q": "ab\x00cd"}).status_code == 422
    assert client.get("/api/cpe/candidates", params={"q": "zzzzzz"}).json() == []


def test_stix_export_by_vulnerability_with_and_without_ultra_classified(client: TestClient, engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        seed(session, "demo")
    as_role(client, Role.ANALYST)
    scope = {"scope": "vulnerability", "vulnerability_id": "CVE-2026-10001"}
    full = client.post("/api/stix/export", json=scope)
    assert full.status_code == 200
    body = full.json()
    assert set(body) == {"type", "id", "objects"} and body["type"] == "bundle"
    marking = next(o for o in body["objects"] if o["type"] == "marking-definition")
    assert marking["name"] == "TLP:RED"
    reduced = client.post("/api/stix/export", json={**scope, "exclude_ultra_classified": True}).json()
    assert next(o for o in reduced["objects"] if o["type"] == "marking-definition")["name"] == "TLP:AMBER"
    assert client.post("/api/stix/export", json={**scope, "exclude_ultra_classified": "yes"}).status_code == 422


@pytest.mark.parametrize(
    "body",
    [
        {"scope": "vulnerability", "vulnerability_id": "not-an-id"},
        {"scope": "run", "run_id": "nope"},
        {"scope": "date_range", "date_from": "yesterday", "date_to": "today"},
        {"scope": "date_range", "date_from": "0001-01-01", "date_to": "9999-12-31"},
        {"scope": "date_range", "date_from": "9999-12-31", "date_to": "9999-12-31"},
        {"scope": "run"},
    ],
)
def test_stix_export_refuses_bad_scope_data_with_422(client: TestClient, body: dict[str, Any]) -> None:
    as_role(client, Role.ANALYST)
    response = client.post("/api/stix/export", json=body)
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "validation_error"
