"""F1.5: the inventory, CPE mapping and STIX export routes over PostgreSQL, with the real role table."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import Engine, event, text
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
    audit = rows(
        engine,
        "SELECT action, entity_id, before ->> 'nvd_vendor', after ->> 'nvd_vendor' FROM audit_log ORDER BY created_at",
    )
    assert audit == [
        ("cpe_mapping_set", str(product), None, "f5"),
        ("cpe_mapping_set", str(product), "f5", "nginx"),
    ]


def test_editing_the_cpe_keeps_the_cna_names(client: TestClient, engine: Engine) -> None:
    product = seed_inventory(engine)
    run(
        engine,
        "INSERT INTO cpe_mapping (software_product_id, nvd_part, nvd_vendor, nvd_product, cna_vendor, cna_product, "
        "origin, mapped_at) VALUES (:p, 'a', 'f5', 'nginx', 'F5 Networks', 'NGINX Plus', 'manual', now())",
        {"p": product},
    )
    as_role(client, Role.ANALYST)
    assert (
        client.put(f"/api/mappings/{product}", json={"cpe": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"}).status_code == 200
    )
    assert rows(engine, "SELECT nvd_vendor, cna_vendor, cna_product FROM cpe_mapping") == [
        ("nginx", "F5 Networks", "NGINX Plus")
    ]


def test_the_mapping_route_stores_the_part_of_the_cpe(client: TestClient, engine: Engine) -> None:
    """D-107 (F20 dry run, P2-1): the kernel is mapped as an operating system (`o`), hardware (`h`) is accepted,
    replacing the mapping replaces the part, and the audit keeps both parts."""
    product = seed_inventory(engine)
    as_role(client, Role.ANALYST)
    kernel = "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
    response = client.put(f"/api/mappings/{product}", json={"cpe": kernel})
    assert response.status_code == 200 and response.json()["cpe"] == kernel
    assert rows(engine, "SELECT nvd_part, nvd_vendor, nvd_product FROM cpe_mapping") == [("o", "linux", "linux_kernel")]
    hardware = "cpe:2.3:h:cisco:asa_5505:-:*:*:*:*:*:*:*"
    assert client.put(f"/api/mappings/{product}", json={"cpe": hardware}).status_code == 200
    assert rows(engine, "SELECT nvd_part, nvd_vendor FROM cpe_mapping") == [("h", "cisco")]
    audit = rows(engine, "SELECT before ->> 'nvd_part', after ->> 'nvd_part' FROM audit_log ORDER BY created_at")
    assert audit == [(None, "o"), ("o", "h")]


def test_the_inventory_and_the_candidates_show_the_stored_part(client: TestClient, engine: Engine) -> None:
    """D-107 (F20 dry run, P2-1): the kernel shows as `cpe:2.3:o:…` in the inventory, and a local candidate takes the
    part its mapping stores (NVD ranges do not keep it)."""
    product = seed_inventory(engine)
    as_role(client, Role.ANALYST)
    kernel = "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
    assert client.put(f"/api/mappings/{product}", json={"cpe": kernel}).status_code == 200
    assert [item["cpe"] for item in client.get("/api/inventory/software").json()["items"]] == [kernel]
    run(engine, "INSERT INTO cve (id) VALUES ('CVE-2026-0002')")
    run(
        engine,
        "INSERT INTO cve_affected_range (cve_id, source, vendor, product) "
        "VALUES ('CVE-2026-0002', 'nvd_cpe', 'linux', 'linux_kernel')",
    )
    found = client.get("/api/cpe/candidates", params={"q": "linux kernel"}).json()
    assert [c["cpe"] for c in found] == [kernel]


def test_the_nvd_dictionary_is_only_queried_when_a_key_is_configured() -> None:
    assert create_app(make_settings()).state.cpe_dictionary is None
    keyed = Settings(
        _env_file=None,
        database_url=SecretStr("postgresql://a:b@db/h"),
        firebase_project_id="p",
        cursor_signing_key=SecretStr("k" * 40),
        nvd_api_key=SecretStr("key"),
    )
    assert create_app(keyed).state.cpe_dictionary is not None


def test_mapping_errors(client: TestClient, engine: Engine) -> None:
    product = seed_inventory(engine)
    as_role(client, Role.ANALYST)
    good = {"cpe": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}
    assert client.put("/api/mappings/not-a-uuid", json=good).status_code == 422  # F12.3: path ids are UUIDs
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
    # Control characters are treated as spaces (every schema-valid query gets a 2xx, Schemathesis ST202).
    control = client.get("/api/cpe/candidates", params={"q": "ngi\x00nx"})
    assert control.status_code == 200
    assert client.get("/api/cpe/candidates", params={"q": "\x01\x02\x03"}).json() == []
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


def test_every_stix_export_is_audited(client: TestClient, engine: Engine) -> None:
    """Who exported what, with which marking (ASVS V16; pendientes F1.5 #50); a refused export leaves no row."""
    with Session(engine) as session, session.begin():
        seed(session, "demo")
    run(
        engine,
        "INSERT INTO app_user (firebase_uid, email, role, active, created_at) "
        "VALUES ('stix-analyst', 'stix-analyst@example.com', 'analyst', true, now())",
    )
    as_role(client, Role.ANALYST, uid="stix-analyst")
    scope = {"scope": "vulnerability", "vulnerability_id": "CVE-2026-10001", "exclude_ultra_classified": True}
    bundle = client.post("/api/stix/export", json=scope).json()
    assert client.post("/api/stix/export", json={"scope": "run"}).status_code == 422
    audit = rows(
        engine,
        "SELECT u.firebase_uid, action, entity_type, entity_id, after ->> 'scope', after ->> 'tlp', "
        "(after ->> 'exclude_ultra_classified')::boolean, (after ->> 'objects')::int FROM audit_log a "
        "JOIN app_user u ON u.id = a.app_user_id WHERE action = 'stix_exported'",
    )
    assert audit == [  # attributed to the analyst who exported, never to the system (NULL actor)
        (
            "stix-analyst",
            "stix_exported",
            "stix_bundle",
            bundle["id"],
            "vulnerability",
            "TLP:AMBER",
            True,
            len(bundle["objects"]),
        )
    ]


def test_pending_rows_carry_their_own_ids_classes_and_the_totals(client: TestClient, engine: Engine) -> None:
    """F18.6: software rows name the product in `software_product_id` (and keep it in `ci_id`), CI rows carry their
    iTop class, and `totals` counts each type past the cap of 200 per list."""
    product = seed_inventory(engine)
    run(
        engine,
        "INSERT INTO software_product (itop_name, first_seen_at) "
        "SELECT 'tool-' || n, now() FROM generate_series(1, 205) n",
    )
    as_role(client, Role.READER)
    body = client.get("/api/pending/inventory").json()
    software = body["software_without_cpe"]
    assert len(software) == 200  # each list is capped (MAX_PAGE)
    assert body["totals"] == {
        "software_without_cpe": 206,
        "without_classification": 1,
        "without_exposure": 1,
        "without_owner": 1,
        "without_custodian": 1,
        "outside_delivery_model": 0,
    }
    nginx = next(i for i in software if i["name"] == "nginx")
    assert (nginx["software_product_id"], nginx["ci_id"], nginx["itop_class"]) == (str(product), str(product), None)
    assert all(i["software_product_id"] == i["ci_id"] and i["itop_class"] is None for i in software)
    for kind in ("without_classification", "without_exposure", "without_owner", "without_custodian"):
        assert [(i["ci_id"], i["itop_class"], i["software_product_id"]) for i in body[kind]] == [
            ("CI-77", "Server", None)
        ]
    assert body["outside_delivery_model"] == []


def test_each_pending_total_is_read_by_the_statement_of_its_list(client: TestClient, engine: Engine) -> None:
    """F18.6 (feature review P1): a list and its total come from one statement, one snapshot, so a CPE mapped or a
    CI synced between two reads can never give a list that contradicts its total."""
    seed_inventory(engine)
    as_role(client, Role.READER)
    reads: list[str] = []

    def record(_conn: Any, _cursor: Any, statement: str, *_args: Any) -> None:
        if "inventory_issue" in statement:
            reads.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    try:
        body = client.get("/api/pending/inventory").json()
    finally:
        event.remove(engine, "before_cursor_execute", record)
    assert len(reads) == 5  # one per list, no separate count
    assert all("count(*) OVER ()" in statement for statement in reads)
    assert body["totals"]["software_without_cpe"] == len(body["software_without_cpe"]) == 1
