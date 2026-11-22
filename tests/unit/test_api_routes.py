"""Sample routes of docs/13 API-06: role table, authorization placeholder, samples, errors and OpenAPI."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from api.app import create_app
from api.auth import CurrentUser, Role, get_current_user
from api.routes._auth import ROUTE_ROLES
from api.routes._events import get_event_queue
from api.routes._state import get_dashboard_source
from api.routes.models import NotificationEventRow
from core.config import Settings
from core.metrics.dashboard import Dashboard, DashboardMetric

pytestmark = pytest.mark.unit

# Outside ROUTE_ROLES: F0.2 auth routes, and the iTop webhook (its own Bearer token, F5.1/ARQ-02).
F0_2_ROUTES = {"/api/health", "/api/me", "/api/admin/users/{uid}/role", "/api/itop/webhook"}
SETTINGS = Settings(  # type: ignore[call-arg]
    _env_file=None,
    database_url=SecretStr("postgresql://a:b@db/h"),
    firebase_project_id="p",
    cursor_signing_key=SecretStr("k" * 40),
)
APP = create_app(SETTINGS)


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(APP, raise_server_exceptions=False) as test_client:
        yield test_client
    APP.dependency_overrides.clear()


def as_role(role: Role) -> None:
    APP.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid="sample-user", email="sample@example.com", display_name=None, role=role
    )


def app_routes() -> set[tuple[str, str]]:
    """(method, path) of every published operation, read from OpenAPI (FastAPI includes routers lazily)."""
    return {
        (method.upper(), path)
        for path, operations in APP.openapi()["paths"].items()
        if path not in F0_2_ROUTES
        for method in operations
    }


def test_every_route_has_a_role_and_every_role_has_a_route() -> None:
    assert app_routes() == set(ROUTE_ROLES)


def test_table_covers_api_06_paths() -> None:
    paths = {path for _, path in ROUTE_ROLES}
    for expected in ("/api/config/schema", "/api/formula/simulate", "/api/runs/{id}/events", "/api/audit"):
        assert expected in paths
    assert len(ROUTE_ROLES) == 46


@pytest.mark.parametrize(("method", "path"), sorted(ROUTE_ROLES))
def test_without_authentication_every_route_answers_401(client: TestClient, method: str, path: str) -> None:
    response = client.request(method, path.replace("{", "x").replace("}", ""))
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_a_lower_role_gets_403(client: TestClient) -> None:
    as_role(Role.READER)
    response = client.post("/api/formula/simulate", json={"changes": {"weights.D": "0.1"}})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"
    as_role(Role.ANALYST)
    assert client.get("/api/audit").status_code == 403
    as_role(Role.ADMIN)
    assert client.get("/api/audit").status_code == 200


GET_SAMPLES = [
    "/api/config/schema",
    "/api/config",
    "/api/config/versions",
    "/api/profile",
    "/api/peer-companies",
    "/api/sources",
    "/api/pending/inventory",
    "/api/cpe/candidates?q=pago",
    "/api/vulnerabilities",
    "/api/vulnerabilities?view=criticality",
    "/api/vulnerabilities?view=asset",
    "/api/vulnerabilities/grp-1",
    "/api/assets/CI-0001",
    "/api/findings/fnd-1/history",
    "/api/comparison/summary",
    "/api/comparison/table",
    "/api/assessments/asm-0001/breakdown",
    "/api/recommendations",
    "/api/recommendations/asm-0001",
    "/api/recommendations/asm-0001/feedback",
    "/api/tickets",
    "/api/alerts",
    "/api/runs",
    "/api/calibration/proposals",
    "/api/connections/status",
    "/api/setup/status",
    "/api/audit",
]


@pytest.mark.parametrize("url", GET_SAMPLES)
def test_get_routes_return_sample_data(client: TestClient, url: str) -> None:
    as_role(Role.ADMIN)
    response = client.get(url)
    assert response.status_code == 200, response.text
    assert response.json()


def test_connection_status_never_contains_a_key(client: TestClient) -> None:
    as_role(Role.ADMIN)
    body = client.get("/api/connections/status").text
    assert "DEEPSEEK_API_KEY" in body  # the variable name, to tell what is missing
    assert "sk-" not in body


def test_pagination_cursor_flow_and_invalid_cursor(client: TestClient) -> None:
    as_role(Role.READER)
    first = client.get("/api/recommendations", params={"limit": 1}).json()
    assert len(first["items"]) == 1
    assert first["next_cursor"]
    second = client.get("/api/recommendations", params={"limit": 1, "cursor": first["next_cursor"]}).json()
    assert second["items"][0]["assessment_id"] == "asm-0002"
    assert second["next_cursor"] is None
    bad = client.get("/api/recommendations", params={"cursor": "tampered.cursor"})
    assert bad.status_code == 400
    assert bad.json()["error"]["code"] == "invalid_cursor"
    assert client.get("/api/recommendations", params={"limit": 500}).status_code == 422


def test_criticality_view_has_a_section_per_band(client: TestClient) -> None:
    as_role(Role.READER)
    bands = client.get("/api/vulnerabilities", params={"view": "criticality"}).json()["bands"]
    assert [b["level"] for b in bands] == ["critical", "high", "medium", "low"]


def test_not_found_uses_the_envelope(client: TestClient) -> None:
    as_role(Role.READER)
    for url in (
        "/api/vulnerabilities/nope",
        "/api/assets/nope",
        "/api/recommendations/nope",
        "/api/findings/x/history",
    ):
        response = client.get(url)
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"


def test_config_write_rules(client: TestClient) -> None:
    as_role(Role.ADMIN)
    stale = client.put("/api/config", json={"expected_version": 1, "changes": {"ui.language": "en"}})
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "version_conflict"
    unknown = client.put("/api/config", json={"expected_version": 3, "changes": {"nope": "1"}})
    assert unknown.status_code == 422
    ok = client.put("/api/config", json={"expected_version": 3, "changes": {"ui.language": "en"}})
    assert ok.status_code == 200
    assert ok.json()["version"] == 4
    assert ok.json()["values"]["weights.P"] == "0.30"


def test_each_parameter_enforces_its_own_minimum_role(client: TestClient) -> None:
    body = {"expected_version": 3, "changes": {"weights.D": "0.10"}}
    as_role(Role.READER)
    denied = client.put("/api/config", json=body)  # admin parameter
    assert denied.status_code == 403
    assert denied.json()["error"]["details"][0] == {"field": "body.changes.weights.D", "issue": "requires_admin"}
    assert client.put("/api/config", json={**body, "changes": {"inventory.cpe_min_score": "0.9"}}).status_code == 403
    assert client.put("/api/config", json={**body, "changes": {"ui.language": "en"}}).status_code == 200  # reader
    as_role(Role.ANALYST)
    assert client.put("/api/config", json={**body, "changes": {"inventory.cpe_min_score": "0.9"}}).status_code == 200
    assert client.put("/api/config", json=body).status_code == 403
    as_role(Role.ADMIN)
    assert client.put("/api/config", json=body).status_code == 200


def test_weights_are_merged_with_the_current_ones_and_must_total_one(client: TestClient) -> None:
    as_role(Role.ADMIN)

    def put(changes: dict[str, str]) -> dict[str, object]:
        response = client.put("/api/config", json={"expected_version": 3, "changes": changes})
        return {
            "status": response.status_code,
            "issue": (response.json().get("error", {}).get("details") or [{}])[0].get("issue"),
        }

    assert put({"weights.D": "0.20"}) == {"status": 422, "issue": "weights_sum_to_one"}  # 0.30+0.30+0.30+0.20
    assert put({"weights.D": "1"}) == {"status": 422, "issue": "weights_sum_to_one"}
    assert put({"weights.D": "0.20", "weights.P": "0.20"})["status"] == 200  # 0.20+0.30+0.30+0.20
    assert put({"weights.D": "-0.1", "weights.P": "0.5"}) == {"status": 422, "issue": "weight_out_of_range"}
    assert put({"weights.D": "1.5", "weights.P": "-0.5"}) == {"status": 422, "issue": "weight_out_of_range"}
    assert put({"weights.D": "x"}) == {"status": 422, "issue": "invalid_decimal"}
    assert put({"ui.language": "en"})["status"] == 200  # no weight touched, current ones stay valid
    simulate = client.post("/api/formula/simulate", json={"changes": {"weights.D": "0.20"}})
    assert simulate.status_code == 422


def test_restore_needs_the_expected_current_version(client: TestClient) -> None:
    as_role(Role.ADMIN)
    assert client.post("/api/config/versions/2/restore", json={"expected_version": 1}).status_code == 409
    assert client.post("/api/config/versions/99/restore", json={"expected_version": 3}).status_code == 404
    ok = client.post("/api/config/versions/2/restore", json={"expected_version": 3})
    assert ok.status_code == 200
    assert ok.json()["version"] == 4
    assert client.post("/api/config/versions/2/restore").status_code == 422  # the version is mandatory


def test_source_level_is_admin_only_but_activation_is_for_analysts(client: TestClient) -> None:
    as_role(Role.ANALYST)
    assert client.patch("/api/sources/src-thn", json={"active": False}).json()["active"] is False
    denied = client.patch("/api/sources/src-thn", json={"level": "N2"})
    assert denied.status_code == 403
    assert denied.json()["error"]["details"][0]["issue"] == "requires_admin"
    assert client.patch("/api/sources/src-thn", json={"active": True, "level": "N2"}).status_code == 403
    as_role(Role.ADMIN)
    assert client.patch("/api/sources/src-thn", json={"level": "N2"}).json()["level"] == "N2"


def test_scan_run_is_listed_and_streams_its_progress(client: TestClient) -> None:
    as_role(Role.ANALYST)
    run = client.post("/api/scans", json={})
    assert run.status_code == 202
    run_id = run.json()["id"]
    listed = client.get("/api/runs").json()["items"]
    assert run_id in [r["id"] for r in listed]
    assert run_id not in {"run-1", "run-2"}
    events = client.get(f"/api/runs/{run_id}/events")
    assert events.status_code == 200
    assert f'"run_id": "{run_id}"' in events.text
    assert '"progress": 100' in events.text
    other = client.post("/api/scans", json={}).json()["id"]
    assert other != run_id
    assert client.get("/api/runs/run-zzz/events").status_code == 404


def test_vulnerability_filters_apply_to_every_view(client: TestClient) -> None:
    as_role(Role.READER)

    def groups(**params: str) -> list[str]:
        return [g["group_id"] for g in client.get("/api/vulnerabilities", params={**params}).json()["groups"]]

    assert groups(custodian="Datos") == ["grp-2"]
    assert groups(owner="Alex Ejemplo") == ["grp-1"]
    assert groups(classification="public") == ["grp-3"]
    assert groups(exposed="true") == ["grp-1", "grp-3"]
    assert groups(in_kev="true") == ["grp-1"]
    assert groups(status="new") == ["grp-2"]
    assert groups(band="medium") == ["grp-3"]
    assert groups(date_from="2026-01-14T00:00:00Z") == ["grp-1", "grp-2"]
    assert groups(date_to="2026-01-12T00:00:00Z") == ["grp-3"]
    assert groups(status="new", band="critical") == []
    assets = client.get("/api/vulnerabilities", params={"view": "asset", "exposed": "false"}).json()["assets"]
    assert [a["ci_id"] for a in assets] == ["CI-0002"]
    assert [
        a["ci_id"]
        for a in client.get("/api/vulnerabilities", params={"view": "asset", "band": "critical"}).json()["assets"]
    ] == ["CI-0001"]
    assert client.get("/api/vulnerabilities", params={"classification": "secret"}).status_code == 422


def test_criticality_view_honors_cursor_and_limit(client: TestClient) -> None:
    as_role(Role.READER)
    first = client.get("/api/vulnerabilities", params={"view": "criticality", "limit": 2}).json()
    assert first["next_cursor"]
    assert [b["level"] for b in first["bands"]] == ["critical", "high", "medium", "low"]
    assert [b["count"] for b in first["bands"]] == [1, 1, 1, 0]  # counts of the whole filtered result
    assert sum(len(b["groups"]) for b in first["bands"]) == 2
    second = client.get(
        "/api/vulnerabilities", params={"view": "criticality", "limit": 2, "cursor": first["next_cursor"]}
    ).json()
    assert [g["group_id"] for b in second["bands"] for g in b["groups"]] == ["grp-3"]
    assert second["next_cursor"] is None


def test_feedback_rules(client: TestClient) -> None:
    as_role(Role.ANALYST)
    ok = client.post("/api/feedback", json={"assessment_id": "asm-0001", "verdict": "relevant"})
    assert ok.status_code == 201
    assert ok.json()["replaced_previous"] is False
    missing_level = client.post("/api/feedback", json={"assessment_id": "asm-0001", "verdict": "wrong_priority"})
    assert missing_level.status_code == 422
    unknown = client.post("/api/feedback", json={"assessment_id": "nope", "verdict": "relevant"})
    assert unknown.status_code == 404
    forged = client.post(
        "/api/feedback", json={"assessment_id": "asm-0001", "verdict": "relevant", "user_email": "x@y.z"}
    )
    assert forged.status_code == 422  # the user comes from the token, never from the body


def test_other_write_routes(client: TestClient) -> None:
    as_role(Role.ADMIN)
    assert client.post("/api/peer-companies", json={"name": "N", "sector": "S", "country": "MX"}).status_code == 201
    assert (
        client.put("/api/peer-companies/peer-1", json={"name": "N", "sector": "S", "country": "MX"}).status_code == 200
    )
    assert client.put("/api/peer-companies/zzz", json={"name": "N", "sector": "S", "country": "MX"}).status_code == 404
    assert client.delete("/api/peer-companies/peer-1").status_code == 204
    assert client.delete("/api/peer-companies/zzz").status_code == 404
    assert client.post("/api/sources", json={"name": "Feed", "url": "http://insecure.test"}).status_code == 422
    created = client.post("/api/sources", json={"name": "Feed", "url": "https://feed.example.test/rss"})
    assert (created.status_code, created.json()["level"], created.json()["active"]) == (201, "N4", False)
    assert client.patch("/api/sources/src-nvd", json={"active": False}).status_code == 409
    assert client.patch("/api/sources/zzz", json={"active": True}).status_code == 404
    assert client.put("/api/mappings/PagoFacil", json={"cpe": "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"}).status_code == 200
    assert (
        client.put(
            "/api/profile",
            json={"expected_version": 1, "sector": "S", "subsectors": [], "countries": [], "language": "es"},
        ).status_code
        == 409
    )
    profile = {"expected_version": 2, "sector": "S", "subsectors": [], "countries": ["MX"], "language": "es"}
    assert client.put("/api/profile", json=profile).json()["version"] == 3
    assert client.post("/api/formula/simulate", json={"changes": {"weights.D": "0.7"}}).status_code == 422
    assert client.post("/api/formula/simulate", json={"changes": {"judge.sensitivity": "wide"}}).status_code == 200


def test_runs_stix_calibration_and_notifications(client: TestClient) -> None:
    as_role(Role.ADMIN)
    events = client.get("/api/runs/run-1/events")
    assert events.headers["content-type"].startswith("text/event-stream")
    assert "event: progress" in events.text
    assert client.get("/api/runs/zzz/events").status_code == 404
    assert client.post("/api/stix/export", json={"scope": "run"}).status_code == 422
    bundle = client.post("/api/stix/export", json={"scope": "run", "run_id": "run-1"})
    assert bundle.json()["type"] == "bundle"
    assert client.post("/api/calibration/proposals/cal-1/approve").json()["status"] == "approved"
    assert client.post("/api/calibration/proposals/cal-1/reject").json()["status"] == "rejected"
    assert client.post("/api/calibration/proposals/zzz/approve").status_code == 404
    assert client.post("/api/connections/test", json={"names": ["itop"]}).json()[0]["name"] == "itop"
    assert client.put("/api/setup/steps/3", json={"done": True}).json()["done"] is True
    assert client.put("/api/setup/steps/99", json={}).status_code == 404
    assert client.get("/api/tickets", params={"urgency": 1}).json()["items"][0]["itop_id"] == "R-000123"
    assert client.get("/api/recommendations/asm-0002/feedback").json() == []


def test_a_decided_proposal_conflicts() -> None:
    from api.routes import operations, samples  # noqa: PLC0415 - patched sample data

    decided = samples.PROPOSALS[0].model_copy(update={"status": "approved"})
    original = list(samples.PROPOSALS)
    try:
        samples.PROPOSALS[:] = [decided]
        as_role(Role.ADMIN)
        with TestClient(APP) as test_client:
            assert test_client.post("/api/calibration/proposals/cal-1/approve").status_code == 409
    finally:
        samples.PROPOSALS[:] = original
        APP.dependency_overrides.clear()
    assert operations.router


def test_openapi_documents_error_envelope_for_every_route() -> None:
    document = APP.openapi()
    for path, methods in document["paths"].items():
        for method, operation in methods.items():
            for status in ("401", "403", "404", "409", "422"):
                response = operation["responses"].get(status)
                assert response is not None, f"{method} {path} lacks {status}"
                ref = response["content"]["application/json"]["schema"]["$ref"]
                assert ref.endswith("/ErrorResponse"), f"{method} {path} {status}"


def test_405_lists_all_documented_methods_of_the_path(client: TestClient) -> None:
    as_role(Role.ADMIN)
    assert client.options("/api/config").headers["allow"] == "GET, PUT"
    assert client.options("/api/peer-companies").headers["allow"] == "GET, POST"
    assert client.options("/api/peer-companies/peer-1").headers["allow"] == "DELETE, PUT"
    assert client.options("/api/sources/src-nvd").headers["allow"] == "PATCH"


def test_created_items_can_be_retrieved_updated_and_deleted(client: TestClient) -> None:
    as_role(Role.ADMIN)
    body = {"name": "Nueva", "sector": "S", "country": "MX"}
    created = client.post("/api/peer-companies", json=body).json()
    ids = [p["id"] for p in client.get("/api/peer-companies").json()["items"]]
    assert created["id"] in ids
    assert client.put(f"/api/peer-companies/{created['id']}", json={**body, "name": "Otra"}).json()["name"] == "Otra"
    assert client.delete(f"/api/peer-companies/{created['id']}").status_code == 204
    assert client.delete(f"/api/peer-companies/{created['id']}").status_code == 404
    source = client.post("/api/sources", json={"name": "Feed", "url": "https://feed.example.test/rss"}).json()
    assert source["id"] in [s["id"] for s in client.get("/api/sources").json()["items"]]
    assert client.patch(f"/api/sources/{source['id']}", json={"active": True}).json()["active"] is True


def test_feedback_rule_is_in_the_request_schema_and_enforced() -> None:
    schema = APP.openapi()["components"]["schemas"]["FeedbackRequest"]
    assert schema["if"]["properties"]["verdict"] == {"const": "wrong_priority"}
    assert schema["then"]["required"] == ["proposed_level"]


def test_cursor_and_sse_are_documented() -> None:
    operation = APP.openapi()["paths"]["/api/recommendations"]["get"]
    cursor = next(p for p in operation["parameters"] if p["name"] == "cursor")
    assert cursor["schema"]["anyOf"][0]["pattern"] == r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"
    assert operation["responses"]["400"]["description"].startswith("Cursor inválido")
    sse = APP.openapi()["paths"]["/api/runs/{id}/events"]["get"]["responses"]["200"]["content"]["text/event-stream"]
    assert sse["schema"]["required"] == ["event", "data"]


def test_metrics_come_from_the_dashboard_service(client: TestClient) -> None:
    as_role(Role.READER)
    now = datetime(2026, 11, 22, 12, tzinfo=UTC)
    dashboard = Dashboard(now, [DashboardMetric("precision", "Precisión", "87.5", "%")])
    APP.dependency_overrides[get_dashboard_source] = lambda: lambda _now: dashboard
    response = client.get("/api/metrics")
    assert response.status_code == 200
    assert response.json() == {
        "generated_at": "2026-11-22T12:00:00Z",
        "metrics": [{"key": "precision", "label": "Precisión", "value": "87.5", "unit": "%"}],
    }


class FakeEvents:
    def __init__(self) -> None:
        self.row = NotificationEventRow(
            id="e1",
            type="new_ticket",
            priority="immediate",
            status="error",
            attempts=10,
            last_error="x",
            created_at="t",
        )

    def list(self, status: str) -> list[NotificationEventRow]:
        return [self.row] if status == self.row.status else []

    def retry(self, event_id: str) -> NotificationEventRow:
        return self.row.model_copy(update={"status": "pending", "attempts": 0, "last_error": None})


def test_notification_events_come_from_the_event_queue(client: TestClient) -> None:
    as_role(Role.ADMIN)
    APP.dependency_overrides[get_event_queue] = FakeEvents
    assert [e["id"] for e in client.get("/api/notifications/events").json()["items"]] == ["e1"]
    assert client.get("/api/notifications/events", params={"status": "pending"}).json()["items"] == []
    assert client.post("/api/notifications/events/e1/retry").json()["status"] == "pending"
