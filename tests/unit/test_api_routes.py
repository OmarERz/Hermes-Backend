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
    assert client.get("/api/connections/status").status_code == 403


GET_SAMPLES = [
    "/api/runs",
]


@pytest.mark.parametrize("url", GET_SAMPLES)
def test_get_routes_return_sample_data(client: TestClient, url: str) -> None:
    as_role(Role.ADMIN)
    response = client.get(url)
    assert response.status_code == 200, response.text
    assert response.json()


def test_pagination_cursor_flow_and_invalid_cursor(client: TestClient) -> None:
    as_role(Role.READER)
    first = client.get("/api/runs", params={"limit": 1}).json()
    assert len(first["items"]) == 1
    assert first["next_cursor"]
    second = client.get("/api/runs", params={"limit": 1, "cursor": first["next_cursor"]}).json()
    assert second["items"][0]["id"] == "run-2"
    assert second["next_cursor"] is None
    bad = client.get("/api/runs", params={"cursor": "tampered.cursor"})
    assert bad.status_code == 400
    assert bad.json()["error"]["code"] == "invalid_cursor"
    assert client.get("/api/runs", params={"limit": 500}).status_code == 422


def test_not_found_uses_the_envelope(client: TestClient) -> None:
    as_role(Role.READER)
    for url in ("/api/recommendations/nope", "/api/recommendations/nope/feedback", "/api/findings/x/history"):
        response = client.get(url)
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"


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


def test_vulnerability_filters_are_validated_before_the_database(client: TestClient) -> None:
    as_role(Role.READER)
    assert client.get("/api/vulnerabilities", params={"classification": "secret"}).status_code == 422
    assert client.get("/api/vulnerabilities", params={"view": "ticket"}).status_code == 422


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


def test_runs_stix_calibration_and_notifications(client: TestClient) -> None:
    as_role(Role.ADMIN)
    events = client.get("/api/runs/run-1/events")
    assert events.headers["content-type"].startswith("text/event-stream")
    assert "event: progress" in events.text
    assert client.get("/api/runs/zzz/events").status_code == 404
    assert (
        client.post("/api/stix/export", json={"scope": "run"}).status_code == 422
    )  # scope data checked before the database


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
