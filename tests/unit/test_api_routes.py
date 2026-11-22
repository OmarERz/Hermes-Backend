"""Sample routes of docs/13 API-06: role table, authorization placeholder, samples, errors and OpenAPI."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from api.app import create_app
from api.auth import CurrentUser, Role, get_current_user
from api.routes._auth import ROUTE_ROLES
from core.config import Settings

pytestmark = pytest.mark.unit

F0_2_ROUTES = {"/api/health", "/api/me", "/api/admin/users/{uid}/role"}  # outside ROUTE_ROLES (F0.2)
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
    "/api/metrics",
    "/api/notifications/events",
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
    as_role(Role.READER)
    stale = client.put("/api/config", json={"expected_version": 1, "changes": {"weights.D": "0.10"}})
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "version_conflict"
    bad_sum = client.put("/api/config", json={"expected_version": 3, "changes": {"weights.D": "0.50"}})
    assert bad_sum.status_code == 422
    assert bad_sum.json()["error"]["details"][0]["issue"] == "weights_sum_to_one"
    unknown = client.put("/api/config", json={"expected_version": 3, "changes": {"nope": "1"}})
    assert unknown.status_code == 422
    bad_decimal = client.put("/api/config", json={"expected_version": 3, "changes": {"weights.D": "x"}})
    assert bad_decimal.json()["error"]["details"][0]["issue"] == "invalid_decimal"
    ok = client.put("/api/config", json={"expected_version": 3, "changes": {"weights.D": "1"}})
    assert ok.status_code == 200
    assert ok.json()["version"] == 4


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
    assert client.patch("/api/sources/src-thn", json={"active": False}).json()["active"] is False
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
    assert client.post("/api/config/versions/2/restore").status_code == 200
    assert client.post("/api/config/versions/99/restore").status_code == 404
    assert client.post("/api/formula/simulate", json={"changes": {"weights.D": "0.7"}}).status_code == 422
    assert client.post("/api/formula/simulate", json={"changes": {"judge.sensitivity": "wide"}}).status_code == 200


def test_runs_stix_calibration_and_notifications(client: TestClient) -> None:
    as_role(Role.ADMIN)
    assert client.post("/api/scans", json={}).status_code == 202
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
    assert client.post("/api/notifications/events/evt-1/retry").json()["status"] == "pending"
    assert client.post("/api/notifications/events/zzz/retry").status_code == 404
    assert client.post("/api/connections/test", json={"names": ["itop"]}).json()[0]["name"] == "itop"
    assert client.put("/api/setup/steps/3", json={"done": True}).json()["done"] is True
    assert client.put("/api/setup/steps/99", json={}).status_code == 404
    assert client.get("/api/tickets", params={"urgency": 1}).json()["items"][0]["itop_id"] == "R-000123"
    assert client.get("/api/recommendations/asm-0002/feedback").json() == []


def test_decided_proposal_and_non_error_event_conflict() -> None:
    from api.routes import operations, samples  # noqa: PLC0415 - patched sample data

    decided = samples.PROPOSALS[0].model_copy(update={"status": "approved"})
    delivered = samples.NOTIFICATION_EVENTS[0].model_copy(update={"status": "delivered"})
    original = (list(samples.PROPOSALS), list(samples.NOTIFICATION_EVENTS))
    try:
        samples.PROPOSALS[:] = [decided]
        samples.NOTIFICATION_EVENTS[:] = [delivered]
        as_role(Role.ADMIN)
        with TestClient(APP) as test_client:
            assert test_client.post("/api/calibration/proposals/cal-1/approve").status_code == 409
            assert test_client.post("/api/notifications/events/evt-1/retry").status_code == 409
    finally:
        samples.PROPOSALS[:] = original[0]
        samples.NOTIFICATION_EVENTS[:] = original[1]
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
