"""Authorization matrix (docs/14 §10.4, ASVS V8): every published operation, with no token and as reader, analyst
and admin, through the real token path (verifier + user directory + require_role), never a dependency override.

Expected: no token -> 401; a role below the route's minimum -> 403; a role at or above it -> neither 401 nor 403
(the request may still fail validation or reach a missing backend, which is not an authorization outcome).
"""

from __future__ import annotations

import re
from collections.abc import Iterator

import pytest
from authfakes import SETTINGS, FakeVerifier, bearer
from fastapi.testclient import TestClient
from pydantic import SecretStr

from api.app import create_app
from api.auth import InMemoryUserDirectory, Role
from api.routes._auth import ROUTE_ROLES

pytestmark = pytest.mark.unit

WEBHOOK_BEARER = "matrix-webhook-value"  # fake value for the test
ROLES = (Role.READER, Role.ANALYST, Role.ADMIN)
# Routes outside ROUTE_ROLES and their minimum role (None: public; "webhook": its own bearer token).
OWN_RULES: dict[tuple[str, str], Role | str | None] = {
    ("GET", "/api/health"): None,
    ("GET", "/api/me"): Role.READER,
    ("PUT", "/api/admin/users/{uid}/role"): Role.ADMIN,
    ("POST", "/api/itop/webhook"): "webhook",
}
SAMPLE_ID = "0196a6f0-0000-7000-8000-000000000001"


class _Sync:
    def sync_itop_ticket(self, itop_id: str) -> bool:
        return True


def _app() -> tuple[TestClient, FakeVerifier]:
    verifier = FakeVerifier()
    for role in ROLES:
        verifier.add(role.value, role, uid=f"matrix-{role.value}")
    settings = SETTINGS.model_copy(
        update={"itop_webhook_token": SecretStr(WEBHOOK_BEARER), "itop_url": "https://itop.example.test/"}
    )
    app = create_app(
        settings,
        token_verifier=verifier,
        user_directory=InMemoryUserDirectory(),
        role_manager=object(),  # never reached: the matrix sends no valid role change
        ticket_sync=_Sync(),
    )
    return TestClient(app, raise_server_exceptions=False), verifier


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    test_client, _verifier = _app()
    with test_client:
        yield test_client


def _operations() -> list[tuple[str, str]]:
    test_client, _verifier = _app()
    paths = test_client.app.openapi()["paths"]
    return sorted((method.upper(), path) for path, operations in paths.items() for method in operations)


OPERATIONS = _operations()


def _url(path: str) -> str:
    return re.sub(r"\{(n|v)\}", "1", re.sub(r"\{(?!n\}|v\})[^}]+\}", SAMPLE_ID, path))


def _call(client: TestClient, method: str, path: str, headers: dict[str, str]) -> int:
    body = None if method in {"GET", "DELETE"} else {}
    return client.request(method, _url(path), headers=headers, json=body).status_code


def test_the_matrix_covers_every_published_operation() -> None:
    assert set(OPERATIONS) == set(ROUTE_ROLES) | set(OWN_RULES)


@pytest.mark.parametrize(("method", "path"), [op for op in OPERATIONS if op in ROUTE_ROLES])
def test_route_roles(client: TestClient, method: str, path: str) -> None:
    minimum = ROUTE_ROLES[(method, path)]
    assert _call(client, method, path, {}) == 401
    assert _call(client, method, path, bearer("not-a-valid-token")) == 401
    assert _call(client, method, path, {"Authorization": f"Bearer {WEBHOOK_BEARER}"}) == 401
    for role in ROLES:
        status = _call(client, method, path, bearer(role.value))
        if role.at_least(minimum):
            assert status not in {401, 403}, f"{role.value} must reach {method} {path}, got {status}"
        else:
            assert status == 403, f"{role.value} must be denied {method} {path}, got {status}"


def test_health_is_public(client: TestClient) -> None:
    assert client.get("/api/health").status_code == 200


def test_me_needs_any_valid_role(client: TestClient) -> None:
    assert client.get("/api/me").status_code == 401
    for role in ROLES:
        response = client.get("/api/me", headers=bearer(role.value))
        assert response.status_code == 200
        assert response.json()["role"] == role.value


def test_role_assignment_is_admin_only(client: TestClient) -> None:
    url = "/api/admin/users/someone/role"
    assert client.put(url, json={"role": "admin"}).status_code == 401
    for role in (Role.READER, Role.ANALYST):
        assert client.put(url, json={"role": "admin"}, headers=bearer(role.value)).status_code == 403
    assert client.put(url, json={}, headers=bearer(Role.ADMIN.value)).status_code == 422  # authorized, bad body


def test_the_webhook_accepts_only_its_own_token(client: TestClient) -> None:
    call = {"class": "UserRequest", "id": "123", "ref": "R-000123"}
    assert client.post("/api/itop/webhook", json=call).status_code == 401
    for role in ROLES:  # a Firebase token, even an admin one, does not open the webhook
        assert client.post("/api/itop/webhook", json=call, headers=bearer(role.value)).status_code == 401
    assert client.post("/api/itop/webhook", json=call, headers=bearer(WEBHOOK_BEARER)).status_code == 202
