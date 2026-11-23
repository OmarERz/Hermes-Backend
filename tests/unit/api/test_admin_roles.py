"""PUT /api/admin/users/{uid}/role with fakes, and FirebaseRoleManager against a patched SDK (no network)."""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any

import pytest
from authfakes import SETTINGS, FakeVerifier, bearer
from fastapi.testclient import TestClient
from firebase_admin import auth
from firebase_admin import exceptions as firebase_exceptions

from api.app import create_app
from api.auth import AuthUnavailableError, InMemoryUserDirectory, Role
from api.auth.directory import AuditEntry, RoleConflictError, UserConflictError
from api.auth.firebase import FirebaseTokenVerifier
from api.auth.role_admin import FirebaseRoleManager, RevocationPendingError, UnknownUserError


class FakeRoleManager:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Role]] = []
        self.error: Exception | None = None

    def assign(self, uid: str, role: Role) -> None:
        if self.error:
            raise self.error
        self.calls.append((uid, role))


@pytest.fixture
def parts() -> tuple[FakeVerifier, InMemoryUserDirectory, FakeRoleManager]:
    verifier = FakeVerifier()
    verifier.add("admin", Role.ADMIN, uid="admin-1")
    verifier.add("analyst", Role.ANALYST, uid="analyst-1")
    return verifier, InMemoryUserDirectory(), FakeRoleManager()


@pytest.fixture
def client(parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeRoleManager]) -> TestClient:
    verifier, directory, manager = parts
    return TestClient(create_app(SETTINGS, token_verifier=verifier, user_directory=directory, role_manager=manager))


def test_admin_assigns_a_role_and_it_is_audited(
    client: TestClient, parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeRoleManager]
) -> None:
    _, directory, manager = parts
    client.get("/api/me", headers=bearer("analyst"))  # the target has logged in once

    response = client.put("/api/admin/users/analyst-1/role", json={"role": "reader"}, headers=bearer("admin"))

    assert response.status_code == 200, response.text
    assert response.json() == {"uid": "analyst-1", "role": "reader", "sessions_revoked": True, "known_user": True}
    assert manager.calls == [("analyst-1", Role.READER)]
    record = directory.get("analyst-1")
    assert record is not None
    assert record.role is Role.READER
    assert directory.audit[-2:] == [
        AuditEntry("admin-1", "role_assignment_requested", "analyst-1", None, {"role": "reader"}),
        AuditEntry(
            "admin-1", "role_assigned", "analyst-1", {"role": "analyst"}, {"role": "reader", "sessions_revoked": True}
        ),
    ]


def test_role_for_a_user_who_never_logged_in(client: TestClient) -> None:
    response = client.put("/api/admin/users/new-user/role", json={"role": "analyst"}, headers=bearer("admin"))
    assert response.status_code == 200
    assert response.json()["known_user"] is False


def test_non_admin_is_forbidden_and_logged(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="api.auth.dependencies"):
        response = client.put("/api/admin/users/x/role", json={"role": "admin"}, headers=bearer("analyst"))
    assert response.status_code == 403
    assert "authorization denied: user analyst-1 with role analyst needs admin" in caplog.text


def test_inactive_user_is_forbidden_and_logged(
    client: TestClient,
    parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeRoleManager],
    caplog: pytest.LogCaptureFixture,
) -> None:
    _, directory, _ = parts
    client.get("/api/me", headers=bearer("admin"))
    directory.deactivate("admin-1")
    with caplog.at_level(logging.WARNING, logger="api.auth.dependencies"):
        response = client.put("/api/admin/users/x/role", json={"role": "reader"}, headers=bearer("admin"))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "user_inactive"
    assert "inactive user admin-1" in caplog.text


def test_without_token_is_unauthorized(client: TestClient) -> None:
    assert client.put("/api/admin/users/x/role", json={"role": "admin"}).status_code == 401


def test_admin_cannot_change_their_own_role(
    client: TestClient, parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeRoleManager]
) -> None:
    response = client.put("/api/admin/users/admin-1/role", json={"role": "reader"}, headers=bearer("admin"))
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "own_role"
    assert parts[2].calls == []


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [(UnknownUserError("x"), 404, "user_not_found"), (AuthUnavailableError(), 503, "auth_unavailable")],
)
def test_role_manager_failures(
    client: TestClient,
    parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeRoleManager],
    error: Exception,
    status: int,
    code: str,
) -> None:
    _, directory, manager = parts
    manager.error = error
    response = client.put("/api/admin/users/x/role", json={"role": "reader"}, headers=bearer("admin"))
    assert response.status_code == status
    assert response.json()["error"]["code"] == code
    assert [e.action for e in directory.audit] == [
        "user_created",
        "role_assignment_requested",
        "role_assignment_failed",
    ]


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/admin/users/x/role", {"role": "superuser"}),
        ("/api/admin/users/x/role", {"role": "reader", "extra": 1}),
        ("/api/admin/users/x/role", {}),
        (f"/api/admin/users/{'a' * 129}/role", {"role": "reader"}),
        ("/api/admin/users/%01bad/role", {"role": "reader"}),
    ],
)
def test_invalid_input_is_rejected(client: TestClient, path: str, body: dict[str, Any]) -> None:
    response = client.put(path, json=body, headers=bearer("admin"))
    assert response.status_code == 422


# --- FirebaseRoleManager with the SDK functions patched -------------------------------------------------


@pytest.fixture
def manager(monkeypatch: pytest.MonkeyPatch) -> tuple[FirebaseRoleManager, list[tuple[str, Any]]]:
    calls: list[tuple[str, Any]] = []
    verifier = FirebaseTokenVerifier("demo-hermes")
    monkeypatch.setattr(verifier, "sdk_app", lambda: "app")
    monkeypatch.setattr(
        auth, "get_user", lambda uid, app: SimpleNamespace(custom_claims={"team": "blue", "role": "reader"})
    )
    monkeypatch.setattr(auth, "set_custom_user_claims", lambda uid, claims, app: calls.append(("claims", claims)))
    monkeypatch.setattr(auth, "revoke_refresh_tokens", lambda uid, app: calls.append(("revoke", uid)))
    return FirebaseRoleManager(verifier, sleep=lambda _s: None), calls


def test_manager_keeps_other_claims_and_revokes(manager: tuple[FirebaseRoleManager, list[tuple[str, Any]]]) -> None:
    role_manager, calls = manager
    role_manager.assign("u1", Role.ANALYST)
    assert calls == [("claims", {"team": "blue", "role": "analyst"}), ("revoke", "u1")]


def test_manager_maps_unknown_and_malformed_users(
    manager: tuple[FirebaseRoleManager, list[tuple[str, Any]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    role_manager, _ = manager

    def missing(uid: str, app: Any) -> Any:
        raise auth.UserNotFoundError("no user")

    monkeypatch.setattr(auth, "get_user", missing)
    with pytest.raises(UnknownUserError):
        role_manager.assign("u1", Role.READER)

    def malformed(uid: str, app: Any) -> Any:
        raise ValueError("bad uid")

    monkeypatch.setattr(auth, "get_user", malformed)
    with pytest.raises(UnknownUserError):
        role_manager.assign("u1", Role.READER)


def test_manager_maps_provider_failures(
    manager: tuple[FirebaseRoleManager, list[tuple[str, Any]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    role_manager, _ = manager

    def down(uid: str, claims: Any, app: Any) -> None:
        raise firebase_exceptions.UnavailableError("down")

    monkeypatch.setattr(auth, "set_custom_user_claims", down)
    with pytest.raises(AuthUnavailableError):
        role_manager.assign("u1", Role.READER)


def test_manager_maps_credential_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    verifier = FirebaseTokenVerifier("demo-hermes")

    def no_credentials() -> Any:
        raise OSError("unreadable")

    monkeypatch.setattr(verifier, "sdk_app", no_credentials)
    with pytest.raises(AuthUnavailableError):
        FirebaseRoleManager(verifier).assign("u1", Role.READER)


def test_manager_revokes_after_the_next_full_second(monkeypatch: pytest.MonkeyPatch) -> None:
    """Firebase revocation is second-granular: revoking in the same second would keep old-role tokens valid."""
    events: list[tuple[str, Any]] = []
    verifier = FirebaseTokenVerifier("demo-hermes")
    monkeypatch.setattr(verifier, "sdk_app", lambda: "app")
    monkeypatch.setattr(auth, "get_user", lambda uid, app: SimpleNamespace(custom_claims=None))
    monkeypatch.setattr(auth, "set_custom_user_claims", lambda uid, claims, app: events.append(("claims", claims)))
    monkeypatch.setattr(auth, "revoke_refresh_tokens", lambda uid, app: events.append(("revoke", uid)))
    manager = FirebaseRoleManager(verifier, clock=lambda: 1000.25, sleep=lambda s: events.append(("sleep", s)))
    manager.assign("u1", Role.READER)
    assert events == [("claims", {"role": "reader"}), ("sleep", 0.75), ("revoke", "u1")]


def test_account_conflict_is_a_controlled_409(
    parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeRoleManager],
) -> None:
    verifier, _, manager = parts

    class ConflictDirectory(InMemoryUserDirectory):
        def sync_login(self, identity: Any) -> Any:
            raise UserConflictError(identity.uid)

    client = TestClient(
        create_app(SETTINGS, token_verifier=verifier, user_directory=ConflictDirectory(), role_manager=manager)
    )
    response = client.get("/api/me", headers=bearer("admin"))
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "account_conflict"


def test_openapi_documents_the_error_envelope_for_422(
    parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeRoleManager],
) -> None:
    verifier, directory, manager = parts
    app = create_app(
        SETTINGS.model_copy(update={"api_docs_enabled": True}),
        token_verifier=verifier,
        user_directory=directory,
        role_manager=manager,
    )
    schema = TestClient(app).get("/api/openapi.json").json()
    response_422 = schema["paths"]["/api/admin/users/{uid}/role"]["put"]["responses"]["422"]
    assert response_422["content"]["application/json"]["schema"]["$ref"].endswith("/ErrorResponse")


def test_firebase_uids_with_symbols_are_accepted(client: TestClient) -> None:
    response = client.put("/api/admin/users/external+123@idp/role", json={"role": "reader"}, headers=bearer("admin"))
    assert response.status_code == 200
    assert response.json()["uid"] == "external+123@idp"


def test_pending_revocation_is_reported_and_audited(
    client: TestClient, parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeRoleManager]
) -> None:
    _, directory, manager = parts
    manager.error = RevocationPendingError("x")
    response = client.put("/api/admin/users/x/role", json={"role": "reader"}, headers=bearer("admin"))
    assert response.status_code == 200
    assert response.json()["sessions_revoked"] is False
    assert directory.audit[-1].after == {"role": "reader", "sessions_revoked": False}


def test_downgrade_applies_to_tokens_still_alive(
    client: TestClient, parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeRoleManager]
) -> None:
    """The effective role is the lower of the token claim and the database copy."""
    client.get("/api/me", headers=bearer("analyst"))
    assert (
        client.put("/api/admin/users/analyst-1/role", json={"role": "reader"}, headers=bearer("admin")).status_code
        == 200
    )
    # The fake verifier still returns the old analyst claim, as an unexpired token would.
    assert client.get("/api/me", headers=bearer("analyst")).json()["role"] == "reader"


def test_login_never_writes_the_role_back(parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeRoleManager]) -> None:
    verifier, directory, _ = parts
    identity = verifier.add("tok", Role.ANALYST, uid="u9")
    directory.sync_login(identity)
    directory.sync_login(verifier.add("admin-tok", Role.ADMIN, uid="admin-1"))  # the actor is a known admin
    directory.change_role("u9", Role.READER, "admin-1", lambda: True)
    record = directory.sync_login(identity)  # a request verified before the change, finishing after it
    assert record.role is Role.READER


def test_manager_retries_revocation_then_reports_it_pending(
    manager: tuple[FirebaseRoleManager, list[tuple[str, Any]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    role_manager, calls = manager
    attempts: list[int] = []

    def flaky(uid: str, app: Any) -> None:
        attempts.append(1)
        raise firebase_exceptions.UnavailableError("down")

    monkeypatch.setattr(auth, "revoke_refresh_tokens", flaky)
    with pytest.raises(RevocationPendingError):
        role_manager.assign("u1", Role.ANALYST)
    assert len(attempts) == 3
    assert calls == [("claims", {"team": "blue", "role": "analyst"})]


def test_manager_recovers_when_a_retry_succeeds(
    manager: tuple[FirebaseRoleManager, list[tuple[str, Any]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    role_manager, _ = manager
    attempts: list[int] = []

    def once_down(uid: str, app: Any) -> None:
        attempts.append(1)
        if len(attempts) == 1:
            raise firebase_exceptions.UnavailableError("blip")

    monkeypatch.setattr(auth, "revoke_refresh_tokens", once_down)
    role_manager.assign("u1", Role.ANALYST)
    assert len(attempts) == 2


def test_a_stale_expected_role_is_a_conflict(
    client: TestClient, parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeRoleManager]
) -> None:
    """API-03 for roles: the admin read `reader`, the stored copy is `analyst` (pending F0 #20)."""
    _, _, manager = parts
    client.get("/api/me", headers=bearer("analyst"))
    body = {"role": "admin", "expected_role": "reader"}
    response = client.put("/api/admin/users/analyst-1/role", json=body, headers=bearer("admin"))
    assert (response.status_code, response.json()["error"]["code"]) == (409, "role_changed")
    assert manager.calls == []
    ok = client.put(
        "/api/admin/users/analyst-1/role", json={"role": "reader", "expected_role": "analyst"}, headers=bearer("admin")
    )
    assert ok.status_code == 200


def test_the_last_active_admin_is_never_demoted(
    client: TestClient, parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeRoleManager]
) -> None:
    """The directory refuses to demote the only active admin (pending F0 #19); the route already refuses an admin's
    own change, so this guards any other caller of the directory."""
    _, directory, manager = parts
    client.get("/api/me", headers=bearer("admin"))
    with pytest.raises(RoleConflictError, match="last_admin"):
        directory.change_role("admin-1", Role.READER, "admin-1", lambda: True)
    assert manager.calls == []


def test_an_actor_who_lost_the_role_meanwhile_is_refused(
    client: TestClient, parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeRoleManager]
) -> None:
    """The actor is re-checked under the lock: a request that waited while its admin was demoted changes nothing."""
    _, directory, manager = parts
    client.get("/api/me", headers=bearer("admin"))
    client.get("/api/me", headers=bearer("analyst"))
    directory.deactivate("admin-1")
    with pytest.raises(RoleConflictError, match="actor_not_admin"):
        directory.change_role("analyst-1", Role.READER, "admin-1", lambda: True)
    assert manager.calls == []


def test_a_last_admin_refusal_is_a_conflict(
    client: TestClient,
    parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeRoleManager],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, directory, _ = parts

    def refuse(*_args: object) -> None:
        raise RoleConflictError("last_admin")

    monkeypatch.setattr(directory, "change_role", refuse)
    response = client.put("/api/admin/users/analyst-1/role", json={"role": "reader"}, headers=bearer("admin"))
    assert (response.status_code, response.json()["error"]["code"]) == (409, "last_admin")


def test_an_actor_refused_under_the_lock_gets_403(
    client: TestClient,
    parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeRoleManager],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, directory, _ = parts

    def refuse(*_args: object) -> None:
        raise RoleConflictError("actor_not_admin")

    monkeypatch.setattr(directory, "change_role", refuse)
    response = client.put("/api/admin/users/analyst-1/role", json={"role": "reader"}, headers=bearer("admin"))
    assert (response.status_code, response.json()["error"]["code"]) == (403, "forbidden")
