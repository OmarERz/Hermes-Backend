"""POST /api/admin/users, POST /api/admin/users/{uid}/password-email and PUT /api/admin/users/{uid}/status with a fake
account manager and the in-memory directory (D-105, F18.8; no network)."""

from __future__ import annotations

import logging
import re
from typing import Any

import pytest
from authfakes import SETTINGS, FakeVerifier, bearer
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from api.app import create_app
from api.auth import AuthUnavailableError, InMemoryUserDirectory, Role, admin_routes
from api.auth.accounts import (
    AccountInfo,
    EmailInUseError,
    EmailQuota,
    InvalidEmailError,
    PasswordEmailError,
    UidInUseError,
)
from api.auth.directory import AuditEntry, NewAccount, RoleConflictError
from api.auth.role_admin import UnknownUserError

pytestmark = pytest.mark.unit

EMAIL = "nueva.persona@example.com"


class FakeAccounts:
    """An AccountManager that records its calls; each step can be told to fail."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.errors: dict[str, Exception] = {}
        self.accounts: dict[str, AccountInfo] = {"u-reader": AccountInfo("u-reader", "reader@example.com", False)}
        self.uids: list[str] = []  # the uids Hermes picked, in order
        self.on_in_hermes: list[bool] = []  # what each status change was told about the copy

    def _fail(self, step: str) -> None:
        if step in self.errors:
            raise self.errors[step]

    def create(self, uid: str, email: str, role: Role) -> NewAccount:
        self.uids.append(uid)
        self._fail("create")
        self.calls.append(("create", (email, role)))
        self.accounts[uid] = AccountInfo(uid, email.lower(), False)
        return NewAccount(uid, email.lower())

    def discard(self, uid: str) -> None:
        self.calls.append(("discard", uid))

    def lookup(self, uid: str) -> AccountInfo:
        self._fail("lookup")
        if uid not in self.accounts:
            raise UnknownUserError(uid)
        return self.accounts[uid]

    def set_disabled(self, uid: str, disabled: bool, on_in_hermes: bool = False) -> bool:
        self._fail("set_disabled")
        if uid not in self.accounts:
            raise UnknownUserError(uid)
        self.calls.append(("set_disabled", (uid, disabled)))
        self.on_in_hermes.append(on_in_hermes)
        return disabled or not on_in_hermes  # a switch-on already applied revokes nothing

    def send_password_setup(self, email: str, user_ip: str | None = None) -> None:
        self._fail("send")
        self.calls.append(("send", (email, user_ip)))


@pytest.fixture
def parts() -> tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts]:
    verifier = FakeVerifier()
    verifier.add("admin", Role.ADMIN, uid="u-admin")
    verifier.add("analyst", Role.ANALYST, uid="u-analyst")
    verifier.add("reader", Role.READER, uid="u-reader")
    return verifier, InMemoryUserDirectory(), FakeAccounts()


def _client(parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts], directory: Any = None) -> TestClient:
    verifier, memory, accounts = parts
    app = create_app(SETTINGS, token_verifier=verifier, user_directory=directory or memory, role_manager=object())  # type: ignore[arg-type]
    app.state.account_manager = accounts
    return TestClient(app)


@pytest.fixture
def client(parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts]) -> TestClient:
    return _client(parts)


def _account_audit(directory: InMemoryUserDirectory) -> list[AuditEntry]:
    return [entry for entry in directory.audit if entry.action.startswith("user.")]


# --- POST /api/admin/users ---------------------------------------------------------------------------------------


def test_an_admin_creates_an_account_and_firebase_emails_the_password_link(
    client: TestClient,
    parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts],
    caplog: pytest.LogCaptureFixture,
) -> None:
    _, directory, accounts = parts
    with caplog.at_level(logging.INFO):
        response = client.post(
            "/api/admin/users", json={"email": "Nueva.Persona@example.com", "role": "analyst"}, headers=bearer("admin")
        )

    assert response.status_code == 201, response.text
    [uid] = accounts.uids
    assert re.fullmatch(r"[0-9a-f]{28}", uid)  # Hermes picks the uid before asking Firebase
    assert response.json() == {"uid": uid, "email": EMAIL, "role": "analyst", "password_email_sent": True}
    assert accounts.calls == [("create", ("Nueva.Persona@example.com", Role.ANALYST)), ("send", (EMAIL, "testclient"))]
    record = directory.get(uid)
    assert record is not None and (record.role, record.active, record.last_login_at) == (Role.ANALYST, True, None)
    assert _account_audit(directory) == [
        AuditEntry("u-admin", "user.create_requested", uid, None, {"role": "analyst"}),
        AuditEntry("u-admin", "user.create", uid, None, {"role": "analyst", "active": True}),
        AuditEntry("u-admin", "user.password_email_requested", uid, None, None),
        AuditEntry("u-admin", "user.password_email_sent", uid, None, None),
    ]
    assert f"account created: user {uid} with role analyst by u-admin" in caplog.text
    assert EMAIL not in caplog.text.lower()


@pytest.mark.parametrize(
    ("error", "reason"),
    [(PasswordEmailError("EMAIL_NOT_FOUND"), "EMAIL_NOT_FOUND"), (AuthUnavailableError(), "auth_unavailable")],
)
def test_an_email_that_was_not_sent_keeps_the_account_and_says_so(
    client: TestClient,
    parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts],
    error: Exception,
    reason: str,
) -> None:
    _, directory, accounts = parts
    accounts.errors["send"] = error
    response = client.post("/api/admin/users", json={"email": EMAIL, "role": "reader"}, headers=bearer("admin"))
    assert response.status_code == 201
    assert response.json()["password_email_sent"] is False
    uid = response.json()["uid"]
    assert directory.get(uid) is not None
    assert _account_audit(directory)[-1] == AuditEntry(
        "u-admin", "user.password_email_failed", uid, None, {"reason": reason}
    )


def test_an_email_with_an_account_is_a_409(
    client: TestClient, parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts]
) -> None:
    _, directory, accounts = parts
    accounts.errors["create"] = EmailInUseError()
    response = client.post("/api/admin/users", json={"email": EMAIL, "role": "reader"}, headers=bearer("admin"))
    assert response.status_code == 409
    assert response.json()["error"] == {
        "code": "email_exists",
        "message": "Ya existe una cuenta con ese correo.",
        "details": [],
    }
    # A copy in Hermes that owns the e-mail is refused the same way, before Firebase.
    client.get("/api/me", headers=bearer("reader"))  # u-reader@example.com
    del accounts.errors["create"]
    again = client.post(
        "/api/admin/users", json={"email": "U-Reader@example.com", "role": "reader"}, headers=bearer("admin")
    )
    assert again.status_code == 409
    assert accounts.calls == []
    assert [entry.action for entry in _account_audit(directory)] == ["user.create_requested", "user.create_failed"] * 2


def test_an_email_firebase_refuses_is_a_422(
    client: TestClient, parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts]
) -> None:
    parts[2].errors["create"] = InvalidEmailError()
    response = client.post("/api/admin/users", json={"email": EMAIL, "role": "reader"}, headers=bearer("admin"))
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_email"
    assert response.json()["error"]["details"] == [{"field": "body.email", "issue": "invalid_email"}]


@pytest.mark.parametrize("error", [AuthUnavailableError(), UidInUseError()])
def test_firebase_down_is_a_503_and_a_half_made_account_is_discarded(
    client: TestClient, parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts], error: Exception
) -> None:
    accounts = parts[2]
    accounts.errors["create"] = error
    response = client.post("/api/admin/users", json={"email": EMAIL, "role": "reader"}, headers=bearer("admin"))
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "auth_unavailable"
    # Only an account Firebase may hold is deleted, by the uid Hermes picked; another account's uid never is.
    expected = [] if isinstance(error, UidInUseError) else [("discard", accounts.uids[0])]
    assert accounts.calls == expected


@pytest.mark.parametrize(
    "body",
    [
        {"email": "sin-arroba.example.com", "role": "reader"},
        {"email": "dos@@example.com", "role": "reader"},
        {"email": "espacio @example.com", "role": "reader"},
        {"email": "nadie@localhost", "role": "reader"},
        {"email": f"{'a' * 65}@example.com", "role": "reader"},
        {"email": f"a@{'b' * 250}.com", "role": "reader"},
        {"email": EMAIL, "role": "superuser"},
        {"email": EMAIL},
        {"email": EMAIL, "role": "reader", "password": "nunca"},
    ],
)
def test_invalid_bodies_are_refused(client: TestClient, body: dict[str, Any]) -> None:
    response = client.post("/api/admin/users", json=body, headers=bearer("admin"))
    assert response.status_code == 422
    assert "nunca" not in response.text


def test_only_an_admin_creates_accounts(
    client: TestClient, parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts]
) -> None:
    body = {"email": EMAIL, "role": "admin"}
    assert client.post("/api/admin/users", json=body).status_code == 401
    for role in ("analyst", "reader"):
        response = client.post("/api/admin/users", json=body, headers=bearer(role))
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "forbidden"
    assert parts[2].calls == []


def test_an_admin_demoted_while_the_request_waited_is_refused(
    parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts],
) -> None:
    class DemotedMeanwhile(InMemoryUserDirectory):
        def create_account(self, *args: Any, **kwargs: Any) -> Any:
            raise RoleConflictError("actor_not_admin")

        def change_status(self, *args: Any, **kwargs: Any) -> Any:
            raise RoleConflictError("actor_not_admin")

    client = _client(parts, DemotedMeanwhile())
    created = client.post("/api/admin/users", json={"email": EMAIL, "role": "reader"}, headers=bearer("admin"))
    status = client.put("/api/admin/users/u-reader/status", json={"disabled": True}, headers=bearer("admin"))
    assert (created.status_code, status.status_code) == (403, 403)


def test_an_admin_demoted_before_the_email_gets_none_sent(
    parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts],
) -> None:
    """The e-mail is allowed again under the directory's lock: an admin demoted meanwhile sends nothing (the account
    just created stays, without its e-mail; another admin can send it)."""

    class DemotedBeforeTheEmail(InMemoryUserDirectory):
        def authorize_password_email(self, uid: str, actor_uid: str) -> None:
            raise RoleConflictError("actor_not_admin")

    client = _client(parts, DemotedBeforeTheEmail())
    created = client.post("/api/admin/users", json={"email": EMAIL, "role": "reader"}, headers=bearer("admin"))
    resend = client.post("/api/admin/users/u-reader/password-email", headers=bearer("admin"))
    assert (created.status_code, created.json()["password_email_sent"]) == (201, False)
    assert resend.status_code == 403
    assert [call for call in parts[2].calls if call[0] == "send"] == []


def test_an_account_switched_off_in_hermes_gets_no_email(
    client: TestClient, parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts]
) -> None:
    _, directory, accounts = parts
    client.get("/api/me", headers=bearer("reader"))
    directory.deactivate("u-reader")  # off in Hermes, still on in Firebase (a switch-off whose Firebase call failed)
    response = client.post("/api/admin/users/u-reader/password-email", headers=bearer("admin"))
    assert (response.status_code, response.json()["error"]["code"]) == (409, "user_disabled")
    assert [call for call in accounts.calls if call[0] == "send"] == []


def test_an_email_that_went_out_is_not_an_error_when_only_its_outcome_cannot_be_audited(
    parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts], monkeypatch: pytest.MonkeyPatch
) -> None:
    class AuditDown(InMemoryUserDirectory):
        def audit_password_email(self, uid: str, actor_uid: str, failure: str | None) -> None:
            raise OperationalError("INSERT", {}, ConnectionError("database down"))

    client = _client(parts, AuditDown())
    warnings: list[str] = []
    monkeypatch.setattr(admin_routes.logger, "warning", lambda message, *args: warnings.append(message % args))
    created = client.post("/api/admin/users", json={"email": EMAIL, "role": "reader"}, headers=bearer("admin"))
    assert (created.status_code, created.json()["password_email_sent"]) == (201, True)
    [warning] = warnings
    assert warning.startswith("setup e-mail outcome not audited: user ")
    assert EMAIL not in warning


def test_a_new_account_whose_email_cannot_be_requested_is_still_created(
    parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts], monkeypatch: pytest.MonkeyPatch
) -> None:
    class AuditDown(InMemoryUserDirectory):
        def authorize_password_email(self, uid: str, actor_uid: str) -> None:
            raise OperationalError("INSERT", {}, ConnectionError("database down"))

    client = _client(parts, AuditDown())
    warnings: list[str] = []
    monkeypatch.setattr(admin_routes.logger, "warning", lambda message, *args: warnings.append(message % args))
    created = client.post("/api/admin/users", json={"email": EMAIL, "role": "reader"}, headers=bearer("admin"))
    assert (created.status_code, created.json()["password_email_sent"]) == (201, False)
    assert [call for call in parts[2].calls if call[0] == "send"] == []
    [warning] = warnings
    assert warning.startswith("setup e-mail not requested: user ")


def test_password_emails_are_capped_per_admin(
    client: TestClient,
    parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts],
    caplog: pytest.LogCaptureFixture,
) -> None:
    client.app.state.email_quota = EmailQuota(limit=1)  # type: ignore[attr-defined]
    first = client.post("/api/admin/users", json={"email": EMAIL, "role": "reader"}, headers=bearer("admin"))
    assert first.status_code == 201
    with caplog.at_level(logging.WARNING):
        second = client.post(
            "/api/admin/users", json={"email": "otra@example.com", "role": "reader"}, headers=bearer("admin")
        )
        resend = client.post(f"/api/admin/users/{first.json()['uid']}/password-email", headers=bearer("admin"))
    assert (second.status_code, resend.status_code) == (429, 429)
    assert second.json()["error"]["code"] == "too_many_emails"
    assert "user u-admin reached the hourly limit" in caplog.text
    assert [call[0] for call in parts[2].calls] == ["create", "send"]


def test_without_an_account_manager_the_routes_answer_503(
    parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts],
) -> None:
    verifier, directory, _ = parts
    client = TestClient(create_app(SETTINGS, token_verifier=verifier, user_directory=directory, role_manager=object()))  # type: ignore[arg-type]
    responses = [
        client.post("/api/admin/users", json={"email": EMAIL, "role": "reader"}, headers=bearer("admin")),
        client.post("/api/admin/users/u-reader/password-email", headers=bearer("admin")),
        client.put("/api/admin/users/u-reader/status", json={"disabled": True}, headers=bearer("admin")),
    ]
    assert [r.status_code for r in responses] == [503, 503, 503]


# --- POST /api/admin/users/{uid}/password-email -------------------------------------------------------------------


def test_the_password_email_is_sent_again(
    client: TestClient, parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts]
) -> None:
    _, directory, accounts = parts
    response = client.post("/api/admin/users/u-reader/password-email", headers=bearer("admin"))
    assert response.status_code == 200, response.text
    assert response.json() == {"uid": "u-reader", "email": "reader@example.com"}
    assert accounts.calls == [("send", ("reader@example.com", "testclient"))]
    assert _account_audit(directory) == [
        AuditEntry("u-admin", "user.password_email_requested", "u-reader", None, None),
        AuditEntry("u-admin", "user.password_email_sent", "u-reader", None, None),
    ]


@pytest.mark.parametrize(
    ("setup", "status", "code"),
    [
        (lambda a: a.accounts.pop("u-reader"), 404, "user_not_found"),
        (lambda a: a.errors.__setitem__("lookup", AuthUnavailableError()), 503, "auth_unavailable"),
        (
            lambda a: a.accounts.__setitem__("u-reader", AccountInfo("u-reader", "r@example.com", True)),
            409,
            "user_disabled",
        ),
        (lambda a: a.accounts.__setitem__("u-reader", AccountInfo("u-reader", None, False)), 409, "no_email"),
    ],
)
def test_a_password_email_that_cannot_go_out_is_refused(
    client: TestClient,
    parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts],
    setup: Any,
    status: int,
    code: str,
) -> None:
    setup(parts[2])
    response = client.post("/api/admin/users/u-reader/password-email", headers=bearer("admin"))
    assert (response.status_code, response.json()["error"]["code"]) == (status, code)
    assert [call for call in parts[2].calls if call[0] == "send"] == []


def test_a_resend_firebase_did_not_send_is_a_503_and_audited(
    client: TestClient, parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts]
) -> None:
    _, directory, accounts = parts
    accounts.errors["send"] = PasswordEmailError("TOO_MANY_ATTEMPTS_TRY_LATER")
    response = client.post("/api/admin/users/u-reader/password-email", headers=bearer("admin"))
    assert (response.status_code, response.json()["error"]["code"]) == (503, "email_unavailable")
    assert _account_audit(directory) == [
        AuditEntry("u-admin", "user.password_email_requested", "u-reader", None, None),
        AuditEntry(
            "u-admin", "user.password_email_failed", "u-reader", None, {"reason": "TOO_MANY_ATTEMPTS_TRY_LATER"}
        ),
    ]


def test_only_an_admin_sends_password_emails(client: TestClient) -> None:
    assert client.post("/api/admin/users/u-reader/password-email").status_code == 401
    for role in ("analyst", "reader"):
        assert client.post("/api/admin/users/u-reader/password-email", headers=bearer(role)).status_code == 403


# --- PUT /api/admin/users/{uid}/status ----------------------------------------------------------------------------


def test_an_admin_disables_and_enables_an_account(
    client: TestClient, parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts]
) -> None:
    _, directory, accounts = parts
    client.get("/api/me", headers=bearer("reader"))  # the reader has a copy in Hermes

    off = client.put("/api/admin/users/u-reader/status", json={"disabled": True}, headers=bearer("admin"))
    assert off.status_code == 200, off.text
    assert off.json() == {"uid": "u-reader", "disabled": True, "sessions_revoked": True, "known_user": True}
    # The reader is refused at once, even with a token still alive (403 user_inactive).
    assert client.get("/api/me", headers=bearer("reader")).json()["error"]["code"] == "user_inactive"

    on = client.put("/api/admin/users/u-reader/status", json={"disabled": False}, headers=bearer("admin"))
    assert on.status_code == 200
    assert client.get("/api/me", headers=bearer("reader")).status_code == 200
    assert accounts.calls == [("set_disabled", ("u-reader", True)), ("set_disabled", ("u-reader", False))]
    assert accounts.on_in_hermes == [False, False]  # the copy was off when it was switched on: revoke again
    # The same switch-on again (its first answer lost): already applied, the sessions opened since stay open.
    again = client.put("/api/admin/users/u-reader/status", json={"disabled": False}, headers=bearer("admin"))
    assert again.status_code == 200
    assert (again.json()["sessions_revoked"], accounts.on_in_hermes[-1]) == (False, True)
    assert client.get("/api/me", headers=bearer("reader")).status_code == 200
    assert [entry.action for entry in _account_audit(directory)] == [
        "user.disable_requested",
        "user.disable",
        "user.enable_requested",
        "user.enable",
        "user.enable_requested",
        "user.enable",
    ]


def test_an_account_that_never_signed_in_is_switched_off_in_firebase(
    client: TestClient, parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts]
) -> None:
    response = client.put("/api/admin/users/u-reader/status", json={"disabled": True}, headers=bearer("admin"))
    assert response.json()["known_user"] is False
    assert parts[2].calls == [("set_disabled", ("u-reader", True))]


def test_nobody_switches_their_own_account(
    client: TestClient, parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts]
) -> None:
    response = client.put("/api/admin/users/u-admin/status", json={"disabled": True}, headers=bearer("admin"))
    assert (response.status_code, response.json()["error"]["code"]) == (409, "own_status")
    assert parts[2].calls == []


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (UnknownUserError("x"), 404, "user_not_found"),
        (AuthUnavailableError(), 503, "auth_unavailable"),
    ],
)
def test_status_errors_from_firebase(
    client: TestClient,
    parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts],
    error: Exception,
    status: int,
    code: str,
) -> None:
    parts[2].errors["set_disabled"] = error
    response = client.put("/api/admin/users/u-reader/status", json={"disabled": True}, headers=bearer("admin"))
    assert (response.status_code, response.json()["error"]["code"]) == (status, code)


def test_the_last_active_admin_is_a_409(parts: tuple[FakeVerifier, InMemoryUserDirectory, FakeAccounts]) -> None:
    class LastAdmin(InMemoryUserDirectory):
        def change_status(self, *args: Any, **kwargs: Any) -> Any:
            raise RoleConflictError("last_admin")

    response = _client(parts, LastAdmin()).put(
        "/api/admin/users/u-other/status", json={"disabled": True}, headers=bearer("admin")
    )
    assert (response.status_code, response.json()["error"]["code"]) == (409, "last_admin")


@pytest.mark.parametrize("body", [{"disabled": "yes"}, {"disabled": 1}, {}, {"disabled": True, "role": "admin"}])
def test_status_bodies_must_say_true_or_false(client: TestClient, body: dict[str, Any]) -> None:
    response = client.put("/api/admin/users/u-reader/status", json=body, headers=bearer("admin"))
    assert response.status_code == 422


def test_only_an_admin_switches_accounts(client: TestClient) -> None:
    url = "/api/admin/users/u-reader/status"
    assert client.put(url, json={"disabled": True}).status_code == 401
    for role in ("analyst", "reader"):
        assert client.put(url, json={"disabled": True}, headers=bearer(role)).status_code == 403
