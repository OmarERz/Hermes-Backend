"""FirebaseAccountManager against a patched SDK and a mock Identity Toolkit transport, and EmailQuota (no network)."""

from __future__ import annotations

import json
import logging
import re
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from firebase_admin import auth
from firebase_admin import exceptions as firebase_exceptions
from google.auth.exceptions import DefaultCredentialsError

from api.auth import AuthUnavailableError, Role
from api.auth.accounts import (
    AccountInfo,
    EmailInUseError,
    EmailQuota,
    FirebaseAccountManager,
    InvalidEmailError,
    PasswordEmailError,
    UidInUseError,
    new_uid,
)
from api.auth.directory import AccountNotCreatedError, NewAccount
from api.auth.firebase import EMULATOR_ENV_VAR, FirebaseTokenVerifier
from api.auth.role_admin import UnknownUserError

pytestmark = pytest.mark.unit

EMAIL = "nueva.persona@example.com"
FAKE_ACCESS = "access-1"  # a fake OAuth access token
ADMIN_IP = "203.0.113.7"


def _app(project: str = "demo-hermes", token: Any = FAKE_ACCESS) -> Any:
    def get_access_token() -> Any:
        if isinstance(token, Exception):
            raise token
        return SimpleNamespace(access_token=token)

    return SimpleNamespace(project_id=project, credential=SimpleNamespace(get_access_token=get_access_token))


class Transport:
    """Records the requests to Identity Toolkit and answers with a fixed response (or raises)."""

    def __init__(self, status: int = 200, body: Any = None, error: Exception | None = None) -> None:
        self.status, self.body, self.error = status, body, error
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.error:
            raise self.error
        content = self.body if isinstance(self.body, bytes) else json.dumps(self.body or {"email": EMAIL}).encode()
        return httpx.Response(self.status, content=content)


def _manager(
    monkeypatch: pytest.MonkeyPatch, app: Any = None, transport: Transport | None = None
) -> tuple[FirebaseAccountManager, Transport]:
    verifier = FirebaseTokenVerifier("demo-hermes")
    monkeypatch.setattr(verifier, "sdk_app", lambda: app or _app())
    transport = transport or Transport()
    client = httpx.Client(transport=httpx.MockTransport(transport))
    return FirebaseAccountManager(verifier, client, clock=lambda: 1000.25, sleep=lambda _s: None), transport


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, Any]]:
    """The SDK's user functions, patched to record their calls and succeed."""
    found: list[tuple[str, Any]] = []

    def create_user(**kwargs: Any) -> Any:
        found.append(("create", {k: v for k, v in kwargs.items() if k != "app"}))
        return SimpleNamespace(uid=kwargs["uid"], email=kwargs["email"].lower())

    monkeypatch.delenv(EMULATOR_ENV_VAR, raising=False)
    monkeypatch.setattr(auth, "create_user", create_user)
    monkeypatch.setattr(auth, "set_custom_user_claims", lambda uid, claims, app: found.append(("claims", claims)))
    monkeypatch.setattr(auth, "delete_user", lambda uid, app: found.append(("delete", uid)))
    monkeypatch.setattr(auth, "update_user", lambda uid, app, **kw: found.append(("update", (uid, kw))))
    monkeypatch.setattr(auth, "revoke_refresh_tokens", lambda uid, app: found.append(("revoke", uid)))
    monkeypatch.setattr(auth, "get_user", lambda uid, app: SimpleNamespace(uid=uid, email=EMAIL, disabled=uid == "off"))
    return found


def _raise(error: Exception) -> Any:
    def fail(*_args: Any, **_kwargs: Any) -> Any:
        raise error

    return fail


# --- create ----------------------------------------------------------------------------------------------------


def test_new_uids_look_like_firebases_and_never_repeat() -> None:
    uids = {new_uid() for _ in range(50)}
    assert len(uids) == 50
    assert all(re.fullmatch(r"[0-9a-f]{28}", uid) for uid in uids)


def test_create_makes_an_account_without_password_and_sets_the_role(
    monkeypatch: pytest.MonkeyPatch, calls: list[tuple[str, Any]]
) -> None:
    manager, _ = _manager(monkeypatch)
    account = manager.create("u-new", "Nueva.Persona@example.com", Role.ANALYST)
    # The copy keeps the e-mail as Firebase stored it.
    assert account == NewAccount(uid="u-new", email="nueva.persona@example.com")
    assert calls == [
        ("create", {"uid": "u-new", "email": "Nueva.Persona@example.com", "email_verified": False, "disabled": False}),
        ("claims", {"role": "analyst"}),
    ]


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (auth.EmailAlreadyExistsError("taken", None, None), EmailInUseError),
        (auth.UidAlreadyExistsError("taken", None, None), UidInUseError),
        (ValueError("Malformed email address string"), InvalidEmailError),
        (firebase_exceptions.InvalidArgumentError("INVALID_EMAIL"), InvalidEmailError),
    ],
)
def test_firebase_refusals_say_nothing_was_created(
    monkeypatch: pytest.MonkeyPatch, calls: list[tuple[str, Any]], error: Exception, expected: type[Exception]
) -> None:
    manager, _ = _manager(monkeypatch)
    monkeypatch.setattr(auth, "create_user", _raise(error))
    monkeypatch.setattr(auth, "get_user", _raise(auth.UserNotFoundError("none")))  # no account with the new uid
    with pytest.raises(expected) as raised:
        manager.create("u-new", EMAIL, Role.READER)
    assert isinstance(raised.value, AccountNotCreatedError)
    assert calls == []


DUPLICATES = [auth.EmailAlreadyExistsError("taken", None, None), auth.UidAlreadyExistsError("taken", None, None)]


@pytest.mark.parametrize("error", DUPLICATES)
def test_a_retried_creation_that_finds_its_own_account_goes_on(
    monkeypatch: pytest.MonkeyPatch, calls: list[tuple[str, Any]], error: Exception
) -> None:
    """The SDK retries a POST whose answer was lost: the retry finds the account this call created (its random uid,
    its e-mail), which goes on to get its role."""
    manager, _ = _manager(monkeypatch)
    monkeypatch.setattr(auth, "create_user", _raise(error))
    monkeypatch.setattr(
        auth, "get_user", lambda uid, app: SimpleNamespace(uid=uid, email="nueva.persona@example.com", disabled=False)
    )
    account = manager.create("u-new", "Nueva.Persona@example.com", Role.READER)
    assert account == NewAccount(uid="u-new", email="nueva.persona@example.com")
    assert calls == [("claims", {"role": "reader"})]


@pytest.mark.parametrize("error", DUPLICATES)
@pytest.mark.parametrize(
    "found",
    [
        SimpleNamespace(uid="u-new", email="otra@example.com", disabled=False),  # another e-mail: not ours
        auth.UserNotFoundError("none"),
        firebase_exceptions.UnavailableError("down"),  # cannot tell: left alone
    ],
)
def test_a_duplicate_that_is_not_this_calls_account_is_never_touched(
    monkeypatch: pytest.MonkeyPatch, calls: list[tuple[str, Any]], error: Exception, found: Any
) -> None:
    manager, _ = _manager(monkeypatch)
    monkeypatch.setattr(auth, "create_user", _raise(error))
    monkeypatch.setattr(auth, "get_user", _raise(found) if isinstance(found, Exception) else lambda uid, app: found)
    with pytest.raises(AccountNotCreatedError):
        manager.create("u-new", EMAIL, Role.READER)
    assert calls == []


@pytest.mark.parametrize("step", ["create_user", "set_custom_user_claims"])
def test_a_half_made_account_is_left_to_the_caller_to_discard(
    monkeypatch: pytest.MonkeyPatch, calls: list[tuple[str, Any]], caplog: pytest.LogCaptureFixture, step: str
) -> None:
    """The SDK creates the account and reads it back, then the claim is set: a failure in between may leave it in
    Firebase, so the error is AuthUnavailableError (not AccountNotCreatedError) and the caller discards the uid."""
    manager, _ = _manager(monkeypatch)
    monkeypatch.setattr(auth, step, _raise(firebase_exceptions.UnavailableError("down")))
    with caplog.at_level(logging.WARNING, logger="api.auth.accounts"), pytest.raises(AuthUnavailableError):
        manager.create("u-new", EMAIL, Role.READER)
    assert [call for call in calls if call[0] == "delete"] == []
    assert EMAIL not in caplog.text


def test_missing_credentials_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    verifier = FirebaseTokenVerifier("demo-hermes")
    monkeypatch.setattr(verifier, "sdk_app", _raise(OSError("unreadable")))
    manager = FirebaseAccountManager(verifier)
    for action in (
        lambda: manager.create("u-new", EMAIL, Role.READER),
        lambda: manager.discard("u1"),
        lambda: manager.lookup("u1"),
        lambda: manager.set_disabled("u1", True),
        lambda: manager.send_password_setup(EMAIL, ADMIN_IP),
    ):
        with pytest.raises(AuthUnavailableError):
            action()


# --- discard, lookup, set_disabled -----------------------------------------------------------------------------


def test_discard_deletes_and_ignores_an_account_already_gone(
    monkeypatch: pytest.MonkeyPatch, calls: list[tuple[str, Any]]
) -> None:
    manager, _ = _manager(monkeypatch)
    manager.discard("new-1")
    assert calls == [("delete", "new-1")]
    monkeypatch.setattr(auth, "delete_user", _raise(auth.UserNotFoundError("gone")))
    manager.discard("new-1")
    monkeypatch.setattr(auth, "delete_user", _raise(firebase_exceptions.UnavailableError("down")))
    with pytest.raises(AuthUnavailableError):
        manager.discard("new-1")


def test_lookup_reads_the_email_and_state(monkeypatch: pytest.MonkeyPatch, calls: list[tuple[str, Any]]) -> None:
    manager, _ = _manager(monkeypatch)
    assert manager.lookup("u1") == AccountInfo(uid="u1", email=EMAIL, disabled=False)
    assert manager.lookup("off").disabled is True
    for error, expected in (
        (auth.UserNotFoundError("none"), UnknownUserError),
        (ValueError("bad uid"), UnknownUserError),
        (firebase_exceptions.UnavailableError("down"), AuthUnavailableError),
    ):
        monkeypatch.setattr(auth, "get_user", _raise(error))
        with pytest.raises(expected):
            manager.lookup("u1")


def _timed_manager(monkeypatch: pytest.MonkeyPatch, calls: list[tuple[str, Any]]) -> FirebaseAccountManager:
    """A manager whose waits are recorded among the SDK calls."""
    verifier = FirebaseTokenVerifier("demo-hermes")
    monkeypatch.setattr(verifier, "sdk_app", _app)
    return FirebaseAccountManager(verifier, clock=lambda: 1000.25, sleep=lambda s: calls.append(("sleep", s)))


def test_disabling_switches_the_account_off_and_then_revokes_after_the_second(
    monkeypatch: pytest.MonkeyPatch, calls: list[tuple[str, Any]]
) -> None:
    """Firebase revocation is second-granular: revoking in the second of the switch-off could spare its tokens."""
    manager = _timed_manager(monkeypatch, calls)
    assert manager.set_disabled("u1", True) is True
    assert calls == [("update", ("u1", {"disabled": True})), ("sleep", 0.75), ("revoke", "u1")]


def test_enabling_revokes_the_old_sessions_before_switching_the_account_on(
    monkeypatch: pytest.MonkeyPatch, calls: list[tuple[str, Any]]
) -> None:
    manager = _timed_manager(monkeypatch, calls)
    assert manager.set_disabled("u1", False) is True
    assert calls == [("sleep", 0.75), ("revoke", "u1"), ("update", ("u1", {"disabled": False}))]


def test_a_failed_revocation_keeps_the_account_off(
    monkeypatch: pytest.MonkeyPatch, calls: list[tuple[str, Any]]
) -> None:
    manager, _ = _manager(monkeypatch)
    monkeypatch.setattr(auth, "revoke_refresh_tokens", _raise(firebase_exceptions.UnavailableError("down")))
    assert manager.set_disabled("u1", True) is False
    assert calls == [("update", ("u1", {"disabled": True}))]
    # Switching it on needs the revocation first: without it the account stays off.
    with pytest.raises(AuthUnavailableError):
        manager.set_disabled("u1", False)
    assert calls == [("update", ("u1", {"disabled": True}))]


def test_enabling_an_unknown_account_is_unknown_not_a_failed_revocation(
    monkeypatch: pytest.MonkeyPatch, calls: list[tuple[str, Any]]
) -> None:
    manager, _ = _manager(monkeypatch)
    monkeypatch.setattr(auth, "get_user", _raise(auth.UserNotFoundError("none")))
    with pytest.raises(UnknownUserError):
        manager.set_disabled("ghost", False)
    assert calls == []


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (auth.UserNotFoundError("none"), UnknownUserError),
        (ValueError("bad uid"), UnknownUserError),
        (firebase_exceptions.UnavailableError("down"), AuthUnavailableError),
    ],
)
def test_set_disabled_maps_firebase_errors(
    monkeypatch: pytest.MonkeyPatch, calls: list[tuple[str, Any]], error: Exception, expected: type[Exception]
) -> None:
    manager, _ = _manager(monkeypatch)
    monkeypatch.setattr(auth, "update_user", _raise(error))
    with pytest.raises(expected):
        manager.set_disabled("u1", True)
    assert calls == []
    with pytest.raises(expected):
        manager.set_disabled("u1", False)
    assert calls == [("revoke", "u1")]


# --- the password e-mail ---------------------------------------------------------------------------------------


def test_the_password_email_is_sent_by_identity_toolkit_with_the_service_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(EMULATOR_ENV_VAR, raising=False)
    manager, transport = _manager(monkeypatch, app=_app(project="hermes-real"))
    manager.send_password_setup(EMAIL, ADMIN_IP)
    [request] = transport.requests
    assert str(request.url) == "https://identitytoolkit.googleapis.com/v1/projects/hermes-real/accounts:sendOobCode"
    assert request.headers["authorization"] == "Bearer access-1"
    # No returnOobLink: Google sends the e-mail and the link never reaches Hermes.
    assert json.loads(request.content) == {"requestType": "PASSWORD_RESET", "email": EMAIL, "userIp": "203.0.113.7"}


@pytest.mark.parametrize("user_ip", [None, "", "testclient", "999.1.1.1"])
def test_without_the_admins_ip_nothing_is_sent(monkeypatch: pytest.MonkeyPatch, user_ip: str | None) -> None:
    """Identity Toolkit requires userIp for PASSWORD_RESET: no request goes out without a valid one."""
    monkeypatch.delenv(EMULATOR_ENV_VAR, raising=False)
    manager, transport = _manager(monkeypatch, app=_app(project="hermes-real"))
    with pytest.raises(PasswordEmailError) as raised:
        manager.send_password_setup(EMAIL, user_ip)
    assert raised.value.reason == "user_ip_missing"
    assert transport.requests == []


def test_the_emulator_gets_the_same_call_with_its_admin_bearer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(EMULATOR_ENV_VAR, "127.0.0.1:9099")
    manager, transport = _manager(monkeypatch, app=_app(token=AssertionError("no token in emulator mode")))
    manager.send_password_setup(EMAIL, ADMIN_IP)
    [request] = transport.requests
    assert str(request.url) == (
        "http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/projects/demo-hermes/accounts:sendOobCode"
    )
    assert request.headers["authorization"] == "Bearer owner"


def test_the_emulator_is_never_used_for_a_real_project(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(EMULATOR_ENV_VAR, "127.0.0.1:9099")
    manager, transport = _manager(monkeypatch, app=_app(project="hermes-real"))
    with pytest.raises(PasswordEmailError) as raised:
        manager.send_password_setup(EMAIL, ADMIN_IP)
    assert raised.value.reason == "emulator_not_allowed"
    assert transport.requests == []


@pytest.mark.parametrize(
    ("transport", "reason"),
    [
        (Transport(400, {"error": {"code": 400, "message": "EMAIL_NOT_FOUND"}}), "EMAIL_NOT_FOUND"),
        (Transport(400, {"error": {"message": "TOO_MANY_ATTEMPTS_TRY_LATER : wait"}}), "TOO_MANY_ATTEMPTS_TRY_LATER"),
        (Transport(403, {"error": {"message": "nueva.persona@example.com is not allowed"}}), "http_403"),
        (Transport(500, b"<html>oops</html>"), "http_500"),
        (Transport(500, {"error": "flat"}), "http_500"),
        (Transport(error=httpx.ConnectTimeout("slow")), "unreachable"),
    ],
)
def test_a_password_email_that_was_not_sent_names_only_a_short_reason(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, transport: Transport, reason: str
) -> None:
    monkeypatch.delenv(EMULATOR_ENV_VAR, raising=False)
    manager, _ = _manager(monkeypatch, app=_app(project="hermes-real"), transport=transport)
    with caplog.at_level(logging.WARNING, logger="api.auth.accounts"), pytest.raises(PasswordEmailError) as raised:
        manager.send_password_setup(EMAIL, ADMIN_IP)
    assert raised.value.reason == reason
    assert "setup e-mail not sent" in caplog.text
    assert EMAIL not in caplog.text
    assert "access-1" not in caplog.text


@pytest.mark.parametrize("token", [DefaultCredentialsError("no credentials"), "", None])
def test_a_credential_without_token_sends_nothing(monkeypatch: pytest.MonkeyPatch, token: Any) -> None:
    monkeypatch.delenv(EMULATOR_ENV_VAR, raising=False)
    manager, transport = _manager(monkeypatch, app=_app(project="hermes-real", token=token))
    with pytest.raises(PasswordEmailError) as raised:
        manager.send_password_setup(EMAIL, ADMIN_IP)
    assert raised.value.reason == "credentials"
    assert transport.requests == []


def test_the_default_client_ignores_proxies_and_redirects() -> None:
    manager = FirebaseAccountManager(FirebaseTokenVerifier("demo-hermes"))
    client = manager._http
    assert client.follow_redirects is False
    assert client.timeout.connect == 10.0
    assert client._trust_env is False


# --- EmailQuota ------------------------------------------------------------------------------------------------


def test_the_quota_caps_each_admin_in_a_sliding_window() -> None:
    now = [0.0]
    quota = EmailQuota(limit=2, window=60.0, clock=lambda: now[0])
    assert [quota.take("a"), quota.take("a"), quota.take("a")] == [True, True, False]
    assert quota.take("b") is True  # each admin has its own count
    now[0] = 59.9
    assert quota.take("a") is False
    now[0] = 60.0
    # Both e-mails of second 0 left the window: two more fit, the third does not.
    assert [quota.take("a"), quota.take("a"), quota.take("a")] == [True, True, False]
