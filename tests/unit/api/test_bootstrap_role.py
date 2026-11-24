"""`python -m api.auth.bootstrap` (make set-role, D-087): the first admin of a real Firebase project.

Fakes stand in for Firebase and the database here; tests/integration covers the SQL directory and the emulator.
"""

from __future__ import annotations

import io
from collections.abc import Callable
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from authfakes import SETTINGS
from firebase_admin import auth
from firebase_admin import exceptions as firebase_exceptions
from sqlalchemy.exc import OperationalError

from api.auth import AuthUnavailableError, Role, VerifiedIdentity, bootstrap
from api.auth.bootstrap import FirebaseUser, FirebaseUserLookup, Services, bootstrap_role, main
from api.auth.directory import BootstrapResult, RoleConflictError, SqlUserDirectory, UserConflictError, UserRecord
from api.auth.role_admin import RevocationPendingError, UnknownUserError

pytestmark = pytest.mark.unit

EMAIL = "person@example.com"
CREATED = datetime(2026, 11, 20, 9, 30, tzinfo=UTC)


def record(role: Role, active: bool = True, uid: str = "uid-ana") -> UserRecord:
    return UserRecord(uuid4(), uid, EMAIL, "Ana", role, active, datetime.now(UTC), None)


def account(claim: str | None = None, verified: bool = True) -> FirebaseUser:
    return FirebaseUser("uid-ana", EMAIL, "Ana", claim, verified, CREATED)


class FakeUsers:
    def __init__(self, found: FirebaseUser | Exception, fresh_claim: str | None = "same") -> None:
        self.found = found
        self.fresh_claim = fresh_claim
        self.asked: list[str] = []

    def by_email(self, email: str) -> FirebaseUser:
        self.asked.append(email)
        if isinstance(self.found, Exception):
            raise self.found
        return self.found

    def role_claim(self, uid: str) -> str | None:
        if self.fresh_claim == "same":
            assert isinstance(self.found, FirebaseUser)
            return self.found.role_claim
        return self.fresh_claim


class FakeManager:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.assigned: list[tuple[str, Role]] = []

    def assign(self, uid: str, role: Role) -> None:
        self.assigned.append((uid, role))
        if self.error:
            raise self.error


class FakeDirectory:
    """Calls ``apply`` like SqlUserDirectory (always, under its locks) unless a canned result is given."""

    def __init__(self, result: BootstrapResult | Exception | None = None) -> None:
        self.result = result
        self.calls: list[tuple[VerifiedIdentity, bool]] = []
        self.revoked: bool | None = None

    def bootstrap_role(
        self, identity: VerifiedIdentity, apply: Callable[[], bool], claim_holds_role: bool
    ) -> BootstrapResult:
        self.calls.append((identity, claim_holds_role))
        if isinstance(self.result, Exception):
            raise self.result
        if self.result is not None:
            return self.result
        self.revoked = apply()
        return BootstrapResult(record(identity.role), True, True, self.revoked)


def test_sets_the_claim_and_syncs_the_copy_when_the_claim_differs() -> None:
    users, manager, directory = FakeUsers(account("reader")), FakeManager(), FakeDirectory()
    found, result = bootstrap_role(EMAIL, Role.ADMIN, Services(users, manager, directory))
    assert users.asked == [EMAIL]
    assert found == account("reader")
    assert manager.assigned == [("uid-ana", Role.ADMIN)]
    identity, claim_holds = directory.calls[0]
    assert identity == VerifiedIdentity(uid="uid-ana", email=EMAIL, display_name="Ana", role=Role.ADMIN)
    assert claim_holds is False
    assert result.sessions_revoked is True


def test_a_claim_that_already_holds_the_role_is_not_written_again() -> None:
    manager, directory = FakeManager(), FakeDirectory()
    bootstrap_role(EMAIL, Role.ADMIN, Services(FakeUsers(account("admin")), manager, directory))
    assert manager.assigned == []
    assert directory.calls[0][1] is True
    assert directory.revoked is False


def test_the_claim_is_read_again_under_the_locks() -> None:
    # The lookup saw the role already set, but an admin changed it before the directory took its locks.
    manager, directory = FakeManager(), FakeDirectory()
    bootstrap_role(EMAIL, Role.ADMIN, Services(FakeUsers(account("admin"), fresh_claim="reader"), manager, directory))
    assert manager.assigned == [("uid-ana", Role.ADMIN)]
    assert directory.revoked is True


def test_a_failed_revocation_still_counts_as_assigned_without_revoked_sessions() -> None:
    directory = FakeDirectory()
    bootstrap_role(
        EMAIL, Role.ADMIN, Services(FakeUsers(account()), FakeManager(RevocationPendingError("uid-ana")), directory)
    )
    assert directory.revoked is False


def services(
    users: FakeUsers | None = None, manager: FakeManager | None = None, directory: FakeDirectory | None = None
) -> Callable[[], Services]:
    return lambda: Services(users or FakeUsers(account()), manager or FakeManager(), directory or FakeDirectory())


def run(*args: str, wiring: Callable[[], Services]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(["--email", EMAIL, *args], services=wiring, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_main_reports_a_new_assignment_without_printing_the_email() -> None:
    code, text, errors = run("--role", "admin", wiring=services())
    assert (code, errors) == (0, "")
    assert "✔ role admin set for uid-ana (created in Hermes); sessions revoked" in text
    assert EMAIL not in text


def test_main_reports_an_update_whose_sessions_were_not_revoked() -> None:
    result = BootstrapResult(record(Role.ANALYST), changed=True, created=False, sessions_revoked=False)
    code, text, _ = run("--role", "analyst", wiring=services(directory=FakeDirectory(result)))
    assert code == 0
    assert "(updated); sessions not revoked" in text


def test_main_reports_nothing_to_do_when_the_role_is_already_there() -> None:
    result = BootstrapResult(record(Role.ADMIN), changed=False, created=False, sessions_revoked=False)
    code, text, _ = run("--role", "admin", wiring=services(directory=FakeDirectory(result)))
    assert (code, text.strip()) == (0, "✔ uid-ana already has the role admin; nothing changed")


def test_main_warns_when_the_user_is_inactive_in_hermes() -> None:
    result = BootstrapResult(record(Role.ADMIN, active=False), changed=True, created=False, sessions_revoked=True)
    code, _, errors = run("--role", "admin", wiring=services(directory=FakeDirectory(result)))
    assert code == 0
    assert "⚠ the user is inactive in Hermes" in errors


@pytest.mark.parametrize(("created", "shown"), [(CREATED, "created 2026-11-20T09:30+00:00"), (None, "created unknown")])
def test_an_unverified_email_needs_the_uid_confirmed_before_anything_is_written(
    created: datetime | None, shown: str
) -> None:
    # Email/Password sign-up does not prove the address: someone may have registered it first.
    unverified = FirebaseUser("uid-ana", EMAIL, "Ana", None, False, created)
    manager, directory = FakeManager(), FakeDirectory()
    code, text, errors = run("--role", "admin", wiring=services(FakeUsers(unverified), manager, directory))
    assert (code, text, manager.assigned, directory.calls) == (3, "", [], [])
    assert "⚠ the account's e-mail is not verified in Firebase: account uid-ana" in errors
    assert shown in errors
    assert "--confirm-uid uid-ana (make set-role ... CONFIRM_UID=uid-ana)" in errors
    assert EMAIL not in errors

    code, text, _ = run("--role", "admin", "--confirm-uid", "uid-ana", wiring=services(FakeUsers(unverified)))
    assert code == 0
    assert "✔ role admin set for uid-ana" in text


@pytest.mark.parametrize("verified", [True, False])
def test_a_confirmed_uid_of_another_account_is_refused(verified: bool) -> None:
    manager = FakeManager()
    users = FakeUsers(account(verified=verified))
    code, _, errors = run("--role", "admin", "--confirm-uid", "uid-other", wiring=services(users, manager))
    assert (code, manager.assigned) == (3, [])
    assert "--confirm-uid is not the uid of the account with that e-mail; nothing changed" in errors


def test_a_database_error_is_reported_without_its_parameters() -> None:
    failing = FakeDirectory(OperationalError("UPDATE app_user SET email=%(email)s", {"email": EMAIL}, Exception()))
    code, _, errors = run("--role", "admin", wiring=services(directory=failing))
    assert code == 1
    assert "database error (OperationalError)" in errors
    assert EMAIL not in errors


@pytest.mark.parametrize(
    ("users", "directory", "message"),
    [
        (FakeUsers(UnknownUserError("x")), None, "no Firebase account has that e-mail"),
        (FakeUsers(AuthUnavailableError()), None, "Firebase could not be reached"),
        (None, FakeDirectory(RoleConflictError("last_admin")), "this is the last active admin"),
        (None, FakeDirectory(RoleConflictError("other")), "refused: other"),
        (None, FakeDirectory(UserConflictError("uid-ana")), "another Hermes user already has that e-mail"),
    ],
)
def test_main_explains_each_refusal_on_stderr(
    users: FakeUsers | None, directory: FakeDirectory | None, message: str
) -> None:
    code, text, errors = run("--role", "admin", wiring=services(users=users, directory=directory))
    assert (code, text) == (1, "")
    assert message in errors
    assert EMAIL not in errors


def test_main_rejects_an_unknown_role() -> None:
    with pytest.raises(SystemExit):
        main(["--email", EMAIL, "--role", "owner"], services=services(), out=io.StringIO(), err=io.StringIO())


def test_main_builds_the_apis_wiring_from_the_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    built: list[Any] = []

    def fake_default(settings: Any) -> Services:
        built.append(settings)
        return services()()

    monkeypatch.setattr(bootstrap, "default_services", fake_default)
    monkeypatch.setattr(bootstrap, "Settings", lambda: "settings")
    assert main(["--email", EMAIL, "--role", "reader"], out=io.StringIO(), err=io.StringIO()) == 0
    assert built == ["settings"]


def test_default_services_share_one_firebase_app_and_the_app_database() -> None:
    wiring = bootstrap.default_services(SETTINGS)
    assert isinstance(wiring.users, FirebaseUserLookup)
    assert wiring.manager._verifier is wiring.users._verifier  # type: ignore[attr-defined]
    assert isinstance(wiring.directory, SqlUserDirectory)
    engine = wiring.directory._sessions.kw["bind"]
    assert engine.url.username == "app"  # SETTINGS.database_url: the API's least-privilege role


class FakeSdk:
    def __init__(self, app: object | Exception = "app") -> None:
        self.app = app

    def sdk_app(self) -> object:
        if isinstance(self.app, Exception):
            raise self.app
        return self.app


def user_record(
    claims: dict[str, Any] | None, verified: bool = True, created_ms: int | None = 1_795_000_000_000
) -> Any:
    return SimpleNamespace(
        uid="uid-ana",
        email=EMAIL,
        display_name="Ana",
        custom_claims=claims,
        email_verified=verified,
        user_metadata=SimpleNamespace(creation_timestamp=created_ms),
    )


def lookup(monkeypatch: pytest.MonkeyPatch, answer: object, app: object | Exception = "app") -> FirebaseUserLookup:
    def get_user(_key: str, app: object) -> object:
        assert app == "app"
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(auth, "get_user_by_email", get_user)
    monkeypatch.setattr(auth, "get_user", get_user)
    return FirebaseUserLookup(FakeSdk(app))  # type: ignore[arg-type]


def test_lookup_reads_the_role_claim_and_the_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    found = lookup(monkeypatch, user_record({"role": "admin", "other": 1})).by_email(EMAIL)
    assert found == FirebaseUser("uid-ana", EMAIL, "Ana", "admin", True, datetime.fromtimestamp(1_795_000_000, UTC))
    unverified = lookup(monkeypatch, user_record(None, verified=False, created_ms=None)).by_email(EMAIL)
    assert (unverified.role_claim, unverified.email_verified, unverified.created_at) == (None, False, None)
    assert lookup(monkeypatch, user_record({"role": 3})).by_email(EMAIL).role_claim is None
    assert lookup(monkeypatch, user_record({"role": "reader"})).role_claim("uid-ana") == "reader"


@pytest.mark.parametrize("error", [auth.UserNotFoundError("gone"), ValueError("malformed")])
def test_lookup_maps_a_missing_account(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    with pytest.raises(UnknownUserError):
        lookup(monkeypatch, error).by_email(EMAIL)
    with pytest.raises(UnknownUserError):
        lookup(monkeypatch, error).role_claim("uid-ana")


def test_lookup_maps_an_unreachable_firebase(monkeypatch: pytest.MonkeyPatch) -> None:
    down = firebase_exceptions.UnavailableError("down")
    with pytest.raises(AuthUnavailableError):
        lookup(monkeypatch, down).by_email(EMAIL)
    with pytest.raises(AuthUnavailableError):
        lookup(monkeypatch, down).role_claim("uid-ana")
    with pytest.raises(AuthUnavailableError):
        lookup(monkeypatch, user_record(None), app=ValueError("bad credentials file")).by_email(EMAIL)
