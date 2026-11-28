"""User list (F18.2): the app_user copy joined with the Firebase directory, against a patched SDK (no network)."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from firebase_admin import auth
from firebase_admin import exceptions as firebase_exceptions

from api.auth import AuthUnavailableError, Role
from api.auth.firebase import FirebaseTokenVerifier
from api.auth.user_list import (
    DirectoryUser,
    FirebaseUserLister,
    StoredUser,
    effective_role,
    merge_users,
    page_at,
)

LOGIN = datetime(2026, 11, 23, 10, 0, tzinfo=UTC)


def stored(uid: str, role: Role, *, active: bool = True, email: str | None = None) -> StoredUser:
    return StoredUser(uid, email or f"{uid}@example.test", None, role, active, LOGIN)


def account(
    uid: str, claim: Role | None, *, disabled: bool = False, name: str | None = None, email: str | None = "-"
) -> DirectoryUser:
    return DirectoryUser(uid, f"{uid}@example.test" if email == "-" else email, name, claim, disabled)


@pytest.mark.parametrize(
    ("claim", "copy", "refused", "expected"),
    [
        (Role.ADMIN, stored("u", Role.ANALYST), False, Role.ANALYST),  # the copy caps a stale claim
        (Role.READER, stored("u", Role.ADMIN), False, Role.READER),  # an upgrade waits for the claim
        (Role.ANALYST, None, False, Role.ANALYST),  # never signed in: the claim it will sign in with
        (None, stored("u", Role.ADMIN), False, None),  # no claim: its token is refused
        (Role.ADMIN, stored("u", Role.ADMIN, active=False), False, None),  # deactivated in Hermes
        (Role.ADMIN, stored("u", Role.ADMIN), True, None),  # its sign-in is refused (disabled, no e-mail...)
    ],
)
def test_effective_role_follows_the_request_rule(
    claim: Role | None, copy: StoredUser | None, refused: bool, expected: Role | None
) -> None:
    assert effective_role(claim, copy, refused) is expected


def test_no_effective_role_for_an_account_whose_sign_in_is_refused() -> None:
    """D-030: without an e-mail the token is refused (401); an e-mail another account's copy owns gives a 409."""
    views = merge_users(
        [stored("old", Role.ADMIN, email="Reused@example.test")],
        [
            account("noemail", Role.ADMIN, email=None),
            account("blank", Role.ADMIN, email="  "),
            account("new", Role.ADMIN, email="reused@example.test"),  # recreated account, old copy still there
            account("old", Role.ADMIN, email="reused@example.test"),
        ],
    )
    by_uid = {v.uid: v for v in views}
    assert by_uid["noemail"].effective_role is None and by_uid["blank"].effective_role is None
    assert by_uid["new"].effective_role is None and by_uid["new"].active is True  # enabled, but cannot sign in
    assert by_uid["old"].effective_role is Role.ADMIN  # the owner of the e-mail still signs in


def test_merge_lists_both_sides_ordered_by_email() -> None:
    copies = [stored("b", Role.ADMIN, email="Bea@example.test"), stored("gone", Role.READER)]
    accounts = [account("b", Role.ADMIN, name="Bea"), account("a", Role.READER, name="Ana")]
    views = merge_users(copies, accounts)
    assert [v.uid for v in views] == ["a", "b", "gone"]
    ana, bea, gone = views
    assert ana.signed_in is False and ana.role is None and ana.effective_role is Role.READER and ana.active
    assert ana.display_name == "Ana" and ana.last_login_at is None
    assert bea.signed_in and bea.role is Role.ADMIN and bea.claim_role is Role.ADMIN and bea.email == "Bea@example.test"
    assert bea.display_name == "Bea" and bea.last_login_at == LOGIN
    # The copy of an account deleted in Firebase stays, with no claim, no effective role, and not active.
    assert gone.claim_role is None and gone.effective_role is None and gone.role is Role.READER
    assert gone.active is False and bea.active is True


def test_a_copy_made_before_the_first_sign_in_has_a_role_but_has_not_signed_in() -> None:
    """An account an admin created (D-105) or the command line set up: Hermes stores its role, nobody signed in yet."""
    invited = StoredUser("n", "n@example.test", None, Role.ANALYST, True, None)
    (view,) = merge_users([invited], [account("n", Role.ANALYST)])
    assert (view.role, view.effective_role, view.signed_in, view.last_login_at) == (
        Role.ANALYST,
        Role.ANALYST,
        False,
        None,
    )


def test_merge_marks_a_disabled_account_that_never_signed_in_as_inactive() -> None:
    (view,) = merge_users([], [account("x", Role.ADMIN, disabled=True)])
    assert view.active is False and view.effective_role is None


def test_an_account_disabled_in_firebase_is_inactive_even_with_an_active_copy() -> None:
    """API-04: `active` means active in Hermes and in Firebase."""
    (view,) = merge_users([stored("x", Role.ADMIN)], [account("x", Role.ADMIN, disabled=True)])
    assert view.active is False and view.effective_role is None and view.signed_in is True
    (deactivated,) = merge_users([stored("y", Role.ADMIN, active=False)], [account("y", Role.ADMIN)])
    assert deactivated.active is False


def test_pages_resume_at_the_next_position() -> None:
    views = merge_users([], [account(f"u{i}", Role.READER) for i in range(5)])
    first, after = page_at(views, 0, 2)
    assert [v.uid for v in first] == ["u0", "u1"] and after == 2
    last, after = page_at(views, 2, 3)
    assert [v.uid for v in last] == ["u2", "u3", "u4"] and after is None
    assert page_at(views, 9, 3) == ([], None) and page_at(views, -4, 1)[0][0].uid == "u0"


class FakePage:
    def __init__(self, records: list[Any]) -> None:
        self.records = records

    def iterate_all(self) -> Any:
        return iter(self.records)


def record(uid: str, claims: dict[str, Any] | None, disabled: bool = False) -> Any:
    return SimpleNamespace(
        uid=uid, email=f"{uid}@example.test", display_name=None, custom_claims=claims, disabled=disabled
    )


@pytest.fixture
def verifier(monkeypatch: pytest.MonkeyPatch) -> FirebaseTokenVerifier:
    found = FirebaseTokenVerifier("demo-hermes")
    monkeypatch.setattr(found, "sdk_app", lambda: "app")
    return found


def test_lister_reads_claims_and_ignores_unknown_roles(
    verifier: FirebaseTokenVerifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    pages: list[tuple[int, Any]] = []

    def list_users(max_results: int, app: Any) -> FakePage:
        pages.append((max_results, app))
        return FakePage([record("a", {"role": "admin", "team": "x"}), record("b", {"role": "boss"}), record("c", None)])

    monkeypatch.setattr(auth, "list_users", list_users)
    users = FirebaseUserLister(verifier).list_users()
    assert pages == [(1000, "app")]
    assert [(u.uid, u.claim_role) for u in users] == [("a", Role.ADMIN), ("b", None), ("c", None)]


def test_lister_reads_every_page_of_the_directory(
    verifier: FirebaseTokenVerifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`iterate_all` follows Firebase's pages: accounts after the first 1 000 are listed too (D-088)."""
    many = [record(f"u{i:04d}", {"role": "reader"}) for i in range(2500)]
    monkeypatch.setattr(auth, "list_users", lambda max_results, app: FakePage(many))
    users = FirebaseUserLister(verifier).list_users()
    assert len(users) == 2500 and users[-1].uid == "u2499"
    views = merge_users([], users)
    first, after = page_at(views, 0, 200)
    assert after == 200 and len(first) == 200
    assert page_at(views, 2400, 200) == (views[2400:], None)


@pytest.mark.parametrize(
    "error", [firebase_exceptions.UnavailableError("down"), OSError("no route"), ValueError("bad credentials")]
)
def test_lister_failures_are_auth_unavailable(
    verifier: FirebaseTokenVerifier, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    def failing(max_results: int, app: Any) -> Any:
        raise error

    monkeypatch.setattr(auth, "list_users", failing)
    with pytest.raises(AuthUnavailableError):
        FirebaseUserLister(verifier).list_users()


def test_lister_without_credentials_is_auth_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    verifier = FirebaseTokenVerifier("demo-hermes")

    def no_credentials() -> Any:
        raise OSError("unreadable")

    monkeypatch.setattr(verifier, "sdk_app", no_credentials)
    with pytest.raises(AuthUnavailableError):
        FirebaseUserLister(verifier).list_users()
