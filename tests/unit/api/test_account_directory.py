"""InMemoryUserDirectory: accounts an admin creates and switches off or on (D-105), with their audit trail."""

from __future__ import annotations

import pytest

from api.auth import InMemoryUserDirectory, Role, VerifiedIdentity
from api.auth.directory import (
    AccountNotCreatedError,
    AccountRequest,
    AuditEntry,
    NewAccount,
    RoleConflictError,
    UserConflictError,
)
from api.auth.identity import AuthUnavailableError

pytestmark = pytest.mark.unit


def _directory() -> InMemoryUserDirectory:
    directory = InMemoryUserDirectory()
    directory.sync_login(VerifiedIdentity("admin-1", "admin@example.com", "Admin", Role.ADMIN))
    directory.sync_login(VerifiedIdentity("reader-1", "Lector@example.com", "Lector", Role.READER))
    directory.audit.clear()
    return directory


def _unexpected(uid: str) -> None:
    raise AssertionError(f"discard({uid}) must not run")


def _request(email: str = "Nueva@example.com", role: Role = Role.ANALYST, uid: str = "new-1") -> AccountRequest:
    return AccountRequest(uid=uid, email=email, role=role)


def test_create_stores_the_copy_and_audits_it() -> None:
    directory = _directory()
    record = directory.create_account(
        _request(), "admin-1", lambda: NewAccount("new-1", "nueva@example.com"), _unexpected
    )
    assert (record.firebase_uid, record.email, record.role, record.active, record.last_login_at) == (
        "new-1",
        "nueva@example.com",
        Role.ANALYST,
        True,
        None,
    )
    assert directory.get("new-1") == record
    assert directory.audit == [
        AuditEntry("admin-1", "user.create_requested", "new-1", None, {"role": "analyst"}),
        AuditEntry("admin-1", "user.create", "new-1", None, {"role": "analyst", "active": True}),
    ]


def test_create_refuses_an_email_a_copy_owns_before_firebase() -> None:
    directory = _directory()
    with pytest.raises(UserConflictError):
        directory.create_account(_request("lector@EXAMPLE.com", Role.READER), "admin-1", _no_firebase, _unexpected)
    assert [entry.action for entry in directory.audit] == ["user.create_requested", "user.create_failed"]
    assert directory.audit[-1].after == {"role": "reader"}


def _no_firebase() -> NewAccount:
    raise AssertionError("Firebase must not be called")


@pytest.mark.parametrize("actor", ["reader-1", "ghost"])
def test_only_an_active_admin_creates_accounts(actor: str) -> None:
    directory = _directory()
    with pytest.raises(RoleConflictError) as raised:
        directory.create_account(_request("x@example.com"), actor, _no_firebase, _unexpected)
    assert raised.value.code == "actor_not_admin"


def test_an_inactive_admin_creates_nothing() -> None:
    directory = _directory()
    directory.deactivate("admin-1")
    with pytest.raises(RoleConflictError):
        directory.create_account(_request("x@example.com"), "admin-1", _no_firebase, _unexpected)


def test_a_firebase_refusal_discards_nothing() -> None:
    directory = _directory()

    def refused() -> NewAccount:
        raise AccountNotCreatedError

    with pytest.raises(AccountNotCreatedError):
        directory.create_account(_request(), "admin-1", refused, _unexpected)
    assert directory.audit[-1] == AuditEntry("admin-1", "user.create_failed", "new-1", None, {"role": "analyst"})


@pytest.mark.parametrize("deleted", [True, False])
def test_a_half_made_account_is_discarded_and_audited_by_uid(deleted: bool) -> None:
    directory = _directory()
    discarded: list[str] = []

    def half_made() -> NewAccount:
        raise AuthUnavailableError

    def discard(uid: str) -> None:
        if not deleted:
            raise AuthUnavailableError
        discarded.append(uid)

    with pytest.raises(AuthUnavailableError):
        directory.create_account(_request(), "admin-1", half_made, discard)
    assert discarded == (["new-1"] if deleted else [])
    assert directory.audit[-1] == AuditEntry(
        "admin-1", "user.create_failed", "new-1", None, {"role": "analyst", "discarded": deleted}
    )
    assert directory.get("new-1") is None


def test_disable_and_enable_change_the_copy_and_are_audited() -> None:
    directory = _directory()
    off = directory.change_status("reader-1", True, "admin-1", lambda: True)
    assert off is not None and off.active is False
    on = directory.change_status("reader-1", False, "admin-1", lambda: True)
    assert on is not None and on.active is True
    assert directory.audit == [
        AuditEntry("admin-1", "user.disable_requested", "reader-1", None, {"active": False}),
        AuditEntry(
            "admin-1", "user.disable", "reader-1", {"active": True}, {"active": False, "sessions_revoked": True}
        ),
        AuditEntry("admin-1", "user.enable_requested", "reader-1", None, {"active": True}),
        AuditEntry("admin-1", "user.enable", "reader-1", {"active": False}, {"active": True, "sessions_revoked": True}),
    ]


def test_status_of_a_user_who_never_logged_in_changes_only_firebase() -> None:
    directory = _directory()
    assert directory.change_status("never", True, "admin-1", lambda: True) is None
    assert directory.audit[-1] == AuditEntry(
        "admin-1", "user.disable", "never", None, {"active": False, "sessions_revoked": True}
    )


def test_the_last_active_admin_is_never_switched_off() -> None:
    directory = _directory()
    with pytest.raises(RoleConflictError) as raised:
        directory.change_status("admin-1", True, "admin-1", _no_status_change)
    assert raised.value.code == "last_admin"
    # An admin created from the app has no password until it follows its e-mail: it is no backup yet.
    directory.create_account(
        _request("nuevo@example.com", Role.ADMIN, "n1"),
        "admin-1",
        lambda: NewAccount("n1", "nuevo@example.com"),
        _unexpected,
    )
    with pytest.raises(RoleConflictError, match="last_admin"):
        directory.change_status("admin-1", True, "admin-1", _no_status_change)
    # With another active admin it is allowed (the route still refuses an admin's own account).
    directory.sync_login(VerifiedIdentity("admin-2", "admin2@example.com", None, Role.ADMIN))
    record = directory.change_status("admin-1", True, "admin-1", lambda: True)
    assert record is not None and record.active is False
    # Switching an account on never needs another admin.
    assert directory.change_status("reader-1", False, "admin-2", lambda: True) is not None


def _no_status_change() -> bool:
    raise AssertionError("Firebase must not be called")


def test_a_failed_status_change_is_audited_and_keeps_the_copy() -> None:
    directory = _directory()

    def down() -> bool:
        raise RuntimeError("firebase down")

    with pytest.raises(RuntimeError):
        directory.change_status("reader-1", True, "admin-1", down)
    with pytest.raises(RoleConflictError):
        directory.change_status("admin-1", True, "reader-1", lambda: True)
    record = directory.get("reader-1")
    assert record is not None and record.active is True
    assert [(entry.actor_uid, entry.action, entry.entity_id) for entry in directory.audit] == [
        ("admin-1", "user.disable_requested", "reader-1"),
        ("admin-1", "user.disable_failed", "reader-1"),
        ("reader-1", "user.disable_requested", "admin-1"),
        ("reader-1", "user.disable_failed", "admin-1"),
    ]


def test_the_password_email_outcome_is_audited_without_the_address() -> None:
    directory = _directory()
    directory.audit_password_email("new-1", "admin-1", None)
    directory.audit_password_email("new-1", "admin-1", "EMAIL_NOT_FOUND")
    assert directory.audit == [
        AuditEntry("admin-1", "user.password_email_sent", "new-1", None, None),
        AuditEntry("admin-1", "user.password_email_failed", "new-1", None, {"reason": "EMAIL_NOT_FOUND"}),
    ]
