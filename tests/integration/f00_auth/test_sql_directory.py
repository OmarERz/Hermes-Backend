"""SqlUserDirectory on the migrated schema: first login creates and audits, later logins refresh, `active` and
role changes behave as the API expects (D-030, docs/13)."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from dbprovision import provisioned_database
from sqlalchemy import create_engine, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from api.auth import Role, VerifiedIdentity
from api.auth.directory import (
    AccountDisabledError,
    AccountNotCreatedError,
    AccountRequest,
    NewAccount,
    RoleConflictError,
    SqlUserDirectory,
    UserConflictError,
)
from api.auth.identity import AuthUnavailableError
from core.db.models import AppUser, AuditLog
from core.db.session import make_engine

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def sessions(postgres_url: str) -> Iterator[sessionmaker[Session]]:
    with provisioned_database(postgres_url, "authdir") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        engine = make_engine(db.superuser_url)
        try:
            yield sessionmaker(engine, expire_on_commit=False)
        finally:
            engine.dispose()


def identity(uid: str, role: Role, email: str | None = None, name: str | None = "Ana") -> VerifiedIdentity:
    return VerifiedIdentity(uid=uid, email=email or f"{uid}@example.com", display_name=name, role=role)


def test_first_login_creates_and_audits_once(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    first = directory.sync_login(identity("u1", Role.ANALYST))
    again = directory.sync_login(identity("u1", Role.ADMIN, email="new@example.com", name=None))

    assert first.id == again.id
    assert first.active and again.active
    # The role is copied only on the first login; later changes go through change_role (D-030).
    assert (again.role, again.email, again.display_name) == (Role.ANALYST, "new@example.com", None)
    assert again.last_login_at is not None and first.last_login_at is not None
    assert again.last_login_at >= first.last_login_at
    with sessions() as session:
        audit = session.scalars(select(AuditLog)).all()
    assert [(a.action, a.entity_type, a.entity_id, a.app_user_id) for a in audit] == [
        ("user_created", "app_user", "u1", None)
    ]
    assert audit[0].after == {"role": "analyst", "active": True}


def test_login_keeps_a_deactivation_made_in_the_database(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("u2", Role.READER))
    with sessions.begin() as session:
        session.execute(update(AppUser).where(AppUser.firebase_uid == "u2").values(active=False))
    assert directory.sync_login(identity("u2", Role.READER)).active is False


def test_role_change_is_copied_and_audited_with_the_actor(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    admin = directory.sync_login(identity("admin", Role.ADMIN))
    directory.sync_login(identity("u3", Role.ANALYST))
    applied: list[str] = []

    record = directory.change_role("u3", Role.READER, "admin", lambda: applied.append("u3") is None)
    unknown = directory.change_role("ghost", Role.ANALYST, "admin", lambda: applied.append("ghost") is None)

    assert applied == ["u3", "ghost"]
    assert record is not None and record.role is Role.READER
    assert unknown is None
    with sessions() as session:
        rows = session.scalars(
            select(AuditLog).where(AuditLog.action.like("role_%")).order_by(AuditLog.created_at, AuditLog.id)
        ).all()
    assert [(r.action, r.entity_id, r.app_user_id, r.before, r.after) for r in rows] == [
        ("role_assignment_requested", "u3", admin.id, None, {"role": "reader"}),
        ("role_assigned", "u3", admin.id, {"role": "analyst"}, {"role": "reader", "sessions_revoked": True}),
        ("role_assignment_requested", "ghost", admin.id, None, {"role": "analyst"}),
        ("role_assigned", "ghost", admin.id, None, {"role": "analyst", "sessions_revoked": True}),
    ]


def test_failed_assignment_is_audited_and_keeps_the_copy(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("admin", Role.ADMIN))
    directory.sync_login(identity("u4", Role.ANALYST))

    def firebase_down() -> bool:
        raise RuntimeError("down")

    with pytest.raises(RuntimeError):
        directory.change_role("u4", Role.READER, "admin", firebase_down)

    with sessions() as session:
        role = session.scalar(select(AppUser.role).where(AppUser.firebase_uid == "u4"))
        actions = session.scalars(
            select(AuditLog.action).where(AuditLog.entity_id == "u4").order_by(AuditLog.created_at, AuditLog.id)
        ).all()
    assert role == "analyst"
    assert actions == ["user_created", "role_assignment_requested", "role_assignment_failed"]


def test_recreated_account_with_the_same_email_is_a_conflict(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("old-uid", Role.READER, email="same@example.com"))
    with pytest.raises(UserConflictError):
        directory.sync_login(identity("new-uid", Role.READER, email="same@example.com"))
    with sessions() as session:
        owner = session.scalar(select(AppUser.firebase_uid).where(AppUser.email == "same@example.com"))
    assert owner == "old-uid"


def test_reciprocal_demotions_never_leave_the_system_without_an_admin(sessions: sessionmaker[Session]) -> None:
    """Two admins demoting each other at the same time: the second change waits for the first and is then refused
    (its actor is no longer an admin), without a deadlock (pending F0 #19). The first change holds its protected
    section until the second one has started, so without the global lock both would read two admins and commit."""
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("a1", Role.ADMIN))
    directory.sync_login(identity("a2", Role.ADMIN))
    in_section, release = threading.Event(), threading.Event()
    applied: list[str] = []

    def first() -> bool:
        applied.append("a2")
        in_section.set()
        return release.wait(10)

    def demote(target: str, actor: str, apply: Callable[[], bool]) -> str:
        try:
            directory.change_role(target, Role.ANALYST, actor, apply)
        except RoleConflictError as exc:
            return exc.code
        return "changed"

    with ThreadPoolExecutor(max_workers=2) as pool:
        one = pool.submit(demote, "a2", "a1", first)
        assert in_section.wait(10)
        two = pool.submit(demote, "a1", "a2", lambda: applied.append("a1") is None)
        time.sleep(0.5)  # the second change reaches the global lock while the first is still inside
        release.set()
        outcomes = (one.result(timeout=30), two.result(timeout=30))
    assert outcomes == ("changed", "actor_not_admin")
    assert applied == ["a2"]  # Firebase is never touched for the refused change
    with sessions() as session:
        roles = dict(session.execute(select(AppUser.firebase_uid, AppUser.role)).tuples().all())
    assert roles == {"a1": "admin", "a2": "analyst"}


def test_a_stale_expected_role_is_refused_before_firebase(sessions: sessionmaker[Session]) -> None:
    """API-03: the admin read `reader`, someone made the user an analyst meanwhile (pending F0 #20)."""
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("boss", Role.ADMIN))
    directory.sync_login(identity("u1", Role.ADMIN))
    directory.change_role("u1", Role.ANALYST, "boss", lambda: True)
    touched: list[str] = []
    with pytest.raises(RoleConflictError, match="role_changed"):
        directory.change_role("u1", Role.ADMIN, "boss", lambda: touched.append("u1") is None, Role.READER)
    assert touched == []
    record = directory.change_role("u1", Role.ADMIN, "boss", lambda: True, Role.ANALYST)
    assert record is not None and record.role is Role.ADMIN
    with pytest.raises(RoleConflictError, match="role_changed"):  # no stored copy: the expectation cannot be checked
        directory.change_role("never-logged", Role.ANALYST, "boss", lambda: touched.append("x") is None, Role.READER)
    assert touched == []


def test_the_only_active_admin_is_never_demoted(sessions: sessionmaker[Session]) -> None:
    """An inactive admin does not count: demoting the only active one is refused before Firebase (pending F0 #19)."""
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("a1", Role.ADMIN))
    directory.sync_login(identity("a2", Role.ADMIN))
    with sessions.begin() as session:
        session.execute(update(AppUser).where(AppUser.firebase_uid == "a2").values(active=False))
    touched: list[str] = []
    with pytest.raises(RoleConflictError, match="last_admin"):
        directory.change_role("a1", Role.READER, "a1", lambda: touched.append("a1") is None)
    assert touched == []
    with sessions() as session:
        assert session.scalar(select(AppUser.role).where(AppUser.firebase_uid == "a1")) == "admin"


def test_a_first_login_during_the_assignment_gets_the_new_role(sessions: sessionmaker[Session]) -> None:
    """The row created by a first login while Firebase is written is updated too (D-030)."""
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("boss", Role.ADMIN))

    def firebase_then_first_login() -> bool:
        with ThreadPoolExecutor(max_workers=1) as pool:  # another connection, as a real login would be
            pool.submit(directory.sync_login, identity("newbie", Role.READER)).result(timeout=10)
        return True

    record = directory.change_role("newbie", Role.ANALYST, "boss", firebase_then_first_login)
    assert record is not None and record.role is Role.ANALYST


# --- bootstrap_role: the command-line first admin (api.auth.bootstrap, D-087) ---------------------------------------


def audit_rows(sessions: sessionmaker[Session], uid: str) -> list[tuple[str, object, object, object]]:
    with sessions() as session:
        rows = session.scalars(select(AuditLog).where(AuditLog.entity_id == uid).order_by(AuditLog.id)).all()
    return [(a.action, a.app_user_id, a.before, a.after) for a in rows]


def test_bootstrap_creates_the_copy_of_a_user_who_never_logged_in(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    applied: list[str] = []

    result = directory.bootstrap_role(identity("b1", Role.ADMIN), lambda: applied.append("b1") is None, False)

    assert applied == ["b1"]
    assert (result.changed, result.created, result.sessions_revoked) == (True, True, True)
    assert (result.record.role, result.record.active, result.record.last_login_at) == (Role.ADMIN, True, None)
    assert audit_rows(sessions, "b1") == [
        ("role_assignment_requested", None, None, {"role": "admin", "via": "cli"}),
        ("user_created", None, None, {"role": "admin", "active": True}),
        ("role_assigned", None, None, {"role": "admin", "via": "cli", "sessions_revoked": True}),
    ]


def test_bootstrap_is_idempotent(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    directory.bootstrap_role(identity("b2", Role.ADMIN), lambda: True, False)
    before = audit_rows(sessions, "b2")

    again = directory.bootstrap_role(identity("b2", Role.ADMIN), lambda: pytest.fail("Firebase written again"), True)

    assert (again.changed, again.created, again.record.role) == (False, False, Role.ADMIN)
    assert audit_rows(sessions, "b2") == before


def test_bootstrap_updates_an_existing_copy_and_skips_a_claim_already_set(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("b3", Role.READER))

    # The claim already holds the role: apply (which reads it again under the locks) writes nothing and revokes nothing.
    result = directory.bootstrap_role(identity("b3", Role.ANALYST), lambda: False, True)

    assert (result.changed, result.created, result.sessions_revoked, result.record.role) == (
        True,
        False,
        False,
        Role.ANALYST,
    )
    assert audit_rows(sessions, "b3")[-1] == (
        "role_assigned",
        None,
        {"role": "reader"},
        {"role": "analyst", "via": "cli", "sessions_revoked": False},
    )


def test_bootstrap_keeps_an_inactive_user_inactive(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("b4", Role.READER))
    with sessions.begin() as session:
        session.execute(update(AppUser).where(AppUser.firebase_uid == "b4").values(active=False))

    result = directory.bootstrap_role(identity("b4", Role.ADMIN), lambda: True, False)

    assert (result.record.role, result.record.active) == (Role.ADMIN, False)


def test_bootstrap_never_demotes_the_last_active_admin(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    directory.bootstrap_role(identity("b5", Role.ADMIN), lambda: True, False)

    with pytest.raises(RoleConflictError) as refused:
        directory.bootstrap_role(identity("b5", Role.READER), lambda: pytest.fail("Firebase touched"), False)

    assert refused.value.code == "last_admin"
    assert audit_rows(sessions, "b5")[-1][0] == "role_assignment_failed"
    with sessions() as session:
        assert session.scalar(select(AppUser.role).where(AppUser.firebase_uid == "b5")) == "admin"
    # Another admin counts once it has signed in (F18.8): until then it may not even be able to.
    directory.bootstrap_role(identity("b6", Role.ADMIN), lambda: True, False)
    with pytest.raises(RoleConflictError, match="last_admin"):
        directory.bootstrap_role(identity("b5", Role.READER), lambda: pytest.fail("Firebase touched"), False)
    directory.sync_login(identity("b6", Role.ADMIN))
    assert directory.bootstrap_role(identity("b5", Role.READER), lambda: True, False).record.role is Role.READER


def test_bootstrap_refuses_an_email_owned_by_another_account(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("old", Role.READER, email="same@example.com"))

    with pytest.raises(UserConflictError):
        directory.bootstrap_role(
            identity("new", Role.ADMIN, email="same@example.com"), lambda: pytest.fail("Firebase touched"), False
        )

    assert [row[0] for row in audit_rows(sessions, "new")] == ["role_assignment_requested", "role_assignment_failed"]
    with sessions() as session:
        assert session.scalar(select(AppUser).where(AppUser.firebase_uid == "new")) is None


def test_a_failed_firebase_write_is_audited_and_creates_no_copy(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)

    def fail() -> bool:
        raise RuntimeError("firebase down")

    with pytest.raises(RuntimeError):
        directory.bootstrap_role(identity("b7", Role.ADMIN), fail, False)

    assert [row[0] for row in audit_rows(sessions, "b7")] == ["role_assignment_requested", "role_assignment_failed"]
    with sessions() as session:
        assert session.scalar(select(AppUser).where(AppUser.firebase_uid == "b7")) is None


def test_bootstrap_keeps_a_copy_a_first_login_created_meanwhile(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)

    def first_login_while_firebase_answers() -> bool:
        directory.sync_login(identity("b8", Role.READER))
        return True

    result = directory.bootstrap_role(identity("b8", Role.ADMIN), first_login_while_firebase_answers, False)

    assert (result.created, result.record.role, result.record.last_login_at is not None) == (False, Role.ADMIN, True)
    rows = audit_rows(sessions, "b8")
    assert [row[0] for row in rows] == ["role_assignment_requested", "user_created", "role_assigned"]  # by the login
    assert rows[-1][2] == {"role": "reader"}  # the role the login copied, overwritten by the bootstrap


def test_an_email_taken_while_firebase_answers_is_a_conflict(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)

    def another_account_takes_the_email() -> bool:
        directory.sync_login(identity("other", Role.READER, email="race@example.com"))
        return True

    with pytest.raises(UserConflictError):
        directory.bootstrap_role(
            identity("b9", Role.ADMIN, email="race@example.com"), another_account_takes_the_email, False
        )

    assert [row[0] for row in audit_rows(sessions, "b9")] == ["role_assignment_requested", "role_assignment_failed"]
    with sessions() as session:
        assert session.scalar(select(AppUser).where(AppUser.firebase_uid == "b9")) is None


# --- accounts an admin creates and switches off or on (D-105, F18.8) ---------------------------------------------


def _no_firebase() -> NewAccount:
    raise AssertionError("Firebase must not be called")


def _keep(uid: str) -> None:
    raise AssertionError(f"discard({uid}) must not run")


def _request(uid: str, email: str, role: Role = Role.READER) -> AccountRequest:
    return AccountRequest(uid=uid, email=email, role=role)


def test_create_account_stores_the_copy_and_audits_it_with_the_actor(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    admin = directory.sync_login(identity("boss", Role.ADMIN))

    record = directory.create_account(
        _request("n1", "Nueva@Example.com", Role.ANALYST), "boss", lambda: NewAccount("n1", "nueva@example.com"), _keep
    )

    assert (record.firebase_uid, record.email, record.role, record.active, record.last_login_at) == (
        "n1",
        "nueva@example.com",
        Role.ANALYST,
        True,
        None,
    )
    assert audit_rows(sessions, "n1") == [
        ("user.create_requested", admin.id, None, {"role": "analyst"}),
        ("user.create", admin.id, None, {"role": "analyst", "active": True}),
    ]
    # Its first login later finds the copy and keeps the role the admin chose.
    login = directory.sync_login(identity("n1", Role.READER, email="nueva@example.com"))
    assert (login.id, login.role, login.last_login_at is not None) == (record.id, Role.ANALYST, True)


def test_create_account_refuses_a_stored_email_before_firebase(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    admin = directory.sync_login(identity("boss", Role.ADMIN))
    directory.sync_login(identity("old", Role.READER, email="taken@example.com"))
    with pytest.raises(UserConflictError):
        directory.create_account(_request("n0", "TAKEN@example.com"), "boss", _no_firebase, _keep)
    assert audit_rows(sessions, "n0") == [
        ("user.create_requested", admin.id, None, {"role": "reader"}),
        ("user.create_failed", admin.id, None, {"role": "reader"}),
    ]


@pytest.mark.parametrize("actor", ["reader", "ghost", "former-admin"])
def test_only_an_active_admin_creates_accounts(sessions: sessionmaker[Session], actor: str) -> None:
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("reader", Role.READER))
    directory.sync_login(identity("former-admin", Role.ADMIN))
    with sessions.begin() as session:
        session.execute(update(AppUser).where(AppUser.firebase_uid == "former-admin").values(active=False))
    with pytest.raises(RoleConflictError, match="actor_not_admin"):
        directory.create_account(_request("n0", "x@example.com"), actor, _no_firebase, _keep)


def test_a_firebase_refusal_creates_and_discards_nothing(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("boss", Role.ADMIN))

    def taken() -> NewAccount:
        raise AccountNotCreatedError

    with pytest.raises(AccountNotCreatedError):
        directory.create_account(_request("n5", "x@example.com"), "boss", taken, _keep)
    assert [(row[0], row[3]) for row in audit_rows(sessions, "n5")] == [
        ("user.create_requested", {"role": "reader"}),
        ("user.create_failed", {"role": "reader"}),
    ]
    with sessions() as session:
        assert session.scalar(select(AppUser).where(AppUser.email == "x@example.com")) is None


def test_a_half_made_account_is_discarded_by_the_uid_of_the_request(sessions: sessionmaker[Session]) -> None:
    """Firebase failed after it may have created the account (the SDK reads it back; then the claim): the uid of the
    request finds it, and the trail keeps who asked, which uid and whether it was deleted."""
    directory = SqlUserDirectory(sessions)
    admin = directory.sync_login(identity("boss", Role.ADMIN))
    discarded: list[str] = []

    def half_made() -> NewAccount:
        raise AuthUnavailableError

    with pytest.raises(AuthUnavailableError):
        directory.create_account(_request("n6", "half@example.com"), "boss", half_made, discarded.append)
    assert discarded == ["n6"]
    assert audit_rows(sessions, "n6")[-1] == (
        "user.create_failed",
        admin.id,
        None,
        {"role": "reader", "discarded": True},
    )


@pytest.mark.parametrize("deleted", [True, False])
def test_a_copy_that_cannot_be_stored_deletes_the_new_account(sessions: sessionmaker[Session], deleted: bool) -> None:
    """Another account took the e-mail while Firebase answered: the new account is deleted again and the failure
    audited, so the admin can retry; a deletion that fails is audited as such."""
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("boss", Role.ADMIN))
    discarded: list[str] = []

    def create_while_another_login_takes_the_email() -> NewAccount:
        with ThreadPoolExecutor(max_workers=1) as pool:  # another connection, as a real login would be
            pool.submit(directory.sync_login, identity("other", Role.READER, email="race@example.com")).result()
        return NewAccount("n2", "race@example.com")

    def discard(uid: str) -> None:
        if not deleted:
            raise AuthUnavailableError
        discarded.append(uid)

    with pytest.raises(UserConflictError):
        directory.create_account(
            _request("n2", "race@example.com", Role.ANALYST),
            "boss",
            create_while_another_login_takes_the_email,
            discard,
        )
    assert discarded == (["n2"] if deleted else [])
    assert [(row[0], row[3]) for row in audit_rows(sessions, "n2")] == [
        ("user.create_requested", {"role": "analyst"}),
        ("user.create_failed", {"role": "analyst", "discarded": deleted}),
    ]
    with sessions() as session:
        assert session.scalar(select(AppUser).where(AppUser.firebase_uid == "n2")) is None


def test_disable_and_enable_set_active_on_the_copy_and_are_audited(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    admin = directory.sync_login(identity("boss", Role.ADMIN))
    directory.sync_login(identity("u9", Role.ANALYST))

    off = directory.change_status("u9", True, "boss", lambda: True)
    on = directory.change_status("u9", False, "boss", lambda: False)
    never = directory.change_status("never", True, "boss", lambda: True)

    assert off is not None and off.active is False
    assert on is not None and on.active is True
    assert never is None
    assert audit_rows(sessions, "u9")[1:] == [
        ("user.disable_requested", admin.id, None, {"active": False}),
        ("user.disable", admin.id, {"active": True}, {"active": False, "sessions_revoked": True}),
        ("user.enable_requested", admin.id, None, {"active": True}),
        ("user.enable", admin.id, {"active": False}, {"active": True, "sessions_revoked": False}),
    ]
    assert audit_rows(sessions, "never") == [
        ("user.disable_requested", admin.id, None, {"active": False}),
        ("user.disable", admin.id, None, {"active": False, "sessions_revoked": True}),
    ]
    # A later login keeps what the admin set (active belongs to the database).
    assert directory.sync_login(identity("u9", Role.ANALYST)).active is True


def test_a_failed_status_change_is_audited_and_fails_closed(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("boss", Role.ADMIN))
    directory.sync_login(identity("u10", Role.READER))

    def firebase_down() -> bool:
        raise RuntimeError("down")

    with pytest.raises(RuntimeError):
        directory.change_status("u10", True, "boss", firebase_down)
    with pytest.raises(RoleConflictError, match="actor_not_admin"):
        directory.change_status("boss", True, "u10", lambda: True)

    assert [row[0] for row in audit_rows(sessions, "u10")] == [
        "user_created",
        "user.disable_requested",
        "user.disable_failed",
    ]
    assert [row[0] for row in audit_rows(sessions, "boss")] == [
        "user_created",
        "user.disable_requested",
        "user.disable_failed",
    ]
    with sessions() as session:  # Firebase may have switched it off before failing: the copy stays off
        assert session.scalar(select(AppUser.active).where(AppUser.firebase_uid == "u10")) is False
        # A refusal before Firebase changes nothing.
        assert session.scalar(select(AppUser.active).where(AppUser.firebase_uid == "boss")) is True


def test_the_last_active_admin_is_never_switched_off(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("a1", Role.ADMIN))
    directory.sync_login(identity("a2", Role.ADMIN))
    with sessions.begin() as session:
        session.execute(update(AppUser).where(AppUser.firebase_uid == "a2").values(active=False))
    touched: list[str] = []
    with pytest.raises(RoleConflictError, match="last_admin"):
        directory.change_status("a1", True, "a1", lambda: touched.append("a1") is None)
    # An admin created from the app has no password until it follows its e-mail: it is no backup yet.
    directory.create_account(
        _request("a3", "invited@example.com", Role.ADMIN), "a1", lambda: NewAccount("a3", "invited@example.com"), _keep
    )
    with pytest.raises(RoleConflictError, match="last_admin"):
        directory.change_status("a1", True, "a1", lambda: touched.append("a1") is None)
    assert touched == []
    # Switching the other admin back on needs no second admin.
    record = directory.change_status("a2", False, "a1", lambda: True)
    assert record is not None and record.active is True
    assert [row[0] for row in audit_rows(sessions, "a1")][-2:] == ["user.disable_requested", "user.disable_failed"]


def test_the_copy_is_off_before_firebase_and_stays_off_if_firebase_fails(sessions: sessionmaker[Session]) -> None:
    """A switch-off commits the copy first: a concurrent request (another connection) already sees it inactive while
    Firebase answers. If Firebase fails it may still have switched the account off, so the copy stays off (fails
    closed) until an admin switches the account on again."""
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("boss", Role.ADMIN))
    directory.sync_login(identity("u11", Role.ANALYST))
    seen: list[bool | None] = []

    def active_now() -> bool | None:
        with sessions() as session:
            return session.scalar(select(AppUser.active).where(AppUser.firebase_uid == "u11"))

    def firebase_fails() -> bool:
        with ThreadPoolExecutor(max_workers=1) as pool:
            seen.append(pool.submit(active_now).result())
        raise RuntimeError("down")

    with pytest.raises(RuntimeError):
        directory.change_status("u11", True, "boss", firebase_fails)
    assert seen == [False]
    assert active_now() is False
    record = directory.change_status("u11", False, "boss", lambda: True)
    assert record is not None and record.active is True


def test_a_copy_a_first_sign_in_creates_meanwhile_goes_off_too(sessions: sessionmaker[Session]) -> None:
    """An account with no copy yet signs in for the first time while Firebase switches it off: its new copy ends off."""
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("boss", Role.ADMIN))

    def first_sign_in_while_firebase_answers() -> bool:
        with ThreadPoolExecutor(max_workers=1) as pool:  # another connection, as a real request would be
            pool.submit(directory.sync_login, identity("a9", Role.ADMIN)).result()
        return True

    record = directory.change_status("a9", True, "boss", first_sign_in_while_firebase_answers)
    assert record is not None and record.active is False
    with sessions() as session:
        assert session.scalar(select(AppUser.active).where(AppUser.firebase_uid == "a9")) is False


def test_a_copy_a_first_sign_in_creates_while_firebase_fails_stays_off(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("boss", Role.ADMIN))

    def first_sign_in_then_firebase_fails() -> bool:
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(directory.sync_login, identity("a10", Role.ADMIN)).result()
        raise RuntimeError("down")

    with pytest.raises(RuntimeError):
        directory.change_status("a10", True, "boss", first_sign_in_then_firebase_fails)
    with sessions() as session:
        assert session.scalar(select(AppUser.active).where(AppUser.firebase_uid == "a10")) is False


class LostCommitAnswer:
    """A session factory whose next ``begin()`` commits and then fails, as when the connection drops before the
    answer to COMMIT arrives."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions
        self.armed = False

    def __call__(self) -> Session:
        return self._sessions()

    @contextmanager
    def begin(self) -> Iterator[Session]:
        with self._sessions.begin() as session:
            yield session
        if self.armed:
            self.armed = False
            raise OperationalError("COMMIT", {}, ConnectionError("connection lost"))


def test_a_creation_whose_commit_answer_was_lost_keeps_the_account(sessions: sessionmaker[Session]) -> None:
    flaky = LostCommitAnswer(sessions)
    directory = SqlUserDirectory(flaky)  # type: ignore[arg-type]
    directory.sync_login(identity("boss", Role.ADMIN))

    def create() -> NewAccount:
        flaky.armed = True  # the transaction of the copy is the one in progress
        return NewAccount("n9", "lost@example.com")

    record = directory.create_account(_request("n9", "lost@example.com"), "boss", create, _keep)
    assert (record.firebase_uid, record.email) == ("n9", "lost@example.com")
    assert [row[0] for row in audit_rows(sessions, "n9")] == ["user.create_requested", "user.create"]


def test_a_status_change_never_needs_a_second_connection_while_it_holds_the_lock(
    sessions: sessionmaker[Session],
) -> None:
    """With a pool of two connections, one change holds the account's lock while Firebase answers and another waits
    for it on the second connection: the first still finishes (it never asks the pool for another connection)."""
    url = sessions.kw["bind"].url.render_as_string(hide_password=False)
    engine = create_engine(url, pool_size=2, max_overflow=0, pool_timeout=5)
    try:
        small = sessionmaker(engine, expire_on_commit=False)
        directory = SqlUserDirectory(small)
        directory.sync_login(identity("boss", Role.ADMIN))
        directory.sync_login(identity("u13", Role.READER))
        in_firebase, release = threading.Event(), threading.Event()

        def first() -> bool:
            in_firebase.set()
            return release.wait(10)

        with ThreadPoolExecutor(max_workers=2) as pool:
            one = pool.submit(directory.change_status, "u13", True, "boss", first)
            assert in_firebase.wait(10)
            two = pool.submit(directory.change_status, "u13", False, "boss", lambda: True)
            time.sleep(0.5)  # the second change holds the other connection, waiting for the lock
            release.set()
            assert one.result(timeout=30) is not None
            assert two.result(timeout=30) is not None
        with small() as session:
            assert session.scalar(select(AppUser.active).where(AppUser.firebase_uid == "u13")) is True
    finally:
        engine.dispose()


def test_reciprocal_disables_never_leave_the_system_without_an_admin(sessions: sessionmaker[Session]) -> None:
    """Two admins switching each other off at the same time: the second waits for the first and is refused."""
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("a1", Role.ADMIN))
    directory.sync_login(identity("a2", Role.ADMIN))
    in_section, release = threading.Event(), threading.Event()
    applied: list[str] = []

    def first() -> bool:
        applied.append("a2")
        in_section.set()
        return release.wait(10)

    def disable(target: str, actor: str, apply: Callable[[], bool]) -> str:
        try:
            directory.change_status(target, True, actor, apply)
        except RoleConflictError as exc:
            return exc.code
        return "changed"

    with ThreadPoolExecutor(max_workers=2) as pool:
        one = pool.submit(disable, "a2", "a1", first)
        assert in_section.wait(10)
        two = pool.submit(disable, "a1", "a2", lambda: applied.append("a1") is None)
        time.sleep(0.5)  # the second change reaches the global lock while the first is still inside
        release.set()
        outcomes = (one.result(timeout=30), two.result(timeout=30))
    assert outcomes == ("changed", "actor_not_admin")
    assert applied == ["a2"]
    with sessions() as session:
        active = dict(session.execute(select(AppUser.firebase_uid, AppUser.active)).tuples().all())
    assert active == {"a1": True, "a2": False}


@pytest.mark.parametrize("first_disables", [True, False])
def test_status_changes_of_one_account_never_interleave(sessions: sessionmaker[Session], first_disables: bool) -> None:
    """A switch-off and a switch-on of the same account, in both orders: the second one starts only after the first
    finished with Firebase and the copy, so Firebase and the copy end in the state of the last one."""
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("boss", Role.ADMIN))
    directory.sync_login(identity("u12", Role.READER))
    if not first_disables:
        directory.change_status("u12", True, "boss", lambda: True)
    in_firebase, release = threading.Event(), threading.Event()
    firebase: list[bool] = []

    def first() -> bool:
        firebase.append(first_disables)
        in_firebase.set()
        return release.wait(10)

    def second() -> bool:
        firebase.append(not first_disables)
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        one = pool.submit(directory.change_status, "u12", first_disables, "boss", first)
        assert in_firebase.wait(10)
        two = pool.submit(directory.change_status, "u12", not first_disables, "boss", second)
        time.sleep(0.5)  # the second change waits for the account's lock while the first is in Firebase
        assert firebase == [first_disables]
        release.set()
        one.result(timeout=30)
        two.result(timeout=30)
    assert firebase == [first_disables, not first_disables]
    with sessions() as session:
        active = session.scalar(select(AppUser.active).where(AppUser.firebase_uid == "u12"))
    assert active is first_disables  # the last change (the opposite of the first) won in both places


def test_the_password_email_needs_an_active_admin_and_an_account_on_in_hermes(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    directory.sync_login(identity("boss", Role.ADMIN))
    directory.sync_login(identity("u14", Role.READER))
    with pytest.raises(RoleConflictError, match="actor_not_admin"):
        directory.authorize_password_email("boss", "u14")
    with sessions.begin() as session:
        session.execute(update(AppUser).where(AppUser.firebase_uid == "u14").values(active=False))
    with pytest.raises(AccountDisabledError):
        directory.authorize_password_email("u14", "boss")
    assert [row[0] for row in audit_rows(sessions, "u14")] == ["user_created"]


def test_the_password_email_outcome_is_audited(sessions: sessionmaker[Session]) -> None:
    directory = SqlUserDirectory(sessions)
    admin = directory.sync_login(identity("boss", Role.ADMIN))
    directory.authorize_password_email("n3", "boss")
    directory.audit_password_email("n3", "boss", None)
    directory.audit_password_email("n3", "boss", "EMAIL_NOT_FOUND")
    assert audit_rows(sessions, "n3") == [
        ("user.password_email_requested", admin.id, None, None),
        ("user.password_email_sent", admin.id, None, None),
        ("user.password_email_failed", admin.id, None, {"reason": "EMAIL_NOT_FOUND"}),
    ]
