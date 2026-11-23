"""SqlUserDirectory on the migrated schema: first login creates and audits, later logins refresh, `active` and
role changes behave as the API expects (D-030, docs/13)."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from dbprovision import provisioned_database
from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from api.auth import Role, VerifiedIdentity
from api.auth.directory import RoleConflictError, SqlUserDirectory, UserConflictError
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
