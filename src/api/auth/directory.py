"""User directory: the copy of Firebase users kept in ``app_user`` (docs/datos/modelo-v1).

The role stored here is a copy: the custom claim stays the master (D-030). ``active`` is owned by the database
(an admin can deactivate a user without touching Firebase). Creating a user and assigning a role leave an
``audit_log`` row (docs/13: every configuration change is audited).
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID, uuid4

from sqlalchemy import Boolean, func, literal_column, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.sql.dml import ReturningInsert

from api.auth.identity import VerifiedIdentity
from api.auth.roles import Role
from core.db.models import AppUser, AuditLog

ENTITY = "app_user"


@dataclass(frozen=True, slots=True)
class UserRecord:
    """Mirror of an ``app_user`` row."""

    id: UUID
    firebase_uid: str
    email: str
    display_name: str | None
    role: Role
    active: bool
    created_at: datetime
    last_login_at: datetime | None


class RoleConflictError(Exception):
    """A role change refused before touching Firebase: `actor_not_admin`, `role_changed` (the expected role is stale or
    cannot be checked) or `last_admin`."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _check_change(
    actor_is_admin: bool, current: str | None, role: Role, expected_role: Role | None, other_admins: int
) -> None:
    """The rules every directory applies under its locks (pending F0 #19, #20). `actor_not_admin`: the actor lost the
    role (or the account) while the request waited; an expected role cannot be checked without a stored copy."""
    if not actor_is_admin:
        raise RoleConflictError("actor_not_admin")
    if expected_role is not None and (current is None or current != expected_role.value):
        raise RoleConflictError("role_changed")
    if current == Role.ADMIN.value and role is not Role.ADMIN and other_admins == 0:
        raise RoleConflictError("last_admin")


class UserDirectory(Protocol):
    def sync_login(self, identity: VerifiedIdentity) -> UserRecord:
        """Create the user on first login or refresh e-mail, name, role copy and ``last_login_at``."""
        ...

    def change_role(
        self, uid: str, role: Role, actor_uid: str, apply: Callable[[], bool], expected_role: Role | None = None
    ) -> UserRecord | None:
        """Assign a role through ``apply`` (Firebase) with a durable audit trail, one change per user at a time.

        Before ``apply`` runs: ``expected_role`` (optional, API-03) must match the stored copy, and an admin is never
        demoted when no other active admin would remain; both raise ``RoleConflictError`` and change nothing.

        ``role_assignment_requested`` is committed before ``apply`` runs; then, holding a per-user lock,
        ``apply`` runs (it returns whether the user's sessions were revoked) and the copy plus ``role_assigned``
        commit together. If ``apply`` fails,
        ``role_assignment_failed`` is recorded and the error propagates. Repeating the request is safe.
        Returns the updated copy, or ``None`` if the user never logged in.
        """
        ...


class UserConflictError(RuntimeError):
    """Another account already owns this e-mail (for example, a Firebase account deleted and recreated)."""


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """In-memory mirror of an ``audit_log`` row (tests and local runs)."""

    actor_uid: str | None
    action: str
    entity_id: str
    before: dict[str, Any] | None
    after: dict[str, Any] | None


@dataclass
class InMemoryUserDirectory:
    _users: dict[str, UserRecord] = field(default_factory=dict)
    audit: list[AuditEntry] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _role_lock: threading.Lock = field(default_factory=threading.Lock)

    def sync_login(self, identity: VerifiedIdentity) -> UserRecord:
        now = datetime.now(UTC)
        with self._lock:
            current = self._users.get(identity.uid)
            if current is None:
                record = UserRecord(
                    id=uuid4(),
                    firebase_uid=identity.uid,
                    email=identity.email,
                    display_name=identity.display_name,
                    role=identity.role,
                    active=True,
                    created_at=now,
                    last_login_at=now,
                )
                self.audit.append(AuditEntry(None, "user_created", identity.uid, None, _snapshot(record)))
            else:
                record = replace(current, email=identity.email, display_name=identity.display_name, last_login_at=now)
            self._users[identity.uid] = record
            return record

    def change_role(
        self, uid: str, role: Role, actor_uid: str, apply: Callable[[], bool], expected_role: Role | None = None
    ) -> UserRecord | None:
        after = {"role": role.value}
        with self._lock:
            self.audit.append(AuditEntry(actor_uid, "role_assignment_requested", uid, None, after))
        with self._role_lock:
            try:
                with self._lock:
                    target, actor = self._users.get(uid), self._users.get(actor_uid)
                    others = sum(
                        1 for u in self._users.values() if u.firebase_uid != uid and u.active and u.role is Role.ADMIN
                    )
                actor_is_admin = actor is not None and actor.active and actor.role is Role.ADMIN
                _check_change(actor_is_admin, target.role.value if target else None, role, expected_role, others)
                revoked = apply()
            except Exception:
                with self._lock:
                    self.audit.append(AuditEntry(actor_uid, "role_assignment_failed", uid, None, after))
                raise
            with self._lock:
                current = self._users.get(uid)
                updated = replace(current, role=role) if current else None
                if updated:
                    self._users[uid] = updated
                before = {"role": current.role.value} if current else None
                done = {**after, "sessions_revoked": revoked}
                self.audit.append(AuditEntry(actor_uid, "role_assigned", uid, before, done))
                return updated

    def get(self, uid: str) -> UserRecord | None:
        """Read a user without touching it."""
        with self._lock:
            return self._users.get(uid)

    def deactivate(self, uid: str) -> None:
        """Test and admin helper: mark a user inactive."""
        with self._lock:
            self._users[uid] = replace(self._users[uid], active=False)


class SqlUserDirectory:
    """``UserDirectory`` on ``app_user`` and ``audit_log`` (connects as the app role)."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def sync_login(self, identity: VerifiedIdentity) -> UserRecord:
        now = datetime.now(UTC)
        values = {
            "firebase_uid": identity.uid,
            "email": identity.email,
            "display_name": identity.display_name,
            "last_login_at": now,
        }
        # One statement: insert on first login, refresh otherwise; xmax = 0 marks a freshly inserted row.
        # The role is copied only on insert: afterwards it changes only through change_role, so a request that
        # verified its token before a role change can never write the old role back (D-030).
        statement: ReturningInsert[AppUser, bool] = (
            insert(AppUser)
            .values(**values, role=identity.role.value, active=True, created_at=now)
            .on_conflict_do_update(index_elements=[AppUser.firebase_uid], set_=values)
            .returning(AppUser, literal_column("xmax = 0", Boolean).label("created"))
        )
        try:
            with self._sessions.begin() as session:
                row, created = session.execute(statement).one()
                record = _record(row)
                if created:
                    entry = AuditEntry(None, "user_created", identity.uid, None, _snapshot(record))
                    session.add(_audit(entry, None, now))
        except IntegrityError as exc:
            # The only other unique key is the e-mail: an older account owns it. Never take over that row by
            # e-mail (it would hand the old history and role to a new identity); an admin resolves it.
            raise UserConflictError(identity.uid) from exc
        return record

    def change_role(
        self, uid: str, role: Role, actor_uid: str, apply: Callable[[], bool], expected_role: Role | None = None
    ) -> UserRecord | None:
        after = {"role": role.value}
        with self._sessions.begin() as session:
            actor_id = self._actor(session, actor_uid)
            session.add(_audit(AuditEntry(actor_uid, "role_assignment_requested", uid, None, after), actor_id, _now()))
        try:
            with self._sessions.begin() as session:
                # One role change per user at a time, from before the Firebase write until the audit commits,
                # so Firebase, the copy and the audit trail see concurrent changes in the same order.
                # Role changes are serialized globally (always before the per-user lock, so no deadlock): two admins
                # demoting each other at once can never leave the system without an admin, and an actor demoted
                # meanwhile is seen as such (pending #19).
                session.execute(select(func.pg_advisory_xact_lock(func.hashtextextended("role:admins", 0))))
                session.execute(select(func.pg_advisory_xact_lock(func.hashtextextended(f"role:{uid}", 0))))
                # The checks read without a row lock: the advisory locks already serialize role changes, and a row
                # lock held while Firebase answers would make every request of the user wait in `sync_login`.
                current = session.scalar(select(AppUser.role).where(AppUser.firebase_uid == uid))
                others = session.scalar(
                    select(func.count())
                    .select_from(AppUser)
                    .where(AppUser.firebase_uid != uid, AppUser.active, AppUser.role == Role.ADMIN.value)
                )
                actor_is_admin = bool(
                    session.scalar(
                        select(func.count())
                        .select_from(AppUser)
                        .where(AppUser.firebase_uid == actor_uid, AppUser.active, AppUser.role == Role.ADMIN.value)
                    )
                )
                _check_change(actor_is_admin, current, role, expected_role, int(others or 0))
                revoked = apply()
                # FOR NO KEY UPDATE only for the local write (it also sees a row a first login created meanwhile):
                # compatible with the KEY SHARE lock the audit_log foreign key check takes, so two admins changing
                # each other's role do not deadlock.
                user = session.scalar(
                    select(AppUser).where(AppUser.firebase_uid == uid).with_for_update(key_share=True)
                )
                before = {"role": user.role} if user else None
                if user:
                    user.role = role.value
                done = {**after, "sessions_revoked": revoked}
                session.add(_audit(AuditEntry(actor_uid, "role_assigned", uid, before, done), actor_id, _now()))
                return _record(user) if user else None
        except Exception:
            with self._sessions.begin() as session:
                session.add(_audit(AuditEntry(actor_uid, "role_assignment_failed", uid, None, after), actor_id, _now()))
            raise

    @staticmethod
    def _actor(session: Session, actor_uid: str) -> UUID | None:
        return session.scalar(select(AppUser.id).where(AppUser.firebase_uid == actor_uid))


def _audit(entry: AuditEntry, actor_id: UUID | None, at: datetime) -> AuditLog:
    return AuditLog(
        app_user_id=actor_id,
        action=entry.action,
        entity_type=ENTITY,
        entity_id=entry.entity_id,
        before=entry.before,
        after=entry.after,
        created_at=at,
    )


def _now() -> datetime:
    return datetime.now(UTC)


def _record(row: AppUser) -> UserRecord:
    return UserRecord(
        id=row.id,
        firebase_uid=row.firebase_uid,
        email=row.email,
        display_name=row.display_name,
        role=Role(row.role),
        active=row.active,
        created_at=row.created_at,
        last_login_at=row.last_login_at,
    )


def _snapshot(record: UserRecord) -> dict[str, Any]:
    # The e-mail stays out of the audit trail (personal data); the uid in entity_id identifies the user.
    return {"role": record.role.value, "active": record.active}
