"""User directory: the copy of Firebase users kept in ``app_user`` (docs/datos/modelo-v1).

The role stored here is a copy: the custom claim stays the master (D-030). ``active`` is owned by the database
(an admin can deactivate a user without touching Firebase). Creating a user and assigning a role leave an
``audit_log`` row (docs/13: every configuration change is audited). An admin can also create an account from the app
and switch one off and on (``AccountDirectory``, D-105): Firebase first, then the copy and the audit row.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID, uuid4

from sqlalchemy import Boolean, func, literal_column, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.sql.dml import ReturningInsert

from api.auth.identity import AuthUnavailableError, VerifiedIdentity
from api.auth.roles import Role
from core.db.models import AppUser, AuditLog

logger = logging.getLogger(__name__)

ENTITY = "app_user"
# Audit actions of the accounts an admin manages from the app (D-105).
CREATE_REQUESTED = "user.create_requested"
CREATE = "user.create"
CREATE_FAILED = "user.create_failed"
SETUP_EMAIL_REQUESTED = "user.password_email_requested"
SETUP_EMAIL_SENT = "user.password_email_sent"
SETUP_EMAIL_FAILED = "user.password_email_failed"


def _create_failure(role: Role, discarded: bool | None) -> dict[str, Any]:
    """The ``after`` of ``user.create_failed``: ``discarded`` says whether an account Firebase may hold was deleted
    again (absent when Firebase was never asked or refused the account)."""
    return {"role": role.value} if discarded is None else {"role": role.value, "discarded": discarded}


def _discarded(discard: Callable[[str], None], uid: str) -> bool:
    """Delete the account ``uid`` if Firebase made it; whether that worked (a failure is logged by uid)."""
    try:
        discard(uid)
    except AuthUnavailableError:
        logger.warning("new account %s could not be deleted; an admin can remove it in Firebase", uid)
        return False
    return True


# The status rows that say how the last change of an account ended: a completed switch-on, or a switch-off asked for.
_STATUS_MARKS = ("user.enable", "user.disable_requested")


def _switched_on_last(session: Session, uid: str) -> bool:
    """Whether the last status change recorded for ``uid`` is a completed switch-on (for an account with no copy)."""
    last = session.scalar(
        select(AuditLog.action)
        .where(AuditLog.entity_type == ENTITY, AuditLog.entity_id == uid, AuditLog.action.in_(_STATUS_MARKS))
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(1)
    )
    return last == "user.enable"


def _status_action(disabled: bool) -> str:
    return "user.disable" if disabled else "user.enable"


def _password_email_entry(uid: str, actor_uid: str, failure: str | None) -> AuditEntry:
    if failure is None:
        return AuditEntry(actor_uid, SETUP_EMAIL_SENT, uid, None, None)
    return AuditEntry(actor_uid, SETUP_EMAIL_FAILED, uid, None, {"reason": failure})


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
class AccountRequest:
    """An account an admin asked for (D-105): the uid Hermes picked for it, the e-mail and the role."""

    uid: str
    email: str
    role: Role


class AccountDisabledError(Exception):
    """The account is switched off in Hermes (its copy is not active)."""


class AccountNotCreatedError(Exception):
    """Firebase refused to create the account (e-mail taken or refused, uid taken): nothing exists to clean up."""


@dataclass(frozen=True, slots=True)
class NewAccount:
    """A Firebase account just created by an admin (D-105): its uid and the e-mail as Firebase stored it."""

    uid: str
    email: str


class AccountDirectory(Protocol):
    """Accounts an admin creates and switches off or on from the app (D-105, F18.8)."""

    def create_account(
        self, request: AccountRequest, actor_uid: str, create: Callable[[], NewAccount], discard: Callable[[str], None]
    ) -> UserRecord:
        """Create the account ``request.uid`` through ``create`` (Firebase) and its copy, audited as ``user.create``.

        ``user.create_requested`` (with the uid) is committed before Firebase is touched. Then, under the same global
        lock as role changes, it is refused before Firebase when the actor is no longer an active admin
        (``RoleConflictError("actor_not_admin")``) or a stored copy already owns the e-mail (``UserConflictError``).
        If anything fails once ``create`` was called (except ``AccountNotCreatedError``: Firebase refused and nothing
        exists), ``discard`` deletes the account ``request.uid`` if Firebase made it; ``user.create_failed`` records
        whether that worked and the error propagates, so the admin can simply retry.
        """
        ...

    def change_status(
        self, uid: str, disabled: bool, actor_uid: str, apply: Callable[[bool], bool]
    ) -> UserRecord | None:
        """Switch a user off (``disabled``) or on through ``apply`` (Firebase; it returns whether the sessions were
        revoked), then set ``active`` on the copy, audited as ``user.disable`` or ``user.enable``. ``apply`` gets
        whether Hermes already has the account on: its stored copy is active or, for an account with no copy yet, its
        last status change recorded is a completed ``user.enable`` (a switch-on already applied, so Firebase keeps the
        sessions opened since). It is False for every switch-off, and after a partial switch-off (the old sessions are
        revoked again).

        As ``change_role``: ``user.disable_requested`` (or ``user.enable_requested``) is committed before Firebase is
        touched, so the trail shows a change even if it stops half way; then, serialized with role changes, the actor
        must still be an active admin (``RoleConflictError("actor_not_admin")``) and an active admin is never switched
        off while no other active admin has ever signed in (``RoleConflictError("last_admin")``), both before
        Firebase. Switching off writes the copy first and Firebase second (if Firebase fails, the copy stays off);
        switching on writes Firebase first; status changes of one account never interleave. Either way a half-done
        change fails closed (an account off in Firebase cannot sign in; a copy that is not active is refused with 403
        ``user_inactive``) and repeating the request completes it. A failure is recorded as ``user.disable_failed`` (or
        ``user.enable_failed``) and propagates. Returns the copy, or ``None`` if the user never logged in.
        """
        ...

    def authorize_password_email(self, uid: str, actor_uid: str) -> None:
        """Allow the password e-mail for ``uid`` and record ``user.password_email_requested``, before Identity Toolkit
        is called (an e-mail never leaves without a trace). Under the same global lock as role and status changes: the
        actor must still be an active admin (``RoleConflictError("actor_not_admin")``) and a copy switched off in
        Hermes gets no e-mail (``AccountDisabledError``)."""
        ...

    def audit_password_email(self, uid: str, actor_uid: str, failure: str | None) -> None:
        """Record that the password e-mail was sent (``failure`` None) or not (its short reason code)."""
        ...


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    """Outcome of ``SqlUserDirectory.bootstrap_role``: the copy, and what the call changed."""

    record: UserRecord
    changed: bool
    created: bool
    sessions_revoked: bool


# The command-line bootstrap (api.auth.bootstrap, D-087) has no signed-in actor: its audit rows name their source.
CLI = "cli"


def _lock_role_change(session: Session, uid: str) -> None:
    """Serialize role changes, from the API (change_role) and the command line (bootstrap_role) alike: globally first,
    then per user, always in this order, so two admins demoting each other cannot leave the system without an admin
    and a change never interleaves with another change of the same user (pending #19, #20)."""
    _lock_admins(session)
    session.execute(select(func.pg_advisory_xact_lock(func.hashtextextended(f"role:{uid}", 0))))


def _lock_admins(session: Session) -> None:
    """The global lock of every change to who is an active admin (role changes, account creation and status)."""
    session.execute(select(func.pg_advisory_xact_lock(func.hashtextextended("role:admins", 0))))


def _other_active_admins(session: Session, uid: str) -> int:
    """Active admins other than ``uid`` who have signed in at least once: the last-admin rule of ``_check_change`` and
    of switching an admin off. An admin created from the app (D-105) or by the command line has no session until it
    signs in (from the app, not even a password until it follows its e-mail), so it is no backup yet."""
    count = session.scalar(
        select(func.count())
        .select_from(AppUser)
        .where(
            AppUser.firebase_uid != uid,
            AppUser.active,
            AppUser.role == Role.ADMIN.value,
            AppUser.last_login_at.is_not(None),
        )
    )
    return int(count or 0)


def _refuse_bootstrap(session: Session, identity: VerifiedIdentity, current: str | None) -> None:
    """The checks ``bootstrap_role`` makes before touching Firebase: a new copy whose e-mail another account's copy
    already owns (``UserConflictError``), and the API's rules (``_check_change``: never demote the last active admin)
    with the operator in place of a signed-in admin."""
    if current is None and session.scalar(
        select(AppUser.id).where(AppUser.email == identity.email, AppUser.firebase_uid != identity.uid)
    ):
        raise UserConflictError(identity.uid)
    _check_change(True, current, identity.role, None, _other_active_admins(session, identity.uid))


def _refuse_last_admin(session: Session, uid: str) -> None:
    """``RoleConflictError("last_admin")`` when ``uid`` is an active admin and no other active admin has ever signed
    in (``_other_active_admins``): switching it off would leave nobody to switch it back on from the app."""
    target = session.execute(select(AppUser.role, AppUser.active).where(AppUser.firebase_uid == uid)).one_or_none()
    if (
        target is not None
        and target.active
        and target.role == Role.ADMIN.value
        and not _other_active_admins(session, uid)
    ):
        raise RoleConflictError("last_admin")


def _refuse_stored_email(session: Session, email: str, actor_uid: str) -> None:
    """``UserConflictError`` when a stored copy already owns the e-mail (``app_user.email`` is citext)."""
    if session.scalar(select(AppUser.id).where(AppUser.email == email)) is not None:
        raise UserConflictError(actor_uid)


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
                    others = self._backups(uid)
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

    def _require_admin(self, uid: str) -> None:
        with self._lock:
            actor = self._users.get(uid)
        if actor is None or not actor.active or actor.role is not Role.ADMIN:
            raise RoleConflictError("actor_not_admin")

    def _backups(self, uid: str) -> int:
        """Active admins other than ``uid`` who have signed in (call it holding ``_lock``)."""
        return sum(
            1
            for u in self._users.values()
            if u.firebase_uid != uid and u.active and u.role is Role.ADMIN and u.last_login_at is not None
        )

    def _refuse_last_admin(self, uid: str) -> None:
        with self._lock:
            target = self._users.get(uid)
            backups = self._backups(uid)
        if target is not None and target.active and target.role is Role.ADMIN and backups == 0:
            raise RoleConflictError("last_admin")

    def create_account(
        self, request: AccountRequest, actor_uid: str, create: Callable[[], NewAccount], discard: Callable[[str], None]
    ) -> UserRecord:
        uid, role = request.uid, request.role
        with self._lock:
            self.audit.append(AuditEntry(actor_uid, CREATE_REQUESTED, uid, None, {"role": role.value}))
        with self._role_lock:
            try:
                self._require_admin(actor_uid)
                self._refuse_taken(request.email, actor_uid)
            except Exception:
                self._create_failed(actor_uid, uid, role, None)
                raise
            try:
                account = create()
            except AccountNotCreatedError:
                self._create_failed(actor_uid, uid, role, None)
                raise
            except Exception:
                self._create_failed(actor_uid, uid, role, _discarded(discard, uid))
                raise
            record = UserRecord(
                id=uuid4(),
                firebase_uid=account.uid,
                email=account.email,
                display_name=None,
                role=role,
                active=True,
                created_at=datetime.now(UTC),
                last_login_at=None,
            )
            with self._lock:
                self._users[account.uid] = record
                self.audit.append(AuditEntry(actor_uid, CREATE, account.uid, None, _snapshot(record)))
            return record

    def _refuse_taken(self, email: str, actor_uid: str) -> None:
        with self._lock:
            taken = any(user.email.lower() == email.lower() for user in self._users.values())
        if taken:
            raise UserConflictError(actor_uid)

    def _create_failed(self, actor_uid: str, uid: str, role: Role, discarded: bool | None) -> None:
        with self._lock:
            self.audit.append(AuditEntry(actor_uid, CREATE_FAILED, uid, None, _create_failure(role, discarded)))

    def change_status(
        self, uid: str, disabled: bool, actor_uid: str, apply: Callable[[bool], bool]
    ) -> UserRecord | None:
        action = _status_action(disabled)
        with self._lock:
            self.audit.append(AuditEntry(actor_uid, f"{action}_requested", uid, None, {"active": not disabled}))
        with self._role_lock:
            try:
                self._require_admin(actor_uid)
                if disabled:
                    self._refuse_last_admin(uid)
                with self._lock:
                    copy = self._users.get(uid)
                    last = next(
                        (e.action for e in reversed(self.audit) if e.entity_id == uid and e.action in _STATUS_MARKS),
                        None,
                    )
                on = copy.active if copy is not None else last == "user.enable"
                revoked = apply(not disabled and on)
            except Exception:
                with self._lock:
                    self.audit.append(AuditEntry(actor_uid, f"{action}_failed", uid, None, {"active": not disabled}))
                raise
            with self._lock:
                current = self._users.get(uid)
                updated = replace(current, active=not disabled) if current else None
                if updated:
                    self._users[uid] = updated
                before = {"active": current.active} if current else None
                after = {"active": not disabled, "sessions_revoked": revoked}
                self.audit.append(AuditEntry(actor_uid, action, uid, before, after))
                return updated

    def authorize_password_email(self, uid: str, actor_uid: str) -> None:
        with self._role_lock:
            self._require_admin(actor_uid)
            with self._lock:
                target = self._users.get(uid)
                if target is not None and not target.active:
                    raise AccountDisabledError(uid)
                self.audit.append(AuditEntry(actor_uid, SETUP_EMAIL_REQUESTED, uid, None, None))

    def audit_password_email(self, uid: str, actor_uid: str, failure: str | None) -> None:
        with self._lock:
            self.audit.append(_password_email_entry(uid, actor_uid, failure))

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
                # so Firebase, the copy and the audit trail see concurrent changes in the same order; an actor
                # demoted meanwhile is seen as such (pending #19).
                _lock_role_change(session, uid)
                # The checks read without a row lock: the advisory locks already serialize role changes, and a row
                # lock held while Firebase answers would make every request of the user wait in `sync_login`.
                current = session.scalar(select(AppUser.role).where(AppUser.firebase_uid == uid))
                others = _other_active_admins(session, uid)
                actor_is_admin = bool(
                    session.scalar(
                        select(func.count())
                        .select_from(AppUser)
                        .where(AppUser.firebase_uid == actor_uid, AppUser.active, AppUser.role == Role.ADMIN.value)
                    )
                )
                _check_change(actor_is_admin, current, role, expected_role, others)
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

    def bootstrap_role(
        self, identity: VerifiedIdentity, apply: Callable[[], bool], claim_holds_role: bool
    ) -> BootstrapResult:
        """Give ``identity.uid`` the role ``identity.role`` from the command line (api.auth.bootstrap, D-087).

        Like ``change_role`` but without a signed-in actor (the audit rows carry ``"via": "cli"`` and no user) and for
        a user who may never have logged in: the copy is created from ``identity`` (``user_created``) when missing.
        ``apply`` sets the Firebase claim unless it already holds the role (it decides under the locks) and returns
        whether the sessions were revoked. Nothing happens, and nothing is audited, when ``claim_holds_role`` and the
        copy already holds the role. Refused before Firebase is touched: demoting the last active admin
        (``RoleConflictError``) and an e-mail that another account's copy already owns (``UserConflictError``).
        ``active`` is never changed.
        """
        uid, role = identity.uid, identity.role
        with self._sessions.begin() as session:
            user = session.scalar(select(AppUser).where(AppUser.firebase_uid == uid))
            if claim_holds_role and user is not None and user.role == role.value:
                return BootstrapResult(_record(user), changed=False, created=False, sessions_revoked=False)
        after = {"role": role.value, "via": CLI}
        with self._sessions.begin() as session:
            session.add(_audit(AuditEntry(None, "role_assignment_requested", uid, None, after), None, _now()))
        try:
            with self._sessions.begin() as session:
                # The same serialization as change_role. As there, the checks read without a row lock: a row lock held
                # while Firebase answers would make every request of the user wait in `sync_login`.
                _lock_role_change(session, uid)
                _refuse_bootstrap(
                    session, identity, session.scalar(select(AppUser.role).where(AppUser.firebase_uid == uid))
                )
                revoked = apply()
                now = _now()
                # The role the copy has now (a first login may have created it while Firebase answered), for the audit.
                current = session.scalar(
                    select(AppUser.role).where(AppUser.firebase_uid == uid).with_for_update(key_share=True)
                )
                # One statement after Firebase answered: creates the copy, or sets the role on the one that exists,
                # including a copy a first login created meanwhile (xmax = 0 marks a fresh insert).
                upsert: ReturningInsert[AppUser, bool] = (
                    insert(AppUser)
                    .values(
                        firebase_uid=uid,
                        email=identity.email,
                        display_name=identity.display_name,
                        role=role.value,
                        active=True,
                        created_at=now,
                        last_login_at=None,
                    )
                    .on_conflict_do_update(index_elements=[AppUser.firebase_uid], set_={"role": role.value})
                    .returning(AppUser, literal_column("xmax = 0", Boolean).label("created"))
                )
                row, created = session.execute(upsert).one()
                record = _record(row)
                if created:
                    session.add(_audit(AuditEntry(None, "user_created", uid, None, _snapshot(record)), None, now))
                before = {"role": current} if current is not None else None
                done = {**after, "sessions_revoked": revoked}
                session.add(_audit(AuditEntry(None, "role_assigned", uid, before, done), None, now))
                result = BootstrapResult(record, changed=True, created=bool(created), sessions_revoked=revoked)
        except IntegrityError as exc:
            # Only the e-mail can still collide (another account's copy took it after the check above); the Firebase
            # claim may already be set, the copy is not changed.
            self._audit_failed(uid, after)
            raise UserConflictError(uid) from exc
        except Exception:
            self._audit_failed(uid, after)
            raise
        return result

    def create_account(
        self, request: AccountRequest, actor_uid: str, create: Callable[[], NewAccount], discard: Callable[[str], None]
    ) -> UserRecord:
        uid, role = request.uid, request.role
        with self._sessions.begin() as session:
            entry = AuditEntry(actor_uid, CREATE_REQUESTED, uid, None, {"role": role.value})
            session.add(_audit(entry, self._actor(session, actor_uid), _now()))
        called = False  # whether Firebase may hold the account now
        try:
            with self._sessions.begin() as session:
                # The global lock of role changes: an admin demoted meanwhile cannot create accounts any more, and two
                # requests for the same e-mail reach Firebase one after the other.
                _lock_admins(session)
                actor_id = self._active_admin(session, actor_uid)
                _refuse_stored_email(session, request.email, actor_uid)
                called = True
                created = create()
                now = _now()
                row = session.scalars(
                    insert(AppUser)
                    .values(
                        firebase_uid=created.uid,
                        email=created.email,
                        display_name=None,
                        role=role.value,
                        active=True,
                        created_at=now,
                        last_login_at=None,
                    )
                    .returning(AppUser)
                ).one()
                record = _record(row)
                session.add(_audit(AuditEntry(actor_uid, CREATE, created.uid, None, _snapshot(record)), actor_id, now))
                session.flush()
        except AccountNotCreatedError:
            self._create_failed(actor_uid, uid, role, None)
            raise
        except IntegrityError as exc:
            # Only the e-mail can collide here (another copy took it while Firebase answered).
            self._create_failed(actor_uid, uid, role, _discarded(discard, uid))
            raise UserConflictError(actor_uid) from exc
        except Exception:
            stored = self._stored(uid) if called else None
            if stored is not None:
                return stored  # the commit went through although its answer was lost: never delete that account
            self._create_failed(actor_uid, uid, role, _discarded(discard, uid) if called else None)
            raise
        return record

    def _stored(self, uid: str) -> UserRecord | None:
        """The copy of ``uid`` if it is stored (it commits together with its ``user.create`` row)."""
        with self._sessions() as session:
            row = session.scalar(select(AppUser).where(AppUser.firebase_uid == uid))
            return _record(row) if row else None

    def _create_failed(self, actor_uid: str, uid: str, role: Role, discarded: bool | None) -> None:
        with self._sessions.begin() as session:
            entry = AuditEntry(actor_uid, CREATE_FAILED, uid, None, _create_failure(role, discarded))
            session.add(_audit(entry, self._actor(session, actor_uid), _now()))

    def change_status(
        self, uid: str, disabled: bool, actor_uid: str, apply: Callable[[bool], bool]
    ) -> UserRecord | None:
        action = _status_action(disabled)
        with self._sessions.begin() as session:
            entry = AuditEntry(actor_uid, f"{action}_requested", uid, None, {"active": not disabled})
            session.add(_audit(entry, self._actor(session, actor_uid), _now()))
        with self._account_lock(uid) as sessions:
            try:
                if disabled:
                    return self._switch_off(sessions, uid, actor_uid, apply)
                return self._switch_on(sessions, uid, actor_uid, apply)
            except Exception:
                with sessions.begin() as session:
                    entry = AuditEntry(actor_uid, f"{action}_failed", uid, None, {"active": not disabled})
                    session.add(_audit(entry, self._actor(session, actor_uid), _now()))
                raise

    @contextmanager
    def _account_lock(self, uid: str) -> Iterator[sessionmaker[Session]]:
        """One status change per account at a time, from its checks to its last audit row: a switch-off and a switch-on
        of the same account never interleave. The lock (session level) and every transaction of the change share one
        connection, so a change never waits for a second connection of the pool while it holds the lock (and requests
        waiting for the lock cannot starve it). Closing the connection releases the lock even after a crash."""
        key = func.hashtextextended(f"status:{uid}", 0)
        with self._sessions.kw["bind"].connect() as connection:
            connection.execute(select(func.pg_advisory_lock(key)))
            connection.commit()
            try:
                yield sessionmaker(bind=connection, expire_on_commit=False)
            finally:
                with suppress(SQLAlchemyError):  # a broken connection releases the lock when it closes
                    connection.rollback()
                    connection.execute(select(func.pg_advisory_unlock(key)))
                    connection.commit()

    @staticmethod
    def _switch_off(
        sessions: sessionmaker[Session], uid: str, actor_uid: str, apply: Callable[[bool], bool]
    ) -> UserRecord | None:
        """The copy goes off first, committed under the role lock, then Firebase: a concurrent change (two admins
        switching each other off) sees the switch-off under that lock, and every request of the user is refused from
        then on. If Firebase fails the copy stays off (Firebase may have switched the account off before failing):
        the change fails closed and switching the account on again fixes both sides."""
        with sessions.begin() as session:
            # Serialized with role changes, so two admins switching each other off cannot both succeed.
            _lock_role_change(session, uid)
            actor_id = SqlUserDirectory._active_admin(session, actor_uid)
            _refuse_last_admin(session, uid)
            was_active = session.scalar(
                select(AppUser.active).where(AppUser.firebase_uid == uid).with_for_update(key_share=True)
            )
            session.execute(update(AppUser).where(AppUser.firebase_uid == uid).values(active=False))
        try:
            revoked = apply(False)
        except Exception:
            # Fails closed here too: a copy a first sign-in created while Firebase answered goes off.
            with sessions.begin() as session:
                session.execute(update(AppUser).where(AppUser.firebase_uid == uid).values(active=False))
            raise
        with sessions.begin() as session:
            # Again: a first sign-in may have created the copy (active) while Firebase answered.
            session.execute(update(AppUser).where(AppUser.firebase_uid == uid).values(active=False))
            before = None if was_active is None else {"active": was_active}
            after = {"active": False, "sessions_revoked": revoked}
            session.add(_audit(AuditEntry(actor_uid, "user.disable", uid, before, after), actor_id, _now()))
            current = session.scalar(select(AppUser).where(AppUser.firebase_uid == uid))
            return _record(current) if current else None

    @staticmethod
    def _switch_on(
        sessions: sessionmaker[Session], uid: str, actor_uid: str, apply: Callable[[bool], bool]
    ) -> UserRecord | None:
        """Firebase first, then the copy, under the role lock: if the database fails after Firebase, the copy still
        refuses the user (403 ``user_inactive``) until the request is repeated."""
        with sessions.begin() as session:
            _lock_role_change(session, uid)
            actor_id = SqlUserDirectory._active_admin(session, actor_uid)
            # Status changes of this account are serialized (``_account_lock``): the copy read here stays as it is.
            copy_active = session.scalar(select(AppUser.active).where(AppUser.firebase_uid == uid))
            revoked = apply(copy_active if copy_active is not None else _switched_on_last(session, uid))
            # As in change_role: the row lock only for the local write, after Firebase answered.
            user = session.scalar(select(AppUser).where(AppUser.firebase_uid == uid).with_for_update(key_share=True))
            before = {"active": user.active} if user else None
            if user:
                user.active = True
            after = {"active": True, "sessions_revoked": revoked}
            session.add(_audit(AuditEntry(actor_uid, "user.enable", uid, before, after), actor_id, _now()))
            session.flush()
            return _record(user) if user else None

    def authorize_password_email(self, uid: str, actor_uid: str) -> None:
        with self._sessions.begin() as session:
            _lock_admins(session)  # an admin demoted or switched off meanwhile is seen as such
            actor_id = self._active_admin(session, actor_uid)
            if session.scalar(select(AppUser.active).where(AppUser.firebase_uid == uid)) is False:
                raise AccountDisabledError(uid)
            session.add(_audit(AuditEntry(actor_uid, SETUP_EMAIL_REQUESTED, uid, None, None), actor_id, _now()))

    def audit_password_email(self, uid: str, actor_uid: str, failure: str | None) -> None:
        with self._sessions.begin() as session:
            session.add(_audit(_password_email_entry(uid, actor_uid, failure), self._actor(session, actor_uid), _now()))

    @staticmethod
    def _active_admin(session: Session, actor_uid: str) -> UUID:
        """The actor's ``app_user.id``; ``RoleConflictError("actor_not_admin")`` unless it is an active admin now."""
        actor_id = session.scalar(
            select(AppUser.id).where(
                AppUser.firebase_uid == actor_uid, AppUser.active, AppUser.role == Role.ADMIN.value
            )
        )
        if actor_id is None:
            raise RoleConflictError("actor_not_admin")
        return actor_id

    def _audit_failed(self, uid: str, after: dict[str, Any]) -> None:
        with self._sessions.begin() as session:
            session.add(_audit(AuditEntry(None, "role_assignment_failed", uid, None, after), None, _now()))

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
