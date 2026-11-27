"""Give a Firebase user a role from the command line (D-087): the first admin of a real project.

    make set-role EMAIL=person@example.com ROLE=admin
    # = docker compose exec -T api python -m api.auth.bootstrap --email person@example.com --role admin

The admin route (``PUT /api/admin/users/{uid}/role``) needs an admin already, so an operator with access to the host
gives the first one its role here. It runs in the API container: the same Firebase project and credentials (or the Auth
emulator in development) and the same least-privilege database role as the API.

1. Looks the user up by e-mail in Firebase: the account must exist (signed up in the front with Email/Password, or
   created in the Firebase console). Email/Password sign-up does not prove the address, so an unverified e-mail is
   reported with the account's creation time: the operator checks it is the intended person's account.
2. Sets the ``role`` custom claim through the admin route's role manager (other claims kept, sessions revoked), unless
   the claim already holds the role; that is decided again under the directory's locks.
3. Syncs the ``app_user`` copy (created when the user never logged in) with the route's audit trail, without an actor
   (``"via": "cli"``). An inactive user stays inactive (``active`` belongs to the database) and is reported.

Idempotent: when the claim and the copy already hold the role, nothing changes and nothing is audited. An admin is never
demoted when no other active admin would remain, as in the route. The e-mail is never printed or logged; errors go to
stderr.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, TextIO

import firebase_admin
from firebase_admin import auth
from firebase_admin import exceptions as firebase_exceptions
from google.auth.exceptions import GoogleAuthError
from sqlalchemy.exc import SQLAlchemyError

from api.auth.directory import BootstrapResult, RoleConflictError, SqlUserDirectory, UserConflictError
from api.auth.firebase import FirebaseTokenVerifier
from api.auth.identity import AuthUnavailableError, VerifiedIdentity
from api.auth.role_admin import FirebaseRoleManager, RevocationPendingError, RoleManager, UnknownUserError
from api.auth.roles import ROLE_CLAIM, Role
from core.config import Settings
from core.db.session import make_session_factory


@dataclass(frozen=True, slots=True)
class FirebaseUser:
    """What the bootstrap needs from a Firebase account."""

    uid: str
    email: str
    display_name: str | None
    role_claim: str | None
    email_verified: bool
    created_at: datetime | None


class UserLookup(Protocol):
    def by_email(self, email: str) -> FirebaseUser:
        """Return the account with this e-mail; ``UnknownUserError`` if there is none."""
        ...

    def role_claim(self, uid: str) -> str | None:
        """The account's current ``role`` claim (read again just before writing it)."""
        ...


class BootstrapDirectory(Protocol):
    def bootstrap_role(
        self, identity: VerifiedIdentity, apply: Callable[[], bool], claim_holds_role: bool
    ) -> BootstrapResult: ...


class FirebaseUserLookup:
    """``UserLookup`` with firebase-admin, sharing the verifier's SDK app (project, credentials or emulator)."""

    def __init__(self, verifier: FirebaseTokenVerifier) -> None:
        self._verifier = verifier

    def _app(self) -> firebase_admin.App:
        try:
            return self._verifier.sdk_app()
        except (OSError, ValueError, GoogleAuthError) as exc:
            # Missing or unusable credentials: Firebase cannot be asked at all.
            raise AuthUnavailableError from exc

    def by_email(self, email: str) -> FirebaseUser:
        app = self._app()
        try:
            user = auth.get_user_by_email(email, app=app)
        except (auth.UserNotFoundError, ValueError) as exc:
            # ValueError: a malformed e-mail, which cannot name an account either.
            raise UnknownUserError("no account with that e-mail") from exc
        except (firebase_exceptions.FirebaseError, GoogleAuthError, OSError) as exc:
            raise AuthUnavailableError from exc
        created_ms = user.user_metadata.creation_timestamp if user.user_metadata else None
        return FirebaseUser(
            uid=user.uid,
            email=user.email or email,
            display_name=user.display_name,
            role_claim=_role(user.custom_claims),
            email_verified=bool(user.email_verified),
            created_at=datetime.fromtimestamp(created_ms / 1000, UTC) if created_ms else None,
        )

    def role_claim(self, uid: str) -> str | None:
        app = self._app()
        try:
            return _role(auth.get_user(uid, app=app).custom_claims)
        except (auth.UserNotFoundError, ValueError) as exc:
            raise UnknownUserError(uid) from exc
        except (firebase_exceptions.FirebaseError, GoogleAuthError, OSError) as exc:
            raise AuthUnavailableError from exc


def _role(claims: dict[str, object] | None) -> str | None:
    role = (claims or {}).get(ROLE_CLAIM)
    return role if isinstance(role, str) else None


class UnconfirmedAccountError(Exception):
    """The account must be confirmed by uid first: its e-mail is unverified, or the given uid is another account's."""

    def __init__(self, account: FirebaseUser, mismatch: bool) -> None:
        super().__init__(account.uid)
        self.account = account
        self.mismatch = mismatch


@dataclass(frozen=True, slots=True)
class Services:
    users: UserLookup
    manager: RoleManager
    directory: BootstrapDirectory


def bootstrap_role(
    email: str, role: Role, wiring: Services, confirm_uid: str | None = None
) -> tuple[FirebaseUser, BootstrapResult]:
    """Give the account with ``email`` the ``role`` in Firebase and in the ``app_user`` copy (see the module doc).

    Nothing is written for an account whose e-mail is unverified unless ``confirm_uid`` names it (anyone may have
    signed up with that address first), nor when ``confirm_uid`` names another account: ``UnconfirmedAccountError``.
    """
    users, manager, directory = wiring.users, wiring.manager, wiring.directory
    account = users.by_email(email)
    if confirm_uid is not None and confirm_uid != account.uid:
        raise UnconfirmedAccountError(account, mismatch=True)
    if not account.email_verified and confirm_uid is None:
        raise UnconfirmedAccountError(account, mismatch=False)
    identity = VerifiedIdentity(uid=account.uid, email=account.email, display_name=account.display_name, role=role)

    def apply() -> bool:
        # Runs under the directory's locks: the claim is read again, so a change made meanwhile is not missed.
        if users.role_claim(account.uid) == role.value:
            return False
        try:
            manager.assign(account.uid, role)
        except RevocationPendingError:
            return False  # the claim changed; the old tokens stay valid until they expire (at most an hour)
        return True

    result = directory.bootstrap_role(identity, apply, claim_holds_role=account.role_claim == role.value)
    return account, result


def default_services(settings: Settings) -> Services:
    """The API's own wiring: Firebase from FIREBASE_PROJECT_ID and FIREBASE_CREDENTIALS_FILE, the app database role."""
    verifier = FirebaseTokenVerifier(settings.firebase_project_id, settings.firebase_credentials_file)
    return Services(
        users=FirebaseUserLookup(verifier),
        manager=FirebaseRoleManager(verifier),
        directory=SqlUserDirectory(make_session_factory(settings)),
    )


def _refusal(error: Exception) -> str:
    if isinstance(error, UnknownUserError):
        return (
            "no Firebase account has that e-mail in this project: sign up first in the front (Email/Password) "
            "or create the user in the Firebase console, then run this again"
        )
    if isinstance(error, AuthUnavailableError):
        return "Firebase could not be reached or rejected the credentials; the Hermes copy was not changed"
    if isinstance(error, RoleConflictError) and error.code == "last_admin":
        return (
            "refused: no other active admin has signed in yet; give another user the admin role and let them sign in "
            "first"
        )
    if isinstance(error, RoleConflictError):
        return f"refused: {error.code}"
    return "another Hermes user already has that e-mail with a different Firebase account; the copy was not changed"


def _confirmation(error: UnconfirmedAccountError) -> str:
    account = error.account
    if error.mismatch:
        return "✖ --confirm-uid is not the uid of the account with that e-mail; nothing changed"
    created = account.created_at.isoformat(timespec="minutes") if account.created_at else "unknown"
    return (
        f"⚠ the account's e-mail is not verified in Firebase: account {account.uid}, created {created}; "
        "nothing changed. Check in the Firebase console (Authentication > Users) that this account belongs to the "
        f"intended person, then run again with --confirm-uid {account.uid} "
        f"(make set-role ... CONFIRM_UID={account.uid})"
    )


def main(
    argv: Sequence[str] | None = None,
    services: Callable[[], Services] | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    parser = argparse.ArgumentParser(prog="api.auth.bootstrap", description="Give a Firebase user a Hermes role.")
    parser.add_argument("--email", required=True, help="e-mail of an existing Firebase account")
    parser.add_argument("--role", required=True, choices=[r.value for r in Role])
    parser.add_argument(
        "--confirm-uid", help="uid of the account, required when its e-mail is unverified (check it in the console)"
    )
    args = parser.parse_args(argv)
    out, err = out or sys.stdout, err or sys.stderr
    try:
        wiring = services() if services else default_services(Settings())
        _, result = bootstrap_role(args.email.strip(), Role(args.role), wiring, args.confirm_uid)
    except UnconfirmedAccountError as exc:
        print(_confirmation(exc), file=err)
        return 3
    except (UnknownUserError, AuthUnavailableError, RoleConflictError, UserConflictError) as exc:
        print(f"✖ {_refusal(exc)}", file=err)
        return 1
    except SQLAlchemyError as exc:
        # Only the class: the driver's message can quote the statement's parameters, the e-mail among them.
        print(f"✖ database error ({type(exc).__name__}); the Firebase claim may already be set: run again", file=err)
        return 1
    record = result.record
    if not result.changed:
        print(f"✔ {record.firebase_uid} already has the role {record.role.value}; nothing changed", file=out)
    else:
        how = "created in Hermes" if result.created else "updated"
        sessions = "revoked" if result.sessions_revoked else "not revoked (claim already set or revocation failed)"
        print(f"✔ role {record.role.value} set for {record.firebase_uid} ({how}); sessions {sessions}", file=out)
    if not record.active:
        print(
            "⚠ the user is inactive in Hermes: it keeps the role but cannot use the API until an admin reactivates it",
            file=err,
        )
    return 0


if __name__ == "__main__":  # pragma: no cover - the module is run with python -m
    sys.exit(main())
