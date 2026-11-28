"""User list for the admin screen (D-088, F18.2): the ``app_user`` copy joined with the Firebase directory.

Firebase is the master of accounts and roles (D-030); ``app_user`` keeps a copy of the role and owns ``active``. A
Firebase account that never signed in has no copy yet, or one an admin (D-105) or the command line made before its first
sign-in (``signed_in`` false either way). The effective role follows the same rule
as every request (``api.auth.dependencies``): the lower of the claim and the copy, and none at all for an inactive
user, a disabled account or a missing claim (such a token is refused). The list is read only: roles change through
``PUT /api/admin/users/{uid}/role``, which takes the stored role back as ``expected_role``.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Protocol

from firebase_admin import auth
from firebase_admin import exceptions as firebase_exceptions
from google.auth.exceptions import GoogleAuthError
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.auth.firebase import FirebaseTokenVerifier
from api.auth.identity import AuthUnavailableError
from api.auth.roles import ROLE_CLAIM, Role, parse_role
from core.db.models import AppUser

logger = logging.getLogger(__name__)

PAGE_SIZE: Final = 1000  # the Firebase maximum per page; `iterate_all` follows every page


@dataclass(frozen=True, slots=True)
class DirectoryUser:
    """One Firebase account, as the admin SDK lists it."""

    uid: str
    email: str | None
    display_name: str | None
    claim_role: Role | None
    disabled: bool


@dataclass(frozen=True, slots=True)
class StoredUser:
    """The ``app_user`` copy of one account."""

    uid: str
    email: str
    display_name: str | None
    role: Role
    active: bool
    last_login_at: datetime | None


@dataclass(frozen=True, slots=True)
class UserView:
    uid: str
    email: str | None
    display_name: str | None
    role: Role | None  # the stored copy: what an admin sends back as `expected_role`
    claim_role: Role | None
    effective_role: Role | None
    active: bool
    signed_in: bool
    last_login_at: datetime | None

    @property
    def sort_key(self) -> tuple[str, str]:
        return ((self.email or "").lower(), self.uid)


class UserLister(Protocol):
    def list_users(self) -> list[DirectoryUser]:
        """Every Firebase account, all pages; ``AuthUnavailableError`` if Firebase fails."""
        ...


class FirebaseUserLister:
    """``UserLister`` backed by firebase-admin, sharing the verifier's SDK app."""

    def __init__(self, verifier: FirebaseTokenVerifier) -> None:
        self._verifier = verifier

    def list_users(self) -> list[DirectoryUser]:
        try:
            app = self._verifier.sdk_app()
            page = auth.list_users(max_results=PAGE_SIZE, app=app)
            found = [_directory_user(record) for record in page.iterate_all()]
        except (firebase_exceptions.FirebaseError, GoogleAuthError, OSError, ValueError) as exc:
            logger.warning("identity provider unavailable: %s", type(exc).__name__)
            raise AuthUnavailableError from exc
        return found


def _directory_user(record: auth.ExportedUserRecord) -> DirectoryUser:
    claims = record.custom_claims or {}
    return DirectoryUser(
        uid=record.uid,
        email=record.email,
        display_name=record.display_name,
        claim_role=parse_role(claims.get(ROLE_CLAIM)),
        disabled=bool(record.disabled),
    )


def stored_users(session: Session) -> list[StoredUser]:
    """Every ``app_user`` row."""
    return [
        StoredUser(row.firebase_uid, row.email, row.display_name, Role(row.role), row.active, row.last_login_at)
        for row in session.scalars(select(AppUser))
    ]


def effective_role(claim: Role | None, stored: StoredUser | None, refused: bool) -> Role | None:
    """The role a request of this user would get now; None when it would be refused."""
    if claim is None or refused or (stored is not None and not stored.active):
        return None
    return claim if stored is None else claim.capped_by(stored.role)


def _refused(account: DirectoryUser | None, uid: str, owners: dict[str, str]) -> bool:
    """Whether a sign-in of this account is refused before any role applies: no account or no e-mail (401
    `token_incomplete`), or an e-mail another account's copy already owns (409 `account_conflict`)."""
    email = (account.email or "").strip().lower() if account is not None else ""
    if account is None or account.disabled or not email:
        return True
    owner = owners.get(email)
    return owner is not None and owner != uid


def merge_users(stored: Iterable[StoredUser], directory: Iterable[DirectoryUser]) -> list[UserView]:
    """One row per account of either side, ordered by e-mail (case-insensitive) and uid. A copy whose Firebase
    account is gone stays listed with no claim and no effective role."""
    copies = {user.uid: user for user in stored}
    accounts = {user.uid: user for user in directory}
    owners = {copy.email.strip().lower(): uid for uid, copy in copies.items()}  # app_user.email is unique (citext)
    views: list[UserView] = []
    for uid in copies.keys() | accounts.keys():
        copy, account = copies.get(uid), accounts.get(uid)
        claim = account.claim_role if account is not None else None
        disabled = _refused(account, uid, owners)
        views.append(
            UserView(
                uid=uid,
                email=copy.email if copy is not None else account.email if account is not None else None,
                display_name=copy.display_name
                if copy is not None and copy.display_name
                else (account.display_name if account is not None else None),
                role=copy.role if copy is not None else None,
                claim_role=claim,
                effective_role=effective_role(claim, copy, disabled),
                # Active in Hermes and in Firebase (API-04): a disabled or deleted Firebase account is never active.
                active=(copy is None or copy.active) and account is not None and not account.disabled,
                signed_in=copy is not None and copy.last_login_at is not None,
                last_login_at=copy.last_login_at if copy is not None else None,
            )
        )
    return sorted(views, key=lambda view: view.sort_key)


def page_at(views: list[UserView], offset: int, limit: int) -> tuple[list[UserView], int | None]:
    """The page starting at ``offset`` of the ordered list and the offset of the next page (None at the end). The
    cursor carries only this position, never an e-mail or a uid, so the URL of the next page names nobody."""
    start = max(offset, 0)
    end = start + limit
    return views[start:end], end if end < len(views) else None
