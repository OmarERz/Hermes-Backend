"""Firebase accounts an admin creates, switches off and on (D-105, F18.8).

An admin creates an account with an e-mail and a role: firebase-admin creates it **without a password** and with the
e-mail unverified, and sets the ``role`` claim (D-030). Firebase then e-mails the person a link to choose a password,
with the project's password-reset template. Hermes never sees, stores or logs a password or that link: the e-mail goes
out through Identity Toolkit (``POST /v1/projects/{project}/accounts:sendOobCode`` with ``requestType:
PASSWORD_RESET``), called from the server with the service account's OAuth token and without ``returnOobLink``, so
Google sends the e-mail itself and the link only ever exists in the person's mailbox. The Admin SDK can only *generate*
that link (``generate_password_reset_link``), which would put it in Hermes' hands; the client SDK's
``sendPasswordResetEmail`` would make the front send it after the creation, so a closed tab could lose the e-mail.

Against the Auth emulator (allowed only for ``demo-`` projects, ``api.auth.firebase``) the same call goes to the
emulator, which keeps the code for tests instead of sending mail; it accepts the ``owner`` bearer as admin.

Disabling an account switches it off in Firebase (it cannot sign in or refresh, and ``check_revoked`` refuses its live
ID tokens) and revokes its refresh tokens. Firebase keeps the revocation time in whole seconds and only refuses tokens
issued *before* that second, so every revocation waits for the next full second (as ``api.auth.role_admin`` does).
Switching an account back on revokes its sessions again first and refuses to switch it on if that fails: a session of
before the switch-off never comes back to life, even when the revocation at switch-off time failed.

Error messages of the SDK can quote the e-mail, so only exception classes are logged; the e-mail and the response
bodies of Identity Toolkit are never logged.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import os
import re
import secrets
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Protocol

import firebase_admin
import httpx
from firebase_admin import auth
from firebase_admin import exceptions as firebase_exceptions
from google.auth.exceptions import GoogleAuthError

from api.auth.directory import AccountNotCreatedError, NewAccount
from api.auth.firebase import EMULATOR_ENV_VAR, EMULATOR_PROJECT_PREFIX, FirebaseTokenVerifier
from api.auth.identity import AuthUnavailableError
from api.auth.role_admin import RevocationPendingError, UnknownUserError, revoke_sessions
from api.auth.roles import ROLE_CLAIM, Role

logger = logging.getLogger(__name__)

IDENTITY_TOOLKIT: Final = "https://identitytoolkit.googleapis.com/v1"
UID_BYTES: Final = 14  # 28 hex characters, the length of the uids Firebase generates
EMULATOR_BEARER: Final = "owner"  # the Auth emulator's admin credential (firebase-admin uses the same one)
SEND_TIMEOUT: Final = httpx.Timeout(10.0)
# Identity Toolkit error messages start with an upper-case code (``EMAIL_NOT_FOUND``, ``TOO_MANY_ATTEMPTS_TRY_LATER``,
# sometimes followed by `` : details``); only that code is kept.
_ERROR_CODE: Final = re.compile(r"[A-Z][A-Z_]{1,63}")
# At most this many password e-mails per admin in a sliding window (EmailQuota).
EMAILS_PER_WINDOW: Final = 20
EMAIL_WINDOW_SECONDS: Final = 3600.0


class EmailInUseError(AccountNotCreatedError):
    """Firebase already has an account with this e-mail."""


class InvalidEmailError(AccountNotCreatedError):
    """Firebase refused the e-mail address."""


class UidInUseError(AccountNotCreatedError):
    """Another account already has the uid Hermes picked (practically never): it is not ours, never touch it."""


def new_uid() -> str:
    """A uid for a new account (28 hex characters, the length of the uids Firebase generates). Hermes picks it, so an
    account Firebase created before an error can still be found and removed by it."""
    return secrets.token_hex(UID_BYTES)


class PasswordEmailError(Exception):
    """Identity Toolkit did not send the password e-mail. ``reason`` is a short code, never the e-mail or a link."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class AccountInfo:
    """What the password e-mail needs from an existing account."""

    uid: str
    email: str | None
    disabled: bool


class AccountManager(Protocol):
    def create(self, uid: str, email: str, role: Role) -> NewAccount:
        """Create the account ``uid`` (``new_uid``) with no password, an unverified e-mail and the ``role`` claim.
        ``EmailInUseError``, ``InvalidEmailError`` or ``UidInUseError`` when Firebase refused it (nothing exists);
        ``AuthUnavailableError`` otherwise, when the account may exist half made: the caller removes it with
        ``discard(uid)``."""
        ...

    def discard(self, uid: str) -> None:
        """Delete an account this manager was asked to create (it failed half way, or Hermes could not keep its copy).
        Never created or gone already: no error."""
        ...

    def lookup(self, uid: str) -> AccountInfo:
        """The account's e-mail and state; ``UnknownUserError`` if the uid does not exist."""
        ...

    def set_disabled(self, uid: str, disabled: bool) -> bool:
        """Switch the account off or on and revoke its refresh tokens; returns whether they were revoked. Switching
        off never fails on the revocation (the account is off already); switching on revokes first and raises
        ``AuthUnavailableError`` without switching it on when that fails. ``UnknownUserError`` if the uid does not
        exist."""
        ...

    def send_password_setup(self, email: str, user_ip: str | None) -> None:
        """Have Firebase e-mail the person a link to choose a password; ``PasswordEmailError`` if it was not sent.
        ``user_ip`` is the address of the admin who asked: Identity Toolkit requires it (``userIp``) for
        ``PASSWORD_RESET``, so without a valid IP nothing is sent (``user_ip_missing``)."""
        ...


class FirebaseAccountManager:
    """``AccountManager`` with firebase-admin and Identity Toolkit, sharing the verifier's SDK app."""

    def __init__(
        self,
        verifier: FirebaseTokenVerifier,
        http: httpx.Client | None = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._verifier = verifier
        # No proxy from the environment and no redirects: the bearer token goes to Identity Toolkit only.
        self._http = http or httpx.Client(trust_env=False, timeout=SEND_TIMEOUT, follow_redirects=False)
        self._clock = clock
        self._sleep = sleep

    def _app(self) -> firebase_admin.App:
        try:
            return self._verifier.sdk_app()
        except (OSError, ValueError, GoogleAuthError) as exc:
            logger.warning("identity provider unavailable: %s", type(exc).__name__)
            raise AuthUnavailableError from exc

    def create(self, uid: str, email: str, role: Role) -> NewAccount:
        app = self._app()
        try:
            user = auth.create_user(uid=uid, email=email, email_verified=False, disabled=False, app=app)
        except (auth.EmailAlreadyExistsError, auth.UidAlreadyExistsError) as exc:
            # The SDK retries a POST whose answer was lost (a read timeout, a 500 or 503): the retry then finds the
            # account this very call created. That one is ours and goes on; any other is not, and is never touched.
            own = self._own_account(app, uid, email)
            if own is None:
                raise (EmailInUseError if isinstance(exc, auth.EmailAlreadyExistsError) else UidInUseError) from exc
            user = own
        except (ValueError, firebase_exceptions.InvalidArgumentError) as exc:
            # ValueError: the SDK's own check; InvalidArgumentError: Identity Toolkit's INVALID_EMAIL.
            raise InvalidEmailError from exc
        except (firebase_exceptions.FirebaseError, GoogleAuthError, OSError) as exc:
            # The SDK reads the account back after creating it: it may exist even though this call failed.
            logger.warning("identity provider unavailable: %s", type(exc).__name__)
            raise AuthUnavailableError from exc
        try:
            auth.set_custom_user_claims(uid, {ROLE_CLAIM: role.value}, app=app)
        except (firebase_exceptions.FirebaseError, GoogleAuthError, OSError, ValueError) as exc:
            # Without its claim the account could never use Hermes: the caller deletes it, so the admin can retry.
            logger.warning("role claim not set on new account %s: %s", uid, type(exc).__name__)
            raise AuthUnavailableError from exc
        return NewAccount(uid=uid, email=user.email or email)

    @staticmethod
    def _own_account(app: firebase_admin.App, uid: str, email: str) -> auth.UserRecord | None:
        """The account ``uid`` if it has ``email`` (the uid is random: only this call can have made it); None when there
        is no such account, it has another e-mail, or Firebase cannot tell (then it is left alone)."""
        try:
            user = auth.get_user(uid, app=app)
        except auth.UserNotFoundError:
            return None
        except (firebase_exceptions.FirebaseError, GoogleAuthError, OSError, ValueError) as exc:
            logger.warning("identity provider unavailable: %s", type(exc).__name__)
            return None
        same = (user.email or "").casefold() == email.casefold()
        return user if same else None

    def discard(self, uid: str) -> None:
        app = self._app()
        try:
            auth.delete_user(uid, app=app)
        except auth.UserNotFoundError:
            return
        except (firebase_exceptions.FirebaseError, GoogleAuthError, OSError, ValueError) as exc:
            logger.warning("identity provider unavailable: %s", type(exc).__name__)
            raise AuthUnavailableError from exc

    def lookup(self, uid: str) -> AccountInfo:
        app = self._app()
        try:
            user = auth.get_user(uid, app=app)
        except (auth.UserNotFoundError, ValueError) as exc:
            # ValueError: a malformed uid, which cannot name an existing user either.
            raise UnknownUserError(uid) from exc
        except (firebase_exceptions.FirebaseError, GoogleAuthError, OSError) as exc:
            logger.warning("identity provider unavailable: %s", type(exc).__name__)
            raise AuthUnavailableError from exc
        return AccountInfo(uid=user.uid, email=user.email, disabled=bool(user.disabled))

    def set_disabled(self, uid: str, disabled: bool) -> bool:
        app = self._app()
        if disabled:
            self._update(app, uid, disabled=True)
            try:
                self._revoke_after_this_second(app, uid)
            except RevocationPendingError:
                # The account is off already: Firebase refuses its sign-ins, refreshes and (check_revoked) live ID
                # tokens; switching it on later revokes again before anything else.
                return False
            return True
        self.lookup(uid)  # an unknown uid is a 404, not a failed revocation
        try:
            self._revoke_after_this_second(app, uid)
        except RevocationPendingError as exc:
            raise AuthUnavailableError from exc  # stays off: a session of before the switch-off could come back
        self._update(app, uid, disabled=False)
        return True

    @staticmethod
    def _update(app: firebase_admin.App, uid: str, disabled: bool) -> None:
        try:
            auth.update_user(uid, disabled=disabled, app=app)
        except (auth.UserNotFoundError, ValueError) as exc:
            raise UnknownUserError(uid) from exc
        except (firebase_exceptions.FirebaseError, GoogleAuthError, OSError) as exc:
            logger.warning("identity provider unavailable: %s", type(exc).__name__)
            raise AuthUnavailableError from exc

    def _revoke_after_this_second(self, app: firebase_admin.App, uid: str) -> None:
        """Revoke once the second in progress is over, so every token issued until now is strictly older than the
        revocation (Firebase compares whole seconds)."""
        now = self._clock()
        self._sleep(math.floor(now) + 1 - now)
        revoke_sessions(app, uid)

    def send_password_setup(self, email: str, user_ip: str | None) -> None:
        if not _is_ip(user_ip):
            raise PasswordEmailError("user_ip_missing")
        app = self._app()
        project = app.project_id
        emulator = os.environ.get(EMULATOR_ENV_VAR)
        if emulator and not (project or "").startswith(EMULATOR_PROJECT_PREFIX):
            raise PasswordEmailError("emulator_not_allowed")  # the verifier refuses this too; never send a token there
        base = f"http://{emulator}/identitytoolkit.googleapis.com/v1" if emulator else IDENTITY_TOOLKIT
        token = EMULATOR_BEARER if emulator else _access_token(app)
        # userIp: required for PASSWORD_RESET by the Identity Toolkit reference.
        body = {"requestType": "PASSWORD_RESET", "email": email, "userIp": str(user_ip)}
        try:
            response = self._http.post(
                f"{base}/projects/{project}/accounts:sendOobCode",
                json=body,
                headers={"Authorization": f"Bearer {token}"},
            )
        except httpx.HTTPError as exc:
            logger.warning("setup e-mail not sent: %s", type(exc).__name__)
            raise PasswordEmailError("unreachable") from exc
        if response.status_code != httpx.codes.OK:
            reason = _error_code(response)
            logger.warning("setup e-mail not sent: HTTP %d %s", response.status_code, reason)
            raise PasswordEmailError(reason)


def _is_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _access_token(app: firebase_admin.App) -> str:
    """An OAuth token of the app's credential (the service account in a real project)."""
    try:
        token = app.credential.get_access_token().access_token
    except (GoogleAuthError, OSError, ValueError) as exc:
        logger.warning("setup e-mail not sent: %s", type(exc).__name__)
        raise PasswordEmailError("credentials") from exc
    if not isinstance(token, str) or not token:
        raise PasswordEmailError("credentials")
    return token


def _error_code(response: httpx.Response) -> str:
    """The upper-case code of an Identity Toolkit error (``EMAIL_NOT_FOUND``), or ``http_<status>``; nothing else of the
    body is read."""
    try:
        message = response.json()["error"]["message"]
    except (ValueError, KeyError, TypeError):
        message = None
    found = _ERROR_CODE.match(message) if isinstance(message, str) else None
    return found.group(0) if found else f"http_{response.status_code}"


class EmailQuota:
    """At most ``limit`` password e-mails per admin in a sliding ``window`` of seconds, counted in this API process.

    The API has no general rate limit (the reverse proxy limits requests per IP, README §7); this one caps the e-mails
    an admin's session can make Firebase send, so a stolen admin token cannot use the project to spam addresses.
    """

    def __init__(
        self,
        limit: int = EMAILS_PER_WINDOW,
        window: float = EMAIL_WINDOW_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limit = limit
        self._window = window
        self._clock = clock
        self._sent: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def take(self, actor_uid: str) -> bool:
        """Count one e-mail for ``actor_uid``; False (and nothing counted) when the window is full."""
        now = self._clock()
        with self._lock:
            sent = self._sent.setdefault(actor_uid, deque())
            while sent and now - sent[0] >= self._window:
                sent.popleft()
            if len(sent) >= self._limit:
                return False
            sent.append(now)
            return True
