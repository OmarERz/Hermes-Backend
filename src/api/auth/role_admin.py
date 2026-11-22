"""Role assignment in Firebase (D-030: only the backend sets the ``role`` custom claim).

After setting the claim, the user's refresh tokens are revoked: tokens issued with the previous role fail
``check_revoked`` from then on, so a downgrade takes effect at once instead of at the next token refresh.
Firebase stores the revocation time in whole seconds and only rejects tokens issued *before* that second, so
the revocation waits for the next full second: every token issued with the old claim (at or before the claim
change) is then strictly older than the revocation time.
"""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Callable
from typing import Protocol

from firebase_admin import auth
from firebase_admin import exceptions as firebase_exceptions
from google.auth.exceptions import GoogleAuthError

from api.auth.firebase import FirebaseTokenVerifier
from api.auth.identity import AuthUnavailableError
from api.auth.roles import ROLE_CLAIM, Role

logger = logging.getLogger(__name__)


REVOKE_ATTEMPTS = 3


class UnknownUserError(LookupError):
    """The uid does not exist in Firebase."""


class RevocationPendingError(RuntimeError):
    """The role claim changed but the sessions could not be revoked; the database copy still limits the role."""


class RoleManager(Protocol):
    def assign(self, uid: str, role: Role) -> None:
        """Set the role claim (other custom claims are kept) and revoke the user's sessions.

        Raises ``RevocationPendingError`` when the claim changed but the revocation failed.
        """
        ...


class FirebaseRoleManager:
    """``RoleManager`` backed by firebase-admin, sharing the verifier's SDK app."""

    def __init__(
        self,
        verifier: FirebaseTokenVerifier,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._verifier = verifier
        self._clock = clock
        self._sleep = sleep

    def _wait_for_next_second(self) -> None:
        now = self._clock()
        self._sleep(math.floor(now) + 1 - now)

    def assign(self, uid: str, role: Role) -> None:
        try:
            app = self._verifier.sdk_app()
        except (OSError, ValueError, GoogleAuthError) as exc:
            logger.warning("identity provider unavailable: %s", type(exc).__name__)
            raise AuthUnavailableError from exc
        try:
            user = auth.get_user(uid, app=app)
            claims = dict(user.custom_claims or {})
            claims[ROLE_CLAIM] = role.value
            auth.set_custom_user_claims(uid, claims, app=app)
        except (auth.UserNotFoundError, ValueError) as exc:
            # ValueError: a malformed uid, which cannot name an existing user either.
            raise UnknownUserError(uid) from exc
        except (firebase_exceptions.FirebaseError, GoogleAuthError, OSError) as exc:
            logger.warning("identity provider unavailable: %s", type(exc).__name__)
            raise AuthUnavailableError from exc
        self._wait_for_next_second()
        self._revoke(app, uid)

    def _revoke(self, app: object, uid: str) -> None:
        failure: Exception | None = None
        for attempt in range(1, REVOKE_ATTEMPTS + 1):
            try:
                auth.revoke_refresh_tokens(uid, app=app)
            except (firebase_exceptions.FirebaseError, GoogleAuthError, OSError) as exc:
                logger.warning("session revocation failed (attempt %d): %s", attempt, type(exc).__name__)
                failure = exc
                continue
            return
        raise RevocationPendingError(uid) from failure
