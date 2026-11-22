"""Firebase ID token verification with firebase-admin (D-029, SEG-25).

Checks signature, issuer, audience, expiry and revocation (``check_revoked=True``) and requires a known
``role`` custom claim. With ``FIREBASE_AUTH_EMULATOR_HOST`` set the SDK talks to the local Auth emulator,
which issues unsigned tokens; that is only allowed for demo projects so production can never accept them.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import firebase_admin
from firebase_admin import auth, credentials
from firebase_admin import exceptions as firebase_exceptions
from google.auth.exceptions import GoogleAuthError

from api.auth.identity import AuthUnavailableError, TokenError, VerifiedIdentity
from api.auth.roles import ROLE_CLAIM, parse_role

logger = logging.getLogger(__name__)

EMULATOR_ENV_VAR = "FIREBASE_AUTH_EMULATOR_HOST"
EMULATOR_PROJECT_PREFIX = "demo-"


class FirebaseTokenVerifier:
    """``TokenVerifier`` backed by firebase-admin. The SDK app is created on first use."""

    def __init__(self, project_id: str, credentials_file: Path | None = None) -> None:
        if not project_id.strip():
            raise ValueError("FIREBASE_PROJECT_ID is empty")
        if os.environ.get(EMULATOR_ENV_VAR) and not project_id.startswith(EMULATOR_PROJECT_PREFIX):
            # The emulator skips signature checks: never let a real project run against it.
            raise ValueError(f"{EMULATOR_ENV_VAR} is only allowed with a '{EMULATOR_PROJECT_PREFIX}' project")
        self._project_id = project_id
        self._credentials_file = credentials_file
        self._app: firebase_admin.App | None = None
        self._lock = threading.Lock()

    def _get_app(self) -> firebase_admin.App:
        with self._lock:
            if self._app is None:
                options = {"projectId": self._project_id}
                cred = credentials.Certificate(str(self._credentials_file)) if self._credentials_file else None
                self._app = firebase_admin.initialize_app(cred, options, name=f"hermes-{uuid.uuid4().hex}")
            return self._app

    def sdk_app(self) -> firebase_admin.App:
        """The firebase-admin app (created on first use); shared with the role manager."""
        return self._get_app()

    def verify(self, token: str) -> VerifiedIdentity:
        if not token:
            raise TokenError("token_missing")
        try:
            app = self._get_app()
        except (OSError, ValueError, GoogleAuthError) as exc:
            # Missing or unreadable credentials: the provider cannot be reached, so fail closed.
            logger.warning("identity provider unavailable: %s", type(exc).__name__)
            raise AuthUnavailableError from exc
        try:
            claims: dict[str, Any] = auth.verify_id_token(token, app=app, check_revoked=True)
        except auth.ExpiredIdTokenError as exc:
            raise TokenError("token_expired") from exc
        except auth.RevokedIdTokenError as exc:
            raise TokenError("token_revoked") from exc
        except auth.UserDisabledError as exc:
            raise TokenError("user_disabled") from exc
        except auth.UserNotFoundError as exc:
            raise TokenError("user_not_found") from exc
        except (auth.InvalidIdTokenError, ValueError, TypeError) as exc:
            raise TokenError("token_invalid") from exc
        except (auth.CertificateFetchError, firebase_exceptions.FirebaseError, GoogleAuthError, OSError) as exc:
            # Log the exception class only: messages can embed token fragments.
            logger.warning("identity provider unavailable: %s", type(exc).__name__)
            raise AuthUnavailableError from exc
        # The SDK skips the expiry check against the emulator, so enforce it here for every mode.
        exp = claims.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, int | float) or exp <= time.time():
            raise TokenError("token_expired")
        return _identity_from_claims(claims)


def _identity_from_claims(claims: dict[str, Any]) -> VerifiedIdentity:
    uid = claims.get("uid")
    email = claims.get("email")
    if not isinstance(uid, str) or not uid or not isinstance(email, str) or not email.strip():
        raise TokenError("token_incomplete")
    role = parse_role(claims.get(ROLE_CLAIM))
    if role is None:
        raise TokenError("role_missing")
    name = claims.get("name")
    return VerifiedIdentity(
        uid=uid, email=email.strip(), display_name=name if isinstance(name, str) else None, role=role
    )
