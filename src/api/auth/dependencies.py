"""FastAPI dependencies: current user and ``require_role`` (API-01, SEG-25)."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from api.auth.directory import UserConflictError, UserDirectory
from api.auth.identity import AuthUnavailableError, TokenError, TokenVerifier
from api.auth.roles import Role
from api.errors import ApiError, ErrorDetail

logger = logging.getLogger(__name__)

_bearer = HTTPBearer(auto_error=False, description="Firebase ID token")


class CurrentUser(BaseModel):
    """The authenticated user, as returned by ``GET /api/me``."""

    uid: str
    email: str
    display_name: str | None
    role: Role


def _unauthenticated() -> HTTPException:
    # HTTPException so the Bearer challenge header (RFC 9110) goes out through the error envelope handler.
    return HTTPException(401, "Autenticación requerida o token no válido.", headers={"WWW-Authenticate": "Bearer"})


def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> CurrentUser:
    if credentials is None or not credentials.credentials:
        raise _unauthenticated()
    verifier: TokenVerifier = request.app.state.token_verifier
    directory: UserDirectory = request.app.state.user_directory
    try:
        identity = verifier.verify(credentials.credentials)
    except TokenError as exc:
        logger.info("authentication rejected: %s", exc.reason)
        raise _unauthenticated() from exc
    except AuthUnavailableError as exc:
        raise ApiError(503, "auth_unavailable", "No se pudo verificar la identidad. Intenta de nuevo.") from exc
    try:
        record = directory.sync_login(identity)
    except UserConflictError as exc:
        logger.warning("account conflict: user %s shares an e-mail with an older account", identity.uid)
        raise ApiError(
            409, "account_conflict", "Tu correo ya pertenece a otra cuenta. Pide a un administrador que la revise."
        ) from exc
    if not record.active:
        logger.warning("authorization denied: inactive user %s", record.firebase_uid)
        raise ApiError(403, "user_inactive", "El usuario está desactivado.")
    # Effective role = the lower of the token claim and the database copy. The copy changes the moment an admin
    # assigns a role, so a downgrade applies at once even to tokens still alive (revocation is asynchronous
    # and can fail); an upgrade applies when the user's token refreshes.
    return CurrentUser(
        uid=record.firebase_uid,
        email=record.email,
        display_name=record.display_name,
        role=identity.role.capped_by(record.role),
    )


def require_role(minimum: Role) -> Callable[[CurrentUser], CurrentUser]:
    """Dependency factory: 401 without a valid token, 403 when the role is below ``minimum``."""

    def dependency(user: Annotated[CurrentUser, Depends(get_current_user)]) -> CurrentUser:
        if not user.role.at_least(minimum):
            logger.warning(
                "authorization denied: user %s with role %s needs %s", user.uid, user.role.value, minimum.value
            )
            raise ApiError(
                403,
                "forbidden",
                "No tienes permisos para esta acción.",
                [ErrorDetail(field="role", issue=f"requires_{minimum.value}")],
            )
        return user

    return dependency
