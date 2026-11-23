"""Admin user routes (docs/13 API-06): ``PUT /api/admin/users/{uid}/role``."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Request
from pydantic import BaseModel, ConfigDict, Field

from api.auth.dependencies import CurrentUser, require_role
from api.auth.directory import RoleConflictError, UserDirectory
from api.auth.identity import AuthUnavailableError
from api.auth.role_admin import RevocationPendingError, RoleManager, UnknownUserError
from api.auth.roles import Role
from api.errors import ApiError, ErrorResponse

logger = logging.getLogger(__name__)

# Any Firebase uid (1 to 128 characters) that fits in one path segment: no slash, no control characters.
UID_PATTERN = r"^[^/\x00-\x1f\x7f]{1,128}$"


class RoleAssignment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Role
    expected_role: Role | None = Field(
        default=None, description="Role the admin read; 409 `role_changed` if it changed since (API-03)"
    )


class RoleAssigned(BaseModel):
    uid: str
    role: Role
    sessions_revoked: bool
    known_user: bool


def build_admin_router() -> APIRouter:
    router = APIRouter(prefix="/api/admin", tags=["admin"])

    @router.put(
        "/users/{uid}/role",
        responses={
            401: {"model": ErrorResponse, "description": "Missing, invalid, expired or revoked token"},
            403: {"model": ErrorResponse, "description": "Not an admin, or inactive user"},
            404: {"model": ErrorResponse, "description": "The uid does not exist in Firebase"},
            409: {
                "model": ErrorResponse,
                "description": "Own role, the last active admin (`last_admin`) or a stale `expected_role` "
                "(`role_changed`)",
            },
            422: {"model": ErrorResponse, "description": "Invalid uid or body"},
            503: {"model": ErrorResponse, "description": "Identity provider unavailable"},
        },
    )
    def assign_role(
        request: Request,
        uid: Annotated[str, Path(pattern=UID_PATTERN)],
        body: RoleAssignment,
        admin: Annotated[CurrentUser, Depends(require_role(Role.ADMIN))],
    ) -> RoleAssigned:
        """Assign a role as a Firebase custom claim, revoke the user's sessions and audit the change (D-030)."""
        if uid == admin.uid:
            # Keeps at least the acting admin in place: an admin never demotes themselves by mistake.
            raise ApiError(409, "own_role", "No puedes cambiar tu propio rol.")
        manager: RoleManager = request.app.state.role_manager
        directory: UserDirectory = request.app.state.user_directory
        outcome = {"revoked": True}

        def apply() -> bool:
            try:
                manager.assign(uid, body.role)
            except RevocationPendingError:
                # The claim changed; the database copy limits the role until the old tokens expire.
                logger.warning("role assigned to %s but its sessions could not be revoked", uid)
                outcome["revoked"] = False
            return outcome["revoked"]

        try:
            record = directory.change_role(uid, body.role, admin.uid, apply, body.expected_role)
        except UnknownUserError as exc:
            raise ApiError(404, "user_not_found", "El usuario no existe en Firebase.") from exc
        except RoleConflictError as exc:
            if exc.code == "actor_not_admin":
                raise ApiError(403, "forbidden", "No tienes permiso para realizar esta acción.") from exc
            if exc.code == "last_admin":
                raise ApiError(409, "last_admin", "No puede quedar el sistema sin un administrador activo.") from exc
            raise ApiError(
                409, "role_changed", "El rol cambió desde que lo leíste (o no se puede comprobar); vuelve a cargarlo."
            ) from exc
        except AuthUnavailableError as exc:
            raise ApiError(503, "auth_unavailable", "No se pudo asignar el rol. Intenta de nuevo.") from exc
        logger.info("role assigned: user %s -> %s by %s", uid, body.role.value, admin.uid)
        return RoleAssigned(uid=uid, role=body.role, sessions_revoked=outcome["revoked"], known_user=record is not None)

    return router
