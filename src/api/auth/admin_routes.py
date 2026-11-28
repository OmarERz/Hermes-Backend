"""Admin user routes (docs/13 API-06, D-105): the role of an account (``PUT /api/admin/users/{uid}/role``), accounts
created from the app with the e-mail to choose a password (``POST /api/admin/users`` and
``POST /api/admin/users/{uid}/password-email``) and switching an account off or on (``PUT
/api/admin/users/{uid}/status``). Admin only and audited; Hermes never sees a password or the e-mail's link."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Request
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sqlalchemy.exc import SQLAlchemyError

from api.auth.accounts import (
    AccountInfo,
    AccountManager,
    EmailInUseError,
    EmailQuota,
    InvalidEmailError,
    PasswordEmailError,
    UidInUseError,
    new_uid,
)
from api.auth.dependencies import CurrentUser, require_role
from api.auth.directory import (
    AccountDirectory,
    AccountDisabledError,
    AccountRequest,
    RoleConflictError,
    UserConflictError,
    UserDirectory,
)
from api.auth.identity import AuthUnavailableError
from api.auth.role_admin import RevocationPendingError, RoleManager, UnknownUserError
from api.auth.roles import Role
from api.errors import ApiError, ErrorDetail, ErrorResponse

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


# --- accounts an admin creates and switches off or on (D-105, F18.8) ---------------------------------------------

# A conservative e-mail address: ASCII local part (RFC 5322 atext and dots) and a domain of DNS labels with a TLD.
# Firebase checks it again; what it refuses is a 422 `invalid_email`.
EMAIL_PATTERN = (
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
FORBIDDEN = "No tienes permiso para realizar esta acción."
DISABLED_ACCOUNT = "La cuenta está desactivada: reactívala antes de enviar el correo."
TOO_MANY_EMAILS = "Se enviaron demasiados correos de acceso en la última hora. Intenta de nuevo más tarde."


class UserCreation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(max_length=254, pattern=EMAIL_PATTERN, description="Correo de la persona; será su usuario")
    role: Role


class UserCreated(BaseModel):
    uid: str
    email: str
    role: Role
    password_email_sent: bool


class PasswordEmailSent(BaseModel):
    uid: str
    email: str


class StatusChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    disabled: StrictBool


class StatusChanged(BaseModel):
    uid: str
    disabled: bool
    sessions_revoked: bool
    known_user: bool


def _accounts(request: Request) -> AccountManager:
    manager: AccountManager | None = request.app.state.account_manager
    if manager is None:  # a test app with a fake verifier and no account manager
        raise ApiError(503, "auth_unavailable", "No se pudo conectar con Firebase. Intenta de nuevo.")
    return manager


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _take_email(request: Request, admin: CurrentUser) -> None:
    quota: EmailQuota = request.app.state.email_quota
    if not quota.take(admin.uid):
        logger.warning("setup e-mail refused: user %s reached the hourly limit", admin.uid)
        raise ApiError(429, "too_many_emails", TOO_MANY_EMAILS)


def _email_new_account(request: Request, accounts: AccountManager, uid: str, email: str, admin: CurrentUser) -> bool:
    """The e-mail of an account just created; whether it went out."""
    directory: AccountDirectory = request.app.state.user_directory
    try:
        directory.authorize_password_email(uid, admin.uid)
    except (RoleConflictError, AccountDisabledError):
        # Demoted, or the account switched off, in the moment since it was created: it exists, without the e-mail.
        return False
    except SQLAlchemyError as exc:
        # The account and its copy are stored: answer 201 with the e-mail pending (resend it later), never a 500.
        logger.warning("setup e-mail not requested: user %s (%s)", uid, type(exc).__name__)
        return False
    return _send_password_email(request, accounts, uid, email, admin) is None


def _authorize_resend(directory: AccountDirectory, account: AccountInfo, admin: CurrentUser) -> None:
    """The checks of a resend: an account switched off in Firebase or in Hermes gets no e-mail, and the actor must still
    be an active admin (checked again under the directory's lock, which also audits the request)."""
    if account.disabled:
        raise ApiError(409, "user_disabled", DISABLED_ACCOUNT)
    try:
        directory.authorize_password_email(account.uid, admin.uid)
    except AccountDisabledError as exc:
        raise ApiError(409, "user_disabled", DISABLED_ACCOUNT) from exc
    except RoleConflictError as exc:
        raise ApiError(403, "forbidden", FORBIDDEN) from exc


def _send_password_email(
    request: Request, accounts: AccountManager, uid: str, email: str, admin: CurrentUser
) -> str | None:
    """Send the e-mail (``authorize_password_email`` allowed it and audited the request) and audit the outcome; returns
    the reason it was not sent, or None."""
    try:
        accounts.send_password_setup(email, _client_ip(request))
    except PasswordEmailError as exc:
        failure: str | None = exc.reason
    except AuthUnavailableError:
        failure = "auth_unavailable"
    else:
        failure = None
    directory: AccountDirectory = request.app.state.user_directory
    try:
        directory.audit_password_email(uid, admin.uid, failure)
    except SQLAlchemyError as exc:
        # The request row is already stored: an e-mail that went out is not turned into an error (a retry would send
        # another one); only the outcome row is missing.
        logger.warning("setup e-mail outcome not audited: user %s (%s)", uid, type(exc).__name__)
    if failure is None:
        logger.info("setup e-mail sent: user %s by %s", uid, admin.uid)
    return failure


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

    _add_account_routes(router)
    _add_status_route(router)
    return router


def _add_account_routes(router: APIRouter) -> None:
    """Accounts created from the app and the e-mail to choose a password (D-105)."""

    @router.post(
        "/users",
        status_code=201,
        responses={
            401: {"model": ErrorResponse, "description": "Missing, invalid, expired or revoked token"},
            403: {"model": ErrorResponse, "description": "Not an admin, or inactive user"},
            409: {"model": ErrorResponse, "description": "The e-mail already has an account (`email_exists`)"},
            422: {
                "model": ErrorResponse,
                "description": "Invalid body, or an e-mail Firebase refuses (`invalid_email`)",
            },
            429: {"model": ErrorResponse, "description": "Too many password e-mails this hour (`too_many_emails`)"},
            503: {"model": ErrorResponse, "description": "Identity provider unavailable"},
        },
    )
    def create_user(
        request: Request,
        body: UserCreation,
        admin: Annotated[CurrentUser, Depends(require_role(Role.ADMIN))],
    ) -> UserCreated:
        """Create an account without a password; Firebase e-mails the person a link to choose one (D-105)."""
        accounts = _accounts(request)
        _take_email(request, admin)
        directory: AccountDirectory = request.app.state.user_directory
        uid = new_uid()
        wanted = AccountRequest(uid=uid, email=body.email, role=body.role)
        try:
            record = directory.create_account(
                wanted, admin.uid, lambda: accounts.create(uid, body.email, body.role), accounts.discard
            )
        except (EmailInUseError, UserConflictError) as exc:
            raise ApiError(409, "email_exists", "Ya existe una cuenta con ese correo.") from exc
        except InvalidEmailError as exc:
            detail = ErrorDetail(field="body.email", issue="invalid_email")
            raise ApiError(422, "invalid_email", "Firebase no aceptó ese correo.", [detail]) from exc
        except RoleConflictError as exc:
            raise ApiError(403, "forbidden", FORBIDDEN) from exc
        except (UidInUseError, AuthUnavailableError) as exc:
            raise ApiError(503, "auth_unavailable", "No se pudo crear la cuenta. Intenta de nuevo.") from exc
        logger.info("account created: user %s with role %s by %s", record.firebase_uid, record.role.value, admin.uid)
        sent = _email_new_account(request, accounts, record.firebase_uid, record.email, admin)
        return UserCreated(uid=record.firebase_uid, email=record.email, role=record.role, password_email_sent=sent)

    @router.post(
        "/users/{uid}/password-email",
        responses={
            401: {"model": ErrorResponse, "description": "Missing, invalid, expired or revoked token"},
            403: {"model": ErrorResponse, "description": "Not an admin, or inactive user"},
            404: {"model": ErrorResponse, "description": "The uid does not exist in Firebase"},
            409: {
                "model": ErrorResponse,
                "description": "The account is switched off (`user_disabled`) or has no e-mail (`no_email`)",
            },
            422: {"model": ErrorResponse, "description": "Invalid uid"},
            429: {"model": ErrorResponse, "description": "Too many password e-mails this hour (`too_many_emails`)"},
            503: {
                "model": ErrorResponse,
                "description": "Identity provider unavailable, or the e-mail was not sent (`email_unavailable`)",
            },
        },
    )
    def send_password_email(
        request: Request,
        uid: Annotated[str, Path(pattern=UID_PATTERN)],
        admin: Annotated[CurrentUser, Depends(require_role(Role.ADMIN))],
    ) -> PasswordEmailSent:
        """Have Firebase send the e-mail to choose a password again (its link lasts an hour, or it did not go out)."""
        accounts = _accounts(request)
        try:
            account = accounts.lookup(uid)
        except UnknownUserError as exc:
            raise ApiError(404, "user_not_found", "El usuario no existe en Firebase.") from exc
        except AuthUnavailableError as exc:
            raise ApiError(503, "auth_unavailable", "No se pudo leer la cuenta. Intenta de nuevo.") from exc
        if not account.email:
            raise ApiError(409, "no_email", "La cuenta no tiene correo.")
        _take_email(request, admin)
        _authorize_resend(request.app.state.user_directory, account, admin)
        if _send_password_email(request, accounts, uid, account.email, admin) is not None:
            raise ApiError(503, "email_unavailable", "No se pudo enviar el correo. Intenta de nuevo más tarde.")
        return PasswordEmailSent(uid=uid, email=account.email)


def _add_status_route(router: APIRouter) -> None:
    """Switching an account off or on (D-105)."""

    @router.put(
        "/users/{uid}/status",
        responses={
            401: {"model": ErrorResponse, "description": "Missing, invalid, expired or revoked token"},
            403: {"model": ErrorResponse, "description": "Not an admin, or inactive user"},
            404: {"model": ErrorResponse, "description": "The uid does not exist in Firebase"},
            409: {
                "model": ErrorResponse,
                "description": "Own account (`own_status`) or the last active admin (`last_admin`)",
            },
            422: {"model": ErrorResponse, "description": "Invalid uid or body"},
            503: {"model": ErrorResponse, "description": "Identity provider unavailable"},
        },
    )
    def set_user_status(
        request: Request,
        uid: Annotated[str, Path(pattern=UID_PATTERN)],
        body: StatusChange,
        admin: Annotated[CurrentUser, Depends(require_role(Role.ADMIN))],
    ) -> StatusChanged:
        """Switch an account off (its sessions are revoked) or back on, in Firebase and in Hermes (D-105)."""
        if uid == admin.uid:
            # An admin never locks themselves out by mistake (nor switches their own account on: it is on).
            raise ApiError(409, "own_status", "No puedes desactivar ni reactivar tu propia cuenta.")
        accounts = _accounts(request)
        directory: AccountDirectory = request.app.state.user_directory
        outcome = {"revoked": False}

        def apply(on_in_hermes: bool) -> bool:
            outcome["revoked"] = accounts.set_disabled(uid, body.disabled, on_in_hermes)
            return outcome["revoked"]

        try:
            record = directory.change_status(uid, body.disabled, admin.uid, apply)
        except UnknownUserError as exc:
            raise ApiError(404, "user_not_found", "El usuario no existe en Firebase.") from exc
        except RoleConflictError as exc:
            if exc.code == "last_admin":
                raise ApiError(409, "last_admin", "No puede quedar el sistema sin un administrador activo.") from exc
            raise ApiError(403, "forbidden", FORBIDDEN) from exc
        except AuthUnavailableError as exc:
            raise ApiError(
                503, "auth_unavailable", "No se pudo cambiar el estado de la cuenta. Intenta de nuevo."
            ) from exc
        logger.info("account %s: user %s by %s", "disabled" if body.disabled else "enabled", uid, admin.uid)
        return StatusChanged(
            uid=uid, disabled=body.disabled, sessions_revoked=outcome["revoked"], known_user=record is not None
        )
