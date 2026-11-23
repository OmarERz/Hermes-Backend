"""Shared pieces of the configuration, profile and source routes: the acting user and the error mapping."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.auth import CurrentUser, get_current_user
from api.errors import ApiError, ErrorDetail
from core.configuration.errors import (
    ConfigError,
    ConflictError,
    ForbiddenParameterError,
    NotFoundError,
    ValidationFailedError,
    VersionConflictError,
)
from core.db.models import AppUser

CurrentUserDep = Annotated[CurrentUser, Depends(get_current_user)]


def app_user_id(session: Session, user: CurrentUser) -> uuid.UUID | None:
    """The `app_user` row of the signed-in user (None only if they never completed a login sync)."""
    return session.scalar(select(AppUser.id).where(AppUser.firebase_uid == user.uid))


def now() -> datetime:
    return datetime.now(UTC)


def to_api_error(error: ConfigError) -> ApiError:
    """Map a configuration error to the error envelope (code, status, Spanish message, field details)."""
    details = [ErrorDetail(field=p.field, issue=p.issue) for p in error.problems]
    if isinstance(error, VersionConflictError):
        return ApiError(409, "version_conflict", error.message, details)
    if isinstance(error, ValidationFailedError):
        return ApiError(422, "validation_error", error.message, details)
    if isinstance(error, ForbiddenParameterError):
        return ApiError(403, "forbidden", error.message, details)
    if isinstance(error, NotFoundError):
        return ApiError(404, "not_found", error.message, details)
    if isinstance(error, ConflictError):
        return ApiError(409, "conflict", error.message, details)
    return ApiError(400, "bad_request", error.message, details)
