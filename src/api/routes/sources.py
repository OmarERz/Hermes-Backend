"""Sources: list, add an own feed, switch on or off and change the level (docs/13 §8, FRO-16, D-041).

The rules live in `core.ingestion.sources` (structural sources stay on, new feeds enter as N4, only an admin changes
a level, every change is audited); the role table only sets the lowest role that may call each route.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Request
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from api.errors import ApiError, ErrorDetail
from api.pagination import PAGINATED_RESPONSES, Page, PageQuery, Signer, paginate
from api.routes._auth import guard
from api.routes._config_support import CurrentUserDep, app_user_id, to_api_error
from api.routes._db import SessionDep
from api.routes._paths import UuidAliasId
from api.routes.models import Source, SourceCreate, SourcePatch
from core.configuration.errors import ConfigError, check_text
from core.db import models as m
from core.ingestion.source_info import source_info
from core.ingestion.sources import (
    RESERVED_CODES,
    NewSource,
    SourceConflictError,
    SourceNotFoundError,
    SourcePermissionError,
    SourceRuleError,
    add_custom_source,
    set_source_enabled,
    set_trust_tier,
)
from core.ingestion.ssrf import system_resolver

router = APIRouter(tags=["sources and inventory"])
SourceId = UuidAliasId
SOURCE_TYPES = {"N1": "official", "N2": "research", "N3": "media", "N4": "feed"}
FAILING_AFTER = 3
MIN_CODE = 2


def _source_model(session: Session, source: m.Source) -> Source:
    """A source as the front shows it: health from consecutive failures, last capture from the last good read."""
    health_row = session.execute(
        text("SELECT last_ok_at, consecutive_failures FROM source_health WHERE source_id = :id"), {"id": source.id}
    ).first()
    last_ok, failures = (health_row[0], int(health_row[1])) if health_row else (None, 0)
    items = session.scalar(
        select(m.SourceFetch.items_new)
        .where(m.SourceFetch.source_id == source.id)
        .order_by(m.SourceFetch.started_at.desc(), m.SourceFetch.id.desc())
        .limit(1)
    )
    health = "ok" if failures == 0 else "failing" if failures >= FAILING_AFTER else "degraded"
    info = source_info(source.code)  # own feeds never take a factory code (RESERVED_CODES)
    return Source.model_validate(
        {
            "id": str(source.id),
            "name": source.name,
            "type": "official" if source.is_structural else SOURCE_TYPES[source.trust_tier],
            "level": source.trust_tier,
            "structural": source.is_structural,
            "active": source.enabled,
            "last_capture": last_ok.isoformat().replace("+00:00", "Z") if last_ok else None,
            "items_per_run": items or 0,
            "health": health,
            "description": info.description,
            "provider": info.provider,
            "refresh_interval_minutes": info.refresh_interval_minutes,
        }
    )


def _source_error(error: SourceRuleError) -> ApiError:
    if isinstance(error, SourcePermissionError):
        return ApiError(403, "forbidden", str(error), [ErrorDetail(field="body", issue="requires_role")])
    if isinstance(error, SourceNotFoundError):
        return ApiError(404, "not_found", "La fuente no existe.")
    if isinstance(error, SourceConflictError):
        return ApiError(409, "structural_source", "Las fuentes estructurales no se pueden desactivar.")
    return ApiError(422, "validation_error", str(error), [ErrorDetail(field="body", issue="source_rule")])


def _slug(name: str, taken: set[str]) -> str:
    base = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")[:30] or "feed"
    code, number = base, 1
    while code in taken or len(code) < MIN_CODE:
        number += 1
        code = f"{base}_{number}"
    return code


@router.get("/api/sources", dependencies=[guard("GET", "/api/sources")], responses=PAGINATED_RESPONSES)
def list_sources(params: PageQuery, signer: Signer, session: SessionDep) -> Page[Source]:
    rows = session.scalars(select(m.Source).order_by(m.Source.is_structural.desc(), m.Source.code))
    return paginate([_source_model(session, row) for row in rows], params, signer)


@router.post("/api/sources", status_code=201, dependencies=[guard("POST", "/api/sources")])
def create_source(source: SourceCreate, request: Request, session: SessionDep, user: CurrentUserDep) -> Source:
    """Own feeds enter as N4 and inactive until an analyst switches them on (D-041); the change is audited."""
    try:
        check_text("body", source.name, source.url)
    except ConfigError as error:
        raise to_api_error(error) from None
    taken = set(session.scalars(select(m.Source.code))) | RESERVED_CODES
    new = NewSource(_slug(source.name, taken), source.name, source.kind, source.url, enabled=False)
    resolver = getattr(request.app.state, "source_resolver", system_resolver)
    try:
        created = add_custom_source(session, new, app_user_id(session, user), datetime.now(UTC), resolver)
    except SourceRuleError as error:
        session.rollback()
        raise _source_error(error) from None
    return _source_model(session, created)


@router.patch("/api/sources/{id}", dependencies=[guard("PATCH", "/api/sources/{id}")])
def patch_source(source_id: SourceId, patch: SourcePatch, session: SessionDep, user: CurrentUserDep) -> Source:
    """Analysts switch a source on or off; only an admin changes its level (D-041); structural ones stay on."""
    try:
        identifier = uuid.UUID(source_id)
    except ValueError:
        raise ApiError(404, "not_found", "La fuente no existe.") from None
    actor, now = app_user_id(session, user), datetime.now(UTC)
    current = session.get(m.Source, identifier)
    if current is None:
        raise ApiError(404, "not_found", "La fuente no existe.")
    if patch.active is False and current.is_structural:  # refused before any other field of the same request is applied
        raise _source_error(SourceConflictError("Las fuentes estructurales no se pueden apagar"))
    try:
        if patch.level is not None:
            set_trust_tier(session, identifier, patch.level, actor, now)
        if patch.active is not None:
            set_source_enabled(session, identifier, patch.active, actor, now)
    except SourceRuleError as error:
        session.rollback()
        raise _source_error(error) from None
    row = session.get(m.Source, identifier)
    if row is None:
        raise ApiError(404, "not_found", "La fuente no existe.")
    return _source_model(session, row)
