"""Connections, first-run setup wizard and audit trail (docs/13 §9, API-06). Admin only (ROUTE_ROLES)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, cast

from fastapi import APIRouter, Depends, Query, Request

from api.errors import ApiError
from api.pagination import PAGINATED_RESPONSES, Page, PageQuery, Signer, decode_key, encode_key
from api.routes._auth import guard
from api.routes._config_support import CurrentUserDep, app_user_id, now
from api.routes._db import SessionDep
from api.routes.models import (
    AuditEntry,
    AuditFilters,
    ConnectionStatus,
    ConnectionTestRequest,
    SetupStep,
    SetupStepUpdate,
)
from core.connections.checker import ConnectionChecker, ConnectionState
from core.connections.messages import connection_text, output_language
from core.connections.probes import NAMES
from core.operations import audit as audit_trail
from core.operations import setup
from core.views.common import iso

router = APIRouter(tags=["operations"])


def get_checker(request: Request) -> ConnectionChecker:
    checker: ConnectionChecker = request.app.state.connections
    return checker


Checker = Annotated[ConnectionChecker, Depends(get_checker)]


def _iso(moment: datetime | None) -> str | None:
    return None if moment is None else iso(moment)


def _status(state: ConnectionState, language: str) -> ConnectionStatus:
    return ConnectionStatus(
        name=state.name,
        ok=state.ok,
        latency_ms=state.latency_ms,
        missing_variable=state.missing_variable,
        message=connection_text(state.message, state.missing_variable, language),
        checked_at=_iso(state.checked_at),
        last_ok_at=_iso(state.last_ok_at),
    )


def _all_ok(checker: ConnectionChecker) -> bool:
    known = checker.cached()
    return set(known) == set(NAMES) and all(s.ok for s in known.values())


@router.get("/api/connections/status", dependencies=[guard("GET", "/api/connections/status")])
def connections_status(checker: Checker, session: SessionDep) -> list[ConnectionStatus]:
    """iTop, DeepSeek, NVD, abuse.ch, ransomware.live and Firebase: configured or not, latency and a generic message.

    Results are reused for 5 minutes, so this route does not spend quota. Never includes a key, not even a partial
    one, nor the body of an error (SEG-23).
    """
    language = output_language(session)
    return [_status(s, language) for s in checker.status()]


@router.post("/api/connections/test", dependencies=[guard("POST", "/api/connections/test")])
def connections_test(request: ConnectionTestRequest, checker: Checker, session: SessionDep) -> list[ConnectionStatus]:
    """Checks again ("Probar de nuevo"); a service checked in the last 30 seconds keeps its result."""
    language = output_language(session)
    return [_status(s, language) for s in checker.test(request.names)]


@router.get("/api/setup/status", dependencies=[guard("GET", "/api/setup/status")])
def setup_status(session: SessionDep, checker: Checker) -> list[SetupStep]:
    """The seven steps of the first-run wizard (D-042). A step is done when the data shows it or an admin marked
    it; step 1 uses the last connection checks without running new ones."""
    return [
        SetupStep(n=s.n, name=s.name, done=s.done, skipped=s.skipped)
        for s in setup.setup_status(session, _all_ok(checker), output_language(session))
    ]


@router.put("/api/setup/steps/{n}", dependencies=[guard("PUT", "/api/setup/steps/{n}")])
def setup_step(
    n: int, update: SetupStepUpdate, session: SessionDep, checker: Checker, user: CurrentUserDep
) -> SetupStep:
    """Marks a step done or skipped (skipping wins); the mark is audited. The wizard never stores a key."""
    mark = setup.Mark(done=update.done, skipped=update.skipped, actor=app_user_id(session, user), at=now())
    step = setup.mark_step(session, n, mark, connections_ok=_all_ok(checker), language=output_language(session))
    if step is None:
        raise ApiError(404, "not_found", "El paso del asistente no existe.")
    session.commit()
    return SetupStep(n=step.n, name=step.name, done=step.done, skipped=step.skipped)


@router.get("/api/audit", dependencies=[guard("GET", "/api/audit")], responses=PAGINATED_RESPONSES)
def audit(
    params: PageQuery, signer: Signer, session: SessionDep, filters: Annotated[AuditFilters, Query()]
) -> Page[AuditEntry]:
    """Changes made from the front and by the system, newest first. Never shows the values changed."""
    key = decode_key(params, "audit", ("time", "uuid"))
    if any(value is not None and "\x00" in value for value in (filters.actor, filters.action)):
        return Page[AuditEntry](items=[], next_cursor=None)  # PostgreSQL text cannot hold it: nothing matches
    rows, next_key = audit_trail.list_audit(
        session,
        audit_trail.AuditFilters(
            actor=filters.actor,
            action=filters.action,
            date_from=datetime.fromisoformat(filters.date_from.upper()) if filters.date_from else None,
            date_to=datetime.fromisoformat(filters.date_to.upper()) if filters.date_to else None,
        ),
        after=None if key is None else (cast(datetime, key[0]), key[1]),
        limit=params.limit,
    )
    return Page[AuditEntry](
        items=[
            AuditEntry(id=str(r.id), created_at=iso(r.created_at), actor=r.actor, action=r.action, target=r.target)
            for r in rows
        ],
        next_cursor=encode_key(signer, "audit", next_key),
    )
