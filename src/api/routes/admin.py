"""Connections, first-run setup wizard, audit trail (docs/13 §9, API-06), user list and error queue (D-088, F18.2).
Admin only (ROUTE_ROLES)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Final, cast

from fastapi import APIRouter, Depends, Path, Query, Request

from api.auth import Role, user_list
from api.auth.identity import AuthUnavailableError
from api.auth.user_list import UserLister
from api.errors import ApiError, ErrorResponse
from api.pagination import PAGINATED_RESPONSES, Page, PageQuery, Signer, decode_key, encode_key
from api.routes._auth import guard
from api.routes._config_support import CurrentUserDep, app_user_id, now
from api.routes._db import SessionDep
from api.routes.models import (
    AuditEntry,
    AuditFilters,
    ConnectionStatus,
    ConnectionTestRequest,
    ErrorKind,
    ErrorQueueFilters,
    ErrorQueueItem,
    ErrorStatus,
    RoleName,
    SetupStep,
    SetupStepUpdate,
    UserAccount,
    filter_ticket_id,
    parse_moment,
)
from core.connections.checker import ConnectionChecker, ConnectionState
from core.connections.messages import connection_text, output_language
from core.connections.probes import NAMES
from core.operations import audit as audit_trail
from core.operations import setup
from core.views import error_queue
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
    return [_setup_step(s) for s in setup.setup_status(session, _all_ok(checker), output_language(session))]


@router.put("/api/setup/steps/{n}", dependencies=[guard("PUT", "/api/setup/steps/{n}")])
def setup_step(
    n: Annotated[int, Path(ge=0, le=99)],  # an unknown step inside the range still answers 404
    update: SetupStepUpdate,
    session: SessionDep,
    checker: Checker,
    user: CurrentUserDep,
) -> SetupStep:
    """Marks a step done or skipped (skipping wins); the mark is audited. The wizard never stores a key."""
    mark = setup.Mark(done=update.done, skipped=update.skipped, actor=app_user_id(session, user), at=now())
    step = setup.mark_step(session, n, mark, connections_ok=_all_ok(checker), language=output_language(session))
    if step is None:
        raise ApiError(404, "not_found", "El paso del asistente no existe.")
    session.commit()
    return _setup_step(step)


def _setup_step(step: setup.SetupStep) -> SetupStep:
    return SetupStep(n=step.n, name=step.name, done=step.done, skipped=step.skipped, done_source=step.done_source)


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
            date_from=parse_moment(filters.date_from),
            date_to=parse_moment(filters.date_to),
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


# --- users and error queue (D-088, F18.2) ------------------------------------------------------------------------
USERS_UNAVAILABLE: Final[dict[int | str, dict[str, Any]]] = {
    **PAGINATED_RESPONSES,
    503: {"model": ErrorResponse, "description": "Firebase no respondió (code: auth_unavailable)"},
}


def get_user_lister(request: Request) -> UserLister | None:
    lister: UserLister | None = request.app.state.user_lister
    return lister


Lister = Annotated[UserLister | None, Depends(get_user_lister)]


def _role(role: Role | None) -> RoleName | None:
    return None if role is None else role.value


@router.get("/api/admin/users", dependencies=[guard("GET", "/api/admin/users")], responses=USERS_UNAVAILABLE)
def list_users(params: PageQuery, signer: Signer, session: SessionDep, lister: Lister) -> Page[UserAccount]:
    """Every account, signed in or not, with its stored role (sent back as `expected_role`), its Firebase claim and
    the effective role a request would get now (D-030), ordered by e-mail. The cursor is the position in that order:
    an account added or removed between two pages shifts the next one by that much."""
    key = decode_key(params, "users", ("int",))
    if lister is None:
        raise ApiError(503, "auth_unavailable", "No se pudo leer el directorio de usuarios. Intenta de nuevo.")
    try:
        directory = lister.list_users()
    except AuthUnavailableError as exc:
        raise ApiError(503, "auth_unavailable", "No se pudo leer el directorio de usuarios. Intenta de nuevo.") from exc
    views = user_list.merge_users(user_list.stored_users(session), directory)
    page, next_offset = user_list.page_at(views, 0 if key is None else int(key[0]), params.limit)
    return Page[UserAccount](
        items=[
            UserAccount(
                uid=v.uid,
                email=v.email,
                display_name=v.display_name,
                role=_role(v.role),
                claim_role=_role(v.claim_role),
                effective_role=_role(v.effective_role),
                active=v.active,
                signed_in=v.signed_in,
                last_login_at=_iso(v.last_login_at),
            )
            for v in page
        ],
        next_cursor=None if next_offset is None else encode_key(signer, "users", (next_offset,)),
    )


@router.get("/api/error-queue", dependencies=[guard("GET", "/api/error-queue")], responses=PAGINATED_RESPONSES)
def list_error_queue(
    params: PageQuery, signer: Signer, session: SessionDep, filters: Annotated[ErrorQueueFilters, Query()]
) -> Page[ErrorQueueItem]:
    """What failed and waits for a person (FRO-18), newest first: notification events and iTop writes that exhausted
    their retries, and the items an analyst or the judge could not validate."""
    key = decode_key(params, "error_queue", ("time", "uuid"))
    found, next_key = error_queue.list_errors(
        session, filters.kind, after=None if key is None else (key[0], key[1]), limit=params.limit
    )
    return Page[ErrorQueueItem](
        items=[
            ErrorQueueItem(
                id=str(e.id),
                kind=cast(ErrorKind, e.kind),
                created_at=iso(e.created_at),
                status=cast(ErrorStatus, e.status),
                attempts=e.attempts,
                next_attempt_at=_iso(e.next_attempt_at),
                error=e.error,
                component=e.component,
                cve=e.cve,
                ticket_itop_id=filter_ticket_id(e.ticket_itop_id),
                ticket_ref=e.ticket_ref,
                assessment_id=str(e.assessment_id) if e.assessment_id else None,
                retryable=e.retryable,
            )
            for e in found
        ],
        next_cursor=encode_key(signer, "error_queue", next_key),
    )
