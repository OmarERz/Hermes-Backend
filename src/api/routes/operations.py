"""Runs, STIX export, calibration, metrics and notification events (docs/13 §8). Connections, setup and audit live
in `admin`."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from api.auth import CurrentUser
from api.errors import ApiError, ErrorDetail
from api.pagination import PAGINATED_RESPONSES, Page, PageQuery, Signer, decode_key, encode_key, paginate
from api.routes._auth import guard
from api.routes._config_support import CurrentUserDep, app_user_id, now, to_api_error
from api.routes._db import SessionDep
from api.routes._events import Events
from api.routes._paths import UuidAliasId, UuidId
from api.routes._runs import Runs
from api.routes._state import MetricsSource
from api.routes.models import (
    CalibrationProposal,
    Metric,
    MetricsDashboard,
    NotificationEventRow,
    Run,
    RunFilters,
    ScanRequest,
    StixBundle,
    StixExportRequest,
)
from core.calibration import proposals as calibration
from core.configuration.errors import ConfigError
from core.db import models as m
from core.db.models import AppUser, AuditLog
from core.stix.export import ExportOptions, ExportScope, StixExportError, export_bundle

router = APIRouter(tags=["operations"])
PROGRESS_ES = {"queued": "En cola", "running": "En curso", "succeeded": "Terminado", "failed": "Falló"}

# Schema of one parsed event: `event` is the event name and `data` a JSON text {run_id, progress, status, message}.
# `contentSchema` (JSON Schema 2020-12, OpenAPI 3.1) describes the object inside that text (F18.6).
SSE_EVENT_DATA_SCHEMA = {
    "type": "object",
    "properties": {
        "run_id": {"type": "string", "description": "Id (UUID) de la corrida."},
        "progress": {"type": "integer", "minimum": 0, "maximum": 100, "description": "Avance de 0 a 100."},
        "status": {
            "type": "string",
            "enum": ["queued", "running", "succeeded", "failed"],
            "description": "Estado de la corrida, el mismo de `GET /api/runs/{id}`; `succeeded` y `failed` son "
            "finales y cierran el flujo.",
        },
        "message": {"type": "string", "description": "El estado para la persona, en español."},
    },
    "required": ["run_id", "progress", "status", "message"],
}
SSE_EVENT_SCHEMA = {
    "type": "object",
    "properties": {
        "event": {"type": "string", "enum": ["progress"], "description": "Nombre del evento: siempre `progress`."},
        "data": {
            "type": "string",
            "contentMediaType": "application/json",
            "contentSchema": SSE_EVENT_DATA_SCHEMA,
            "description": "Texto JSON con `run_id`, `progress` (0 a 100), `status` (`queued`, `running`, "
            "`succeeded` o `failed`) y `message` (el estado en español). El flujo termina después del evento con "
            "estado final (`succeeded` o `failed`).",
        },
    },
    "required": ["event", "data"],
}


@router.post("/api/scans", status_code=202, dependencies=[guard("POST", "/api/scans")])
def launch_scan(_request: ScanRequest, runs: Runs, user: CurrentUserDep) -> Run:
    """Queues a simulated scan; the worker runs it on this run row and its progress streams from the run events
    (FRO-19). The run shows up in GET /api/runs."""
    return runs.queue_scan(user.uid)


@router.get("/api/runs", dependencies=[guard("GET", "/api/runs")], responses=PAGINATED_RESPONSES)
def list_runs(params: PageQuery, signer: Signer, runs: Runs, filters: Annotated[RunFilters, Query()]) -> Page[Run]:
    """Scans, news runs and recalculations: those not started yet first, then the newest (ARQ-04). Optional filters
    by kind, status and start date (HI-2); each run says why and by whom it was launched (HI-10)."""
    key = decode_key(params, "runs", ("int", "time", "str"))
    items, next_key = runs.page(None if key is None else (key[0], key[1], key[2]), params.limit, filters)
    return Page[Run](items=items, next_cursor=encode_key(signer, "runs", next_key))


@router.get("/api/runs/{id}", dependencies=[guard("GET", "/api/runs/{id}")])
def get_run(id: UuidId, runs: Runs) -> Run:  # noqa: A002 - path parameter name of API-06
    """One run as the list shows it, with its current state (the final one once it ends), why it was launched and
    by whom (F18.6): the frontend reads it by id instead of searching the list."""
    return runs.get(id)


@router.get(
    "/api/runs/{id}/events",
    dependencies=[guard("GET", "/api/runs/{id}/events")],
    response_class=StreamingResponse,
    responses={
        200: {"content": {"text/event-stream": {"schema": SSE_EVENT_SCHEMA}}, "description": "Server-sent events"}
    },
)
def run_events(id: UuidId, runs: Runs) -> StreamingResponse:  # noqa: A002 - path parameter name of API-06
    """Progress of a run until it ends (ARQ-05): one event each time its status or progress changes."""
    snapshots = runs.progress(id)

    def stream() -> Iterator[str]:
        for run in snapshots:
            data = json.dumps(
                {"run_id": run.id, "progress": run.progress, "status": run.status, "message": PROGRESS_ES[run.status]},
                ensure_ascii=False,
            )
            yield f"event: progress\ndata: {data}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream")


_STIX_GUARD = guard("POST", "/api/stix/export")


@router.post("/api/stix/export")
def stix_export(
    request: StixExportRequest, session: SessionDep, user: Annotated[CurrentUser, _STIX_GUARD]
) -> StixBundle:
    """Exports a STIX 2.1 bundle with TLP marking (STX-03, STX-06). The scope needs its identifier or range."""
    missing = {
        "vulnerability": request.vulnerability_id is None,
        "run": request.run_id is None,
        "date_range": request.date_from is None or request.date_to is None,
    }[request.scope]
    if missing:
        raise ApiError(
            422,
            "validation_error",
            "Faltan datos para el alcance de la exportación.",
            [ErrorDetail(field="body.scope", issue="missing_scope_data")],
        )
    scope = ExportScope(
        request.scope,
        vulnerability_id=request.vulnerability_id,
        run_id=request.run_id,
        date_from=request.date_from,
        date_to=request.date_to,
    )
    try:
        result = export_bundle(session, scope, ExportOptions(exclude_ultra_classified=request.exclude_ultra_classified))
    except StixExportError:
        raise ApiError(
            422,
            "validation_error",
            "No se pudo exportar con los datos del alcance.",
            [ErrorDetail(field="body.scope", issue="invalid_scope_data")],
        ) from None
    bundle = StixBundle.model_validate(result.bundle)
    # Who exported what leaves the system, and with which marking (ASVS V16; pendientes F1.5 #50).
    session.add(
        AuditLog(
            app_user_id=session.scalar(select(AppUser.id).where(AppUser.firebase_uid == user.uid)),
            action="stix_exported",
            entity_type="stix_bundle",
            entity_id=str(result.bundle.get("id", "")),
            before=None,
            after={
                "scope": request.scope,
                "vulnerability_id": request.vulnerability_id,
                "run_id": request.run_id,
                "date_from": request.date_from,
                "date_to": request.date_to,
                "exclude_ultra_classified": request.exclude_ultra_classified,
                "tlp": result.tlp,
                "objects": len(result.bundle.get("objects", [])),
            },
            created_at=datetime.now(UTC),
        )
    )
    session.commit()
    return bundle


KINDS: dict[str, Literal["source_level", "reason_threshold", "formula_weight"]] = {
    "weight": "formula_weight",
    "source_trust": "source_level",
    "reason_range": "reason_threshold",
    "new_reason": "reason_threshold",
}
STATUSES: dict[str, Literal["pending", "approved", "rejected"]] = {
    "proposed": "pending",
    "approved": "approved",
    "applied": "approved",
    "reverted": "approved",
    "rejected": "rejected",
    "discarded": "rejected",
}
ProposalId = UuidAliasId


def _proposal(row: m.CalibrationProposal) -> CalibrationProposal:
    return CalibrationProposal.model_validate(
        {
            "id": str(row.id),
            "created_at": row.created_at.isoformat().replace("+00:00", "Z"),
            "kind": KINDS[row.target_kind],
            "summary": calibration.describe(row),
            "status": STATUSES[row.status],
            "target_key": row.target_key,
            "previous_value": row.previous_value,
            "proposed_value": row.proposed_value,
            "evidence": row.evidence,
            "backtest": row.backtest,
            "decided_at": row.decided_at.isoformat().replace("+00:00", "Z") if row.decided_at else None,
        }
    )


@router.get(
    "/api/calibration/proposals",
    dependencies=[guard("GET", "/api/calibration/proposals")],
    responses=PAGINATED_RESPONSES,
)
def list_proposals(params: PageQuery, signer: Signer, session: SessionDep) -> Page[CalibrationProposal]:
    """Mode 4 proposals, newest first. They are only ever applied when an admin approves them (D-020)."""
    return paginate([_proposal(row) for row in calibration.list_proposals(session)], params, signer)


def _decide(
    session: SessionDep, user: CurrentUserDep, proposal_id: str, action: Literal["approve", "reject"]
) -> CalibrationProposal:
    who = calibration.Decider(app_user_id(session, user), now())
    try:
        row = (
            calibration.approve(session, proposal_id, who)
            if action == "approve"
            else calibration.reject(session, proposal_id, who)
        )
    except ConfigError as error:
        session.rollback()
        raise to_api_error(error) from None
    result = _proposal(row)
    session.commit()  # before answering: the client must not see a decision that was not saved
    return result


@router.post(
    "/api/calibration/proposals/{id}/approve", dependencies=[guard("POST", "/api/calibration/proposals/{id}/approve")]
)
def approve_proposal(proposal_id: ProposalId, session: SessionDep, user: CurrentUserDep) -> CalibrationProposal:
    """Applies the proposal as a new formula version or a source level change, audited; 409 if it went stale."""
    return _decide(session, user, proposal_id, "approve")


@router.post(
    "/api/calibration/proposals/{id}/reject", dependencies=[guard("POST", "/api/calibration/proposals/{id}/reject")]
)
def reject_proposal(proposal_id: ProposalId, session: SessionDep, user: CurrentUserDep) -> CalibrationProposal:
    return _decide(session, user, proposal_id, "reject")


@router.get("/api/metrics", dependencies=[guard("GET", "/api/metrics")])
def metrics(source: MetricsSource) -> MetricsDashboard:
    """Dashboards of docs/10 (FRO-21): the latest nightly value of each metric and the judge ladder level."""
    dashboard = source(datetime.now(UTC))
    return MetricsDashboard(
        generated_at=dashboard.generated_at.isoformat().replace("+00:00", "Z"),
        metrics=[
            Metric(
                key=m.key,
                label=m.label,
                value=m.value,
                unit=m.unit,
                as_of=m.as_of.isoformat() if m.as_of else None,
                description=m.description,
            )
            for m in dashboard.metrics
        ],
    )


@router.get(
    "/api/notifications/events", dependencies=[guard("GET", "/api/notifications/events")], responses=PAGINATED_RESPONSES
)
def notification_events(
    params: PageQuery, signer: Signer, events: Events, status: Literal["pending", "delivered", "error"] = "error"
) -> Page[NotificationEventRow]:
    """Notification events of the outbox (NOT-02); `error` lists those that exhausted their retries."""
    return paginate(events.list(status), params, signer)


@router.post(
    "/api/notifications/events/{id}/retry",
    status_code=202,
    dependencies=[guard("POST", "/api/notifications/events/{id}/retry")],
)
def retry_event(id: UuidId, events: Events) -> NotificationEventRow:  # noqa: A002
    """Put an event in error back in the queue with a fresh attempt budget."""
    return events.retry(id)
