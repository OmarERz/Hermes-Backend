"""Runs, STIX export, calibration, metrics and notification events (docs/13 §8). Connections, setup and audit live
in `admin`."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Literal

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from api.errors import ApiError, ErrorDetail
from api.pagination import PAGINATED_RESPONSES, Page, PageQuery, Signer, paginate
from api.routes import samples
from api.routes._auth import guard
from api.routes._db import SessionDep
from api.routes._state import RunStore
from api.routes.models import (
    CalibrationProposal,
    MetricsDashboard,
    NotificationEventRow,
    Run,
    ScanRequest,
    StixBundle,
    StixExportRequest,
)
from core.stix.export import ExportOptions, ExportScope, StixExportError, export_bundle

router = APIRouter(tags=["operations"])

# Schema of one parsed event: `event` is the event name and `data` a JSON text {run_id, progress, message}.
SSE_EVENT_SCHEMA = {
    "type": "object",
    "properties": {
        "event": {"type": "string", "enum": ["progress"]},
        "data": {"type": "string", "description": "JSON text: run_id, progress (0-100) and message"},
    },
    "required": ["event", "data"],
}


@router.post("/api/scans", status_code=202, dependencies=[guard("POST", "/api/scans")])
def launch_scan(_request: ScanRequest, runs: RunStore) -> Run:
    """Queues a simulated scan; progress comes from the run events (FRO-19). The run shows up in GET /api/runs."""
    run = Run(
        id=f"run-{len(runs) + 1}", kind="scan", status="queued", started_at=samples.NOW, finished_at=None, progress=0
    )
    runs.insert(0, run)
    return run


@router.get("/api/runs", dependencies=[guard("GET", "/api/runs")], responses=PAGINATED_RESPONSES)
def list_runs(params: PageQuery, signer: Signer, runs: RunStore) -> Page[Run]:
    return paginate(runs, params, signer)


@router.get(
    "/api/runs/{id}/events",
    dependencies=[guard("GET", "/api/runs/{id}/events")],
    response_class=StreamingResponse,
    responses={
        200: {"content": {"text/event-stream": {"schema": SSE_EVENT_SCHEMA}}, "description": "Server-sent events"}
    },
)
def run_events(id: str, runs: RunStore) -> StreamingResponse:  # noqa: A002 - path parameter name of API-06
    run = next((r for r in runs if r.id == id), None)
    if run is None:
        raise ApiError(404, "not_found", "La corrida no existe.")

    def stream() -> Iterator[str]:
        for progress, message in (
            (10, "Leyendo activos de iTop"),
            (60, "Correlacionando con noticias"),
            (100, "Terminado"),
        ):
            yield f'event: progress\ndata: {{"run_id": "{run.id}", "progress": {progress}, "message": "{message}"}}\n\n'

    return StreamingResponse(stream(), media_type="text/event-stream")


@router.post("/api/stix/export", dependencies=[guard("POST", "/api/stix/export")])
def stix_export(request: StixExportRequest, session: SessionDep) -> StixBundle:
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
    return StixBundle.model_validate(result.bundle)


@router.get(
    "/api/calibration/proposals",
    dependencies=[guard("GET", "/api/calibration/proposals")],
    responses=PAGINATED_RESPONSES,
)
def list_proposals(params: PageQuery, signer: Signer) -> Page[CalibrationProposal]:
    return paginate(samples.PROPOSALS, params, signer)


def _decide(proposal_id: str, status: Literal["approved", "rejected"]) -> CalibrationProposal:
    proposal = next((p for p in samples.PROPOSALS if p.id == proposal_id), None)
    if proposal is None:
        raise ApiError(404, "not_found", "La propuesta no existe.")
    if proposal.status != "pending":
        raise ApiError(409, "already_decided", "La propuesta ya fue resuelta.")
    return proposal.model_copy(update={"status": status})


@router.post(
    "/api/calibration/proposals/{id}/approve", dependencies=[guard("POST", "/api/calibration/proposals/{id}/approve")]
)
def approve_proposal(id: str) -> CalibrationProposal:  # noqa: A002
    return _decide(id, "approved")


@router.post(
    "/api/calibration/proposals/{id}/reject", dependencies=[guard("POST", "/api/calibration/proposals/{id}/reject")]
)
def reject_proposal(id: str) -> CalibrationProposal:  # noqa: A002
    return _decide(id, "rejected")


@router.get("/api/metrics", dependencies=[guard("GET", "/api/metrics")])
def metrics() -> MetricsDashboard:
    return MetricsDashboard(generated_at=samples.NOW, metrics=samples.METRICS)


@router.get(
    "/api/notifications/events", dependencies=[guard("GET", "/api/notifications/events")], responses=PAGINATED_RESPONSES
)
def notification_events(
    params: PageQuery, signer: Signer, status: Literal["pending", "delivered", "error"] = "error"
) -> Page[NotificationEventRow]:
    return paginate([e for e in samples.NOTIFICATION_EVENTS if e.status == status], params, signer)


@router.post(
    "/api/notifications/events/{id}/retry",
    status_code=202,
    dependencies=[guard("POST", "/api/notifications/events/{id}/retry")],
)
def retry_event(id: str) -> NotificationEventRow:  # noqa: A002
    event = next((e for e in samples.NOTIFICATION_EVENTS if e.id == id), None)
    if event is None:
        raise ApiError(404, "not_found", "El evento no existe.")
    if event.status != "error":
        raise ApiError(409, "not_in_error", "Solo se pueden reintentar eventos en error.")
    return event.model_copy(update={"status": "pending", "attempts": 0, "last_error": None})
