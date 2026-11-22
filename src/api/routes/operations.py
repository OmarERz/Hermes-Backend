"""Runs, STIX export, calibration, metrics, notification events, connections, setup and audit (docs/13 §8 to §9)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from api.errors import ApiError, ErrorDetail
from api.pagination import Page, PageQuery, Signer, paginate
from api.routes import samples
from api.routes._auth import guard
from api.routes.models import (
    AuditEntry,
    CalibrationProposal,
    ConnectionStatus,
    ConnectionTestRequest,
    MetricsDashboard,
    NotificationEventRow,
    Run,
    ScanRequest,
    SetupStep,
    SetupStepUpdate,
    StixBundle,
    StixExportRequest,
)

router = APIRouter(tags=["operations"])


def get_runs(request: Request) -> list[Run]:
    """The runs of this app instance (sample store seeded in create_app; the real one is the runs table)."""
    runs: list[Run] = request.app.state.runs
    return runs


RunStore = Annotated[list[Run], Depends(get_runs)]


@router.post("/api/scans", status_code=202, dependencies=[guard("POST", "/api/scans")])
def launch_scan(_request: ScanRequest, runs: RunStore) -> Run:
    """Queues a simulated scan; progress comes from the run events (FRO-19). The run shows up in GET /api/runs."""
    run = Run(
        id=f"run-{len(runs) + 1}", kind="scan", status="queued", started_at=samples.NOW, finished_at=None, progress=0
    )
    runs.insert(0, run)
    return run


@router.get("/api/runs", dependencies=[guard("GET", "/api/runs")])
def list_runs(params: PageQuery, signer: Signer, runs: RunStore) -> Page[Run]:
    return paginate(runs, params, signer)


@router.get(
    "/api/runs/{id}/events",
    dependencies=[guard("GET", "/api/runs/{id}/events")],
    response_class=StreamingResponse,
    responses={
        200: {"content": {"text/event-stream": {"schema": {"type": "string"}}}, "description": "Server-sent events"}
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
def stix_export(request: StixExportRequest) -> StixBundle:
    """Exports a STIX 2.1 bundle. The scope needs its matching identifier or range."""
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
    return StixBundle(**samples.STIX_BUNDLE)


@router.get("/api/calibration/proposals", dependencies=[guard("GET", "/api/calibration/proposals")])
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


@router.get("/api/notifications/events", dependencies=[guard("GET", "/api/notifications/events")])
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


@router.get("/api/connections/status", dependencies=[guard("GET", "/api/connections/status")])
def connections_status() -> list[ConnectionStatus]:
    """Never includes a key, not even a partial one (SEG-23)."""
    return samples.CONNECTIONS


@router.post("/api/connections/test", dependencies=[guard("POST", "/api/connections/test")])
def connections_test(request: ConnectionTestRequest) -> list[ConnectionStatus]:
    return [c for c in samples.CONNECTIONS if request.names is None or c.name in request.names]


@router.get("/api/setup/status", dependencies=[guard("GET", "/api/setup/status")])
def setup_status() -> list[SetupStep]:
    return samples.SETUP_STEPS


@router.put("/api/setup/steps/{n}", dependencies=[guard("PUT", "/api/setup/steps/{n}")])
def setup_step(n: int, update: SetupStepUpdate) -> SetupStep:
    step = next((s for s in samples.SETUP_STEPS if s.n == n), None)
    if step is None:
        raise ApiError(404, "not_found", "El paso del asistente no existe.")
    return step.model_copy(update=update.model_dump())


@router.get("/api/audit", dependencies=[guard("GET", "/api/audit")])
def audit(
    params: PageQuery, signer: Signer, actor: str | None = Query(default=None, max_length=100)
) -> Page[AuditEntry]:
    return paginate([a for a in samples.AUDIT if actor is None or a.actor == actor], params, signer)
