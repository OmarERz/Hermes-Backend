"""Runs, STIX export, calibration, metrics, notification events, connections, setup and audit (docs/13 §8 to §9)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Path, Query
from fastapi.responses import StreamingResponse

from api.errors import ApiError, ErrorDetail
from api.pagination import PAGINATED_RESPONSES, Page, PageQuery, Signer, paginate
from api.routes import samples
from api.routes._auth import guard
from api.routes._config_support import CurrentUserDep, app_user_id, now, to_api_error
from api.routes._db import SessionDep
from api.routes._events import Events
from api.routes._runs import Runs
from api.routes._state import MetricsSource
from api.routes.models import (
    AuditEntry,
    CalibrationProposal,
    ConnectionStatus,
    ConnectionTestRequest,
    Metric,
    MetricsDashboard,
    NotificationEventRow,
    Run,
    ScanRequest,
    SetupStep,
    SetupStepUpdate,
    StixBundle,
    StixExportRequest,
)
from core.calibration import proposals as calibration
from core.configuration.errors import ConfigError
from core.db import models as m
from core.stix.export import ExportOptions, ExportScope, StixExportError, export_bundle

router = APIRouter(tags=["operations"])
PROGRESS_ES = {"queued": "En cola", "running": "En curso", "succeeded": "Terminado", "failed": "Falló"}

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
def launch_scan(_request: ScanRequest, runs: Runs, user: CurrentUserDep) -> Run:
    """Queues a simulated scan; the worker runs it on this run row and its progress streams from the run events
    (FRO-19). The run shows up in GET /api/runs."""
    return runs.queue_scan(user.uid)


@router.get("/api/runs", dependencies=[guard("GET", "/api/runs")], responses=PAGINATED_RESPONSES)
def list_runs(params: PageQuery, signer: Signer, runs: Runs) -> Page[Run]:
    """Scans, news runs and recalculations, newest first (ARQ-04)."""
    return paginate(runs.list(), params, signer)


@router.get(
    "/api/runs/{id}/events",
    dependencies=[guard("GET", "/api/runs/{id}/events")],
    response_class=StreamingResponse,
    responses={
        200: {"content": {"text/event-stream": {"schema": SSE_EVENT_SCHEMA}}, "description": "Server-sent events"}
    },
)
def run_events(id: str, runs: Runs) -> StreamingResponse:  # noqa: A002 - path parameter name of API-06
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
ProposalId = Annotated[str, Path(alias="id")]


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
        metrics=[Metric(key=m.key, label=m.label, value=m.value, unit=m.unit) for m in dashboard.metrics],
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
def retry_event(id: str, events: Events) -> NotificationEventRow:  # noqa: A002
    """Put an event in error back in the queue with a fresh attempt budget."""
    return events.retry(id)


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


@router.get("/api/audit", dependencies=[guard("GET", "/api/audit")], responses=PAGINATED_RESPONSES)
def audit(
    params: PageQuery, signer: Signer, actor: str | None = Query(default=None, max_length=100)
) -> Page[AuditEntry]:
    return paginate([a for a in samples.AUDIT if actor is None or a.actor == actor], params, signer)
