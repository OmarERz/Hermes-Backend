"""iTop webhook doorbell (ARQ-02, prototype C4/C12): `POST /api/itop/webhook`.

iTop calls it when one of its UserRequests changes, with the minimal payload `{"class", "id", "ref"}` configured
in the test instance. The payload is only a doorbell: it is never trusted as state. The route answers 202 at once
(iTop's webhooks are synchronous, time out after 5 s and are never retried) and re-reads that ticket from iTop in
the background. A lost call costs nothing: the 15-minute reconciliation reads every open ticket anyway.

Authentication fails closed (prototype C5): without `ITOP_WEBHOOK_TOKEN` or without iTop configured the route
answers 503; a missing or wrong `Authorization: Bearer` answers 401. The token is compared in constant time.
"""

from __future__ import annotations

import logging
import secrets
from typing import Annotated, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, Header, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from api.errors import ApiError, ErrorResponse
from core.itop.client import ItopError, ItopUnavailableError
from core.tickets.sync import TicketStateSync

log = logging.getLogger("api.itop_webhook")


class ItopWebhookCall(BaseModel):
    """What iTop sends: the class, id and reference of the changed object, nothing else."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    class_name: Literal["UserRequest"] = Field(alias="class")
    id: str = Field(pattern=r"^[1-9][0-9]{0,11}$", description="iTop object id")
    ref: str | None = Field(default=None, max_length=40)


class WebhookAccepted(BaseModel):
    status: Literal["accepted"] = "accepted"


def _resync(sync: TicketStateSync, itop_id: str) -> None:
    try:
        sync.sync_itop_ticket(itop_id)
    except (ItopError, ItopUnavailableError) as exc:
        log.warning("webhook re-read of iTop ticket %s failed (%s); the periodic sync will retry", itop_id, exc)


def build_itop_webhook_router(token: SecretStr | None, sync: TicketStateSync | None) -> APIRouter:
    router = APIRouter(prefix="/api/itop", tags=["itop"])

    def require_webhook_token(authorization: Annotated[str | None, Header()] = None) -> TicketStateSync:
        """Runs before the body is read, so a caller without the token gets 401/503, never a validation 422."""
        if token is None or sync is None:
            raise ApiError(503, "webhook_disabled", "El webhook de iTop no está configurado.")
        expected = f"Bearer {token.get_secret_value()}".encode()
        if authorization is None or not secrets.compare_digest(authorization.encode(), expected):
            raise ApiError(401, "unauthorized", "Se requiere autenticación válida.")
        return sync

    webhook_guard = Depends(require_webhook_token)  # resolved before the body (annotations here are strings)

    @router.post(
        "/webhook",
        status_code=status.HTTP_202_ACCEPTED,
        responses={
            401: {"model": ErrorResponse, "description": "Missing or wrong webhook token"},
            503: {"model": ErrorResponse, "description": "Webhook or iTop not configured"},
        },
    )
    def itop_webhook(
        call: ItopWebhookCall,
        background: BackgroundTasks,
        ready: TicketStateSync = webhook_guard,
    ) -> WebhookAccepted:
        """Doorbell from iTop: re-read the ticket in the background (ARQ-02). Not for the frontend."""
        background.add_task(_resync, ready, call.id)
        return WebhookAccepted()

    return router
