"""Ticket notification events (NOT-02, NOT-03): built by code, stored in `notification_event` in the caller's
transaction, delivered later by the dispatcher.

The payload follows `schemas/notification_event.schema.json` exactly. Two fields depend on iTop and may be unknown
when the event is recorded (a new ticket is created by the outbox afterwards): `ticket.itop_id` and `ticket.url`
are then empty strings and the dispatcher completes them before delivering (`complete_ticket_link`). Never produced
by an LLM; names, titles and news come from data and are only copied (the consumer escapes them).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Literal

from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id
from core.tickets.content import LEVEL_ES, TicketContext, sorted_cis
from core.tickets.rules import Priority, level

CONTRACT_VERSION: Final = "1.0"
LEAST_URGENT: Final = 4
TicketEventType = Literal["new_ticket", "level_up", "reopened", "partially_fixed", "fixed"]
_ITOP_TICKET_PAGE: Final = "/pages/UI.php?operation=details&class=UserRequest&id="


def ticket_url(itop_base_url: str | None, itop_id: str | None) -> str:
    """Link to the ticket in iTop's console, or "" while the id or iTop's URL is unknown."""
    if not itop_base_url or not itop_id:
        return ""
    return f"{itop_base_url.rstrip('/')}{_ITOP_TICKET_PAGE}{itop_id}"


def _owners(context: TicketContext) -> list[dict[str, Any]]:
    """Distinct owners of the current CIs, keyed and ordered like the ticket's `contacts_list`."""
    owners: dict[str, dict[str, Any]] = {}
    for ci in sorted_cis(context.current_cis):
        if ci.owner_name:
            owners.setdefault(ci.owner_itop_id or ci.owner_name, {"name": ci.owner_name, "email": ci.owner_email})
    return list(owners.values())


def justification(context: TicketContext, urgency: int | None) -> str:
    """Text for people (Spanish): the score, what drives it and the judge's reasons."""
    # TODO(P-009): code template plus the judge's reasons until the justification text is confirmed.
    if context.score is None or urgency is None:
        return "No quedan CIs vigentes en este ticket."
    text = (
        f"Puntuación {context.score} ({LEVEL_ES[level(urgency)]}) impulsada por {context.driving_ci}: "
        f"base {context.base}, ajuste del juez {context.judge_adjustment:+d}."
    )
    if context.reasons:
        text += " Motivos: " + ", ".join(f"{r.code} ({r.points:+d})" for r in context.reasons) + "."
    return text


@dataclass(frozen=True)
class TicketEvent:
    """One ticket event decided by the lifecycle: what happened and how urgent it is (NOT-03)."""

    event_type: TicketEventType
    priority: Priority
    urgency: int | None
    previous: int | None
    assessment_id: uuid.UUID | None


def ticket_event_payload(
    event_id: uuid.UUID, event: TicketEvent, context: TicketContext, ticket_link: tuple[str, str], now: datetime
) -> dict[str, Any]:
    """The event exactly as the contract defines it (NOT-03); `ticket_link` is (itop_id, url), possibly empty."""
    if now.tzinfo is None:
        raise ValueError("event dates must be timezone-aware")
    urgency = event.urgency
    score: dict[str, Any] | None = None
    if context.score is not None and urgency is not None:
        score = {
            "base": context.base if context.base is not None else context.score - context.judge_adjustment,
            "judge_adjustment": context.judge_adjustment,
            "final": context.score,
            "level": level(urgency),
            "previous": event.previous,
            "driving_ci": context.driving_ci,
        }
    fixed = sum(1 for ci in context.cis if ci.fixed)
    return {
        "event_id": str(event_id),
        "contract_version": CONTRACT_VERSION,
        "type": event.event_type,
        "priority": event.priority,
        "date": now.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "ticket": {
            "itop_id": ticket_link[0],
            "url": ticket_link[1],
            "custodian": context.custodian,
            "owners": _owners(context),
            "urgency": urgency if urgency is not None else LEAST_URGENT,
            "fixed_cis": fixed,
            "total_cis": len(context.cis),
        },
        "vulnerability": {
            "cve": context.cve,
            "product": context.product,
            "cvss": context.cvss,
            "in_kev": context.in_kev,
        },
        "alert": None,
        "score": score,
        "assets": [
            {
                "ci_id": ci.itop_ci_id,
                "name": ci.name,
                "score": ci.score,
                "criticality": ci.criticality,
                "exposed": ci.exposed is True,  # P-013: an unknown exposure counts as not exposed
                "confidentiality": ci.confidentiality,
                "personal_data": ci.personal_data,
                "owner": ci.owner_name,
                "status": "fixed" if ci.fixed else "active",
            }
            for ci in context.cis
        ],
        "justification": justification(context, urgency),
        "mitigation": context.mitigation,
        "mitigation_draft": list(context.mitigation_draft) if context.mitigation_draft else None,
        "news": [{"title": n.title, "url": n.url, "source": n.source, "date": n.published} for n in context.news],
        "assessment_id": str(event.assessment_id) if event.assessment_id is not None else None,
        "frontend_url": None,
    }


@dataclass(frozen=True)
class EventRecorder:
    """Writes ticket events into `notification_event`; knows iTop's URL to link the ticket."""

    itop_base_url: str | None = None

    def record(
        self, session: Session, ticket: m.Ticket, context: TicketContext, event: TicketEvent, now: datetime
    ) -> m.NotificationEvent:
        """Insert the event in the caller's transaction (NOT-02): it exists if and only if the change is committed."""
        event_id = new_id()
        itop_id = ticket.itop_ticket_id or ""
        link = (itop_id, ticket_url(self.itop_base_url, itop_id))
        row = m.NotificationEvent(
            id=event_id,
            contract_version=CONTRACT_VERSION,
            event_type=event.event_type,
            priority=event.priority,
            ticket_id=ticket.id,
            assessment_id=event.assessment_id,
            payload=ticket_event_payload(event_id, event, context, link, now),
            status="pending",
            attempts=0,
            next_attempt_at=now,
            created_at=now,
        )
        session.add(row)
        session.flush()
        return row


def complete_ticket_link(payload: dict[str, Any], itop_id: str, itop_base_url: str | None) -> dict[str, Any]:
    """The payload with the iTop id and URL filled in, once the outbox created the ticket (dispatcher side)."""
    ticket = dict(payload["ticket"])
    if ticket.get("itop_id") != itop_id or not ticket.get("url"):
        ticket["url"] = ticket_url(itop_base_url, itop_id)
    ticket["itop_id"] = itop_id
    return {**payload, "ticket": ticket}
