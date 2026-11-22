"""Builders of the rows the ticket tests need (teams, groups, tickets), with unique names per call."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from core.db import models as m

T0 = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)


def _tag() -> str:
    return uuid.uuid4().hex[:8]


def make_team(session: Session, name: str | None = None, *, itop_id: str | None = None) -> m.Team:
    team = m.Team(itop_team_id=itop_id or f"T-{_tag()}", name=name or f"Team {_tag()}", is_default=False, synced_at=T0)
    session.add(team)
    session.flush()
    return team


def make_group(session: Session, cve: str | None = None, product: str | None = None) -> m.FindingGroup:
    cve_id = cve or f"CVE-2026-{uuid.uuid4().int % 90000 + 10000}"
    if session.get(m.Cve, cve_id) is None:
        session.add(m.Cve(id=cve_id))
    software = m.SoftwareProduct(itop_name=product or f"product-{_tag()}", first_seen_at=T0)
    session.add(software)
    session.flush()
    group = m.FindingGroup(cve_id=cve_id, software_product_id=software.id, created_at=T0)
    session.add(group)
    session.flush()
    return group


def make_ticket(
    session: Session, *, group: m.FindingGroup | None = None, team: m.Team | None = None, **fields: object
) -> m.Ticket:
    """A ticket; `itop_id`, `status` and `urgency` are optional overrides."""
    itop_id = fields.get("itop_id")
    status = str(fields.get("status") or ("open" if itop_id else "pending_creation"))
    ticket = m.Ticket(
        finding_group_id=(group or make_group(session)).id,
        custodian_team_id=(team or make_team(session)).id,
        itop_ticket_id=str(itop_id) if itop_id else None,
        itop_ref=f"R-{int(str(itop_id)):06d}" if itop_id else None,
        status=status,
        current_urgency=fields.get("urgency"),
        suggestions_enabled=True,
        created_at=T0,
        closed_at=T0 if status == "closed" else None,
        resolved_at=T0 if status == "resolved" else None,
    )
    session.add(ticket)
    session.flush()
    return ticket
