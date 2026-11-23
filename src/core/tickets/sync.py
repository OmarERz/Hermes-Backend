"""Ticket state read back from iTop (ARQ-02, prototype C4/C6/C12).

iTop is the master of a ticket's state once it exists: people resolve, close, reopen and change its urgency there.
This module mirrors that state into `ticket` (status, resolution and closing dates, urgency, impact) and detects
the last human change of urgency (D-007, TIC-06):

* first from iTop's change history (`CMDBChangeOpSetAttributeScalar` on `urgency`), comparing the author with
  `ITOP_SYSTEM_USER`;
* when the history cannot be read or the system user is not configured, from the shadow state: the urgency we
  last wrote (`ticket.current_urgency`, set by the outbox) differs from the one iTop holds, so someone else changed
  it.

It runs every 15 minutes over the open and resolved tickets, and for one ticket when iTop rings the webhook. Only
reads: nothing here writes to iTop. ⚠️ The history class, its fields and the `userinfo` format are those of iTop
3.2.2's data model; confirm them against the live instance (P-011).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from core.itop import oql
from core.itop.client import ItopError, ItopReader, ItopUnavailableError
from core.textnum import ascii_int

log = logging.getLogger("core.tickets.sync")

TICKET_CLASS: Final = "UserRequest"
TICKET_FIELDS: Final = ("status", "urgency", "impact", "ref")
HISTORY_CLASS: Final = "CMDBChangeOpSetAttributeScalar"
HISTORY_FIELDS: Final = ("date", "userinfo", "newvalue")
ITOP_DATE_FORMAT: Final = "%Y-%m-%d %H:%M:%S"
# iTop's UserRequest impact codes ⚠️ (P-011): 1 department, 2 service, 3 person.
IMPACTS: Final[dict[str, str]] = {"1": "department", "2": "service"}
SYNCED_STATES: Final = ("open", "resolved")

# Demo tickets (`make demo`) carry these ids instead of iTop's: they are never read from iTop (pending F13.1 #70).
DEMO_ID_PREFIX: Final = "DEMO-"
# An urgency write of ours that finished at or after `:since`: iTop may have answered before it landed.
_URGENCY_WRITE_DONE_SINCE: Final = text(
    """
    SELECT 1
      FROM itop_outbox o
      JOIN ticket_update u ON u.id = o.ticket_update_id
     WHERE u.ticket_id = :ticket_id
       AND o.status = 'done' AND o.done_at >= :since
       AND o.payload -> 'fields' ? 'urgency'
     LIMIT 1
    """
)
_URGENCY_WRITE_QUEUED: Final = text(
    """
    SELECT 1
      FROM itop_outbox o
      JOIN ticket_update u ON u.id = o.ticket_update_id
     WHERE u.ticket_id = :ticket_id
       AND o.status IN ('pending', 'in_progress')
       AND o.payload -> 'fields' ? 'urgency'
     LIMIT 1
    """
)


@dataclass(frozen=True)
class UrgencyChange:
    """The latest change of a ticket's urgency in iTop's history."""

    at: datetime
    by: str


def ticket_status(itop_status: str | None) -> str:
    """Our three states after creation; every iTop state that is not resolved or closed is still open."""
    if itop_status == "resolved":
        return "resolved"
    if itop_status == "closed":
        return "closed"
    return "open"


def _parse_itop_date(raw: str | None) -> datetime | None:
    """iTop dates are `YYYY-MM-DD HH:MM:SS` in the server's time zone; the test instance runs in UTC ⚠️."""
    if not raw:
        return None
    try:
        return datetime.strptime(raw, ITOP_DATE_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None


def last_urgency_change(reader: ItopReader, itop_ticket_id: str) -> UrgencyChange | None:
    """The newest urgency change in iTop's history, or None when the history cannot be read or holds none."""
    query = oql.select(
        HISTORY_CLASS,
        oql.eq("objclass", TICKET_CLASS),
        oql.eq("objkey", itop_ticket_id),
        oql.eq("attcode", "urgency"),
    )
    try:
        changes = reader.get(HISTORY_CLASS, query, HISTORY_FIELDS)
    except ItopError:
        log.warning("iTop history unreadable for ticket %s; using the shadow urgency", itop_ticket_id)
        return None
    dated = [(at, obj) for obj in changes if (at := _parse_itop_date(obj.text("date"))) is not None]
    if not dated:
        return None
    at, newest = max(dated, key=lambda pair: (pair[0], ascii_int(pair[1].key) or 0))
    return UrgencyChange(at=at, by=newest.text("userinfo") or "")


def _is_system(author: str, system_user: str) -> bool:
    return author.strip().casefold() == system_user.strip().casefold()


@dataclass
class TicketStateSync:
    """Mirrors iTop's state of our tickets into the database."""

    session_factory: sessionmaker[Session]
    reader: ItopReader
    system_user: str | None
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def sync_open_tickets(self) -> int:
        """ARQ-02 pass over every open or resolved ticket; returns how many were read. Stops if iTop is down."""
        with self.session_factory() as session:
            ids = session.scalars(
                select(m.Ticket.id)
                .where(
                    m.Ticket.status.in_(SYNCED_STATES),
                    m.Ticket.itop_ticket_id.is_not(None),
                    m.Ticket.itop_ticket_id.not_like(f"{DEMO_ID_PREFIX}%"),
                )
                .order_by(m.Ticket.id)
            ).all()
        read = 0
        for ticket_id in ids:
            try:
                self._sync(ticket_id)
            except ItopUnavailableError:
                log.warning("iTop unavailable: ticket sync stopped after %d of %d tickets", read, len(ids))
                break
            except ItopError as exc:
                log.warning("iTop refused reading ticket %s: %s", ticket_id, exc)
            read += 1
        return read

    def sync_itop_ticket(self, itop_ticket_id: str) -> bool:
        """Webhook doorbell: re-read one ticket by its iTop id. False when it is not one of ours."""
        with self.session_factory() as session:
            ticket_id = session.scalar(select(m.Ticket.id).where(m.Ticket.itop_ticket_id == itop_ticket_id))
        if ticket_id is None or itop_ticket_id.startswith(DEMO_ID_PREFIX):
            return False
        self._sync(ticket_id)
        return True

    def _sync(self, ticket_id: object) -> None:
        # Our own pending urgency writes are looked up before reading iTop, and the writes that finish while iTop is
        # read are caught afterwards: either way the remote urgency may predate our write, so it is not a human
        # change (pending F5.1 #44, D-007).
        read_started = self.clock()
        with self.session_factory() as session:
            ticket = session.get_one(m.Ticket, ticket_id)
            itop_id = ticket.itop_ticket_id
            queued = session.scalar(_URGENCY_WRITE_QUEUED, {"ticket_id": ticket.id}) is not None
        if itop_id is None:
            return
        found = self.reader.get(TICKET_CLASS, itop_id, TICKET_FIELDS)
        if not found:
            log.warning("ticket %s is no longer in iTop", ticket_id)
            return
        remote = found[0]
        urgency_text = remote.text("urgency")
        urgency = ascii_int(urgency_text)
        change: UrgencyChange | None = None
        with self.session_factory() as session:
            ticket = session.get_one(m.Ticket, ticket_id)
            suspicious = urgency is not None and urgency != ticket.current_urgency
            queued = queued or self._ours_in_flight(session, ticket.id, read_started)
        if suspicious and not queued and self.system_user:
            change = last_urgency_change(self.reader, itop_id)
        now = self.clock()
        with self.session_factory() as session, session.begin():
            ticket = session.get_one(m.Ticket, ticket_id, with_for_update=True)
            if ticket.itop_ticket_id != itop_id:
                return  # re-created meanwhile (reopen of a closed ticket): the next pass reads the new one
            self._apply_status(ticket, ticket_status(remote.text("status")), now)
            queued = queued or self._ours_in_flight(session, ticket.id, read_started)
            if urgency is not None and urgency != ticket.current_urgency and not queued:
                self._record_human_change(ticket, change, now)
                ticket.current_urgency = urgency
            impact = IMPACTS.get(remote.text("impact") or "")
            if impact is not None:
                ticket.current_impact = impact
            ticket.itop_ref = remote.text("ref") or ticket.itop_ref

    @staticmethod
    def _ours_in_flight(session: Session, ticket_id: object, since: datetime) -> bool:
        """An urgency write of ours is queued, running, or finished since `since`."""
        params = {"ticket_id": ticket_id, "since": since}
        return (
            session.scalar(_URGENCY_WRITE_QUEUED, params) is not None
            or session.scalar(_URGENCY_WRITE_DONE_SINCE, params) is not None
        )

    @staticmethod
    def _apply_status(ticket: m.Ticket, status: str, now: datetime) -> None:
        if status == "resolved" and ticket.status != "resolved":
            ticket.resolved_at = now
        ticket.closed_at = (ticket.closed_at or now) if status == "closed" else None
        ticket.status = status

    def _record_human_change(self, ticket: m.Ticket, change: UrgencyChange | None, now: datetime) -> None:
        """D-007: an urgency we did not write. The history names the author; otherwise the shadow state decides."""
        if change is not None and self.system_user and _is_system(change.by, self.system_user):
            return
        ticket.last_human_change_at = change.at if change is not None else now
        ticket.last_human_change_by = (change.by or None) if change is not None else None
        log.info("human urgency change detected on ticket %s", ticket.id)
