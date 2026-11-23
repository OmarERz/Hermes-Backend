"""The iTop write path (ARQ-01): every write to iTop is a row of `itop_outbox`, sent later by a worker.

This is the only module allowed to send `core/create`, `core/update` and `core/apply_stimulus` (prototype C3,
Semgrep rule `itop-write-outside-outbox`). No LLM ever reaches it: callers are the ticket rules of the backend.

* `record_write` stores the intent (`ticket_update` + `itop_outbox`) inside the caller's transaction, so the
  write exists if and only if the decision that caused it was committed.
* `ItopOutboxWorker` claims one row at a time with `FOR UPDATE SKIP LOCKED`, marks it `in_progress` with a lease
  (a crashed worker's row becomes claimable again when the lease expires), calls iTop outside any transaction
  and stores the outcome.
* A created ticket carries `Ref. Hermes: <ticket id>` in its description and every comment ends with a
  `[hermes:<row>]` marker. Creating first looks for a non-closed request with the same title and our marker, and a
  retried comment or reopen first checks whether iTop already applied it: a lost answer never duplicates a ticket,
  a comment or a stimulus (ARQ-01, PRE-02). Field updates are idempotent by nature.
* Rows of one ticket are sent in order; any write also waits for a queued create of its ticket (it needs the id).
* Transport failures retry with a growing delay (1, 2, 4 ... minutes, at most 60) and end as `failed` after
  `max_attempts`, also when a worker died during the last attempt. A refusal from iTop (`code != 0`) is final,
  except a create whose team iTop refused (TIC-09), retried once with the default team.

Payloads are data for iTop, never logged (they carry names and descriptions). ⚠️ The REST field names follow
iTop 3.2.2's data model and the prototype's lessons; confirm them against the live instance (P-011).
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Literal

import httpx
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

from core.config import Settings
from core.db import models as m
from core.itop import oql
from core.itop.client import READ_OPERATIONS, ItopError, ItopObject, ItopReader, ItopUnavailableError
from core.itop.oql import FIRST_PRINTABLE

log = logging.getLogger("core.itop.outbox")

TICKET_CLASS: Final = "UserRequest"
WRITE_OPERATIONS: Final = frozenset({"core/create", "core/update", "core/apply_stimulus"})
LOG_FIELDS: Final = frozenset({"public_log", "private_log"})
STIMULI: Final = frozenset({"ev_reopen"})
REOPENABLE: Final = frozenset({"resolved", "closed"})  # ev_reopen still needed while the ticket is in these
MAX_BACKOFF_MINUTES: Final = 60

Kind = Literal["create", "update", "stimulus", "comment"]
# itop_outbox.operation only knows create/update/comment: a stimulus is an update of the ticket's state.
_OPERATION: Final[dict[str, str]] = {"create": "create", "update": "update", "stimulus": "update", "comment": "comment"}


def utcnow() -> datetime:
    return datetime.now(UTC)


# --- payloads ---------------------------------------------------------------------------------------------------


def create_payload(fields: dict[str, Any], *, fallback_team_id: str | None = None) -> dict[str, Any]:
    """`core/create` of a UserRequest; `fields["title"]` is also the idempotency lookup (ARQ-01)."""
    title = str(fields.get("title", ""))
    if not title.strip():
        raise ValueError("a ticket needs a title: it is the idempotency lookup")
    if any(ord(ch) < FIRST_PRINTABLE for ch in title):
        raise ValueError("a ticket title cannot contain control characters")
    return {"kind": "create", "fields": dict(fields), "fallback_team_id": fallback_team_id}


def update_payload(fields: dict[str, Any]) -> dict[str, Any]:
    """`core/update` of plain fields. A linked set (`functionalcis_list`, `contacts_list`) replaces the whole list; the
    worker merges `contacts_list` with the contacts already on the ticket before writing."""
    if not fields:
        raise ValueError("an update needs at least one field")
    if LOG_FIELDS & fields.keys():
        raise ValueError("comments go through comment_payload")
    return {"kind": "update", "fields": dict(fields)}


def comment_payload(message: str, *, private: bool = False) -> dict[str, Any]:
    """A new entry in the ticket's public or private log (`core/update` of a case log appends an entry)."""
    if not message.strip():
        raise ValueError("a comment needs text")
    # `marker: full`: queued by code that always writes the whole row id, so a retry never looks for the short marker
    # of older rows (F5.1 #43); rows queued before F12.2 lack it.
    return {"kind": "comment", "log": "private_log" if private else "public_log", "text": message, "marker": "full"}


def stimulus_payload(stimulus: str) -> dict[str, Any]:
    if stimulus not in STIMULI:
        raise ValueError(f"unsupported stimulus: {stimulus}")
    return {"kind": "stimulus", "stimulus": stimulus}


@dataclass(frozen=True)
class ItopWrite:
    """One intended write to a ticket: what to send, why (`action`, `assessment_id`) and its idempotency key."""

    ticket_id: uuid.UUID
    action: str
    payload: dict[str, Any]
    idempotency_key: str
    assessment_id: uuid.UUID | None = None


def record_write(session: Session, write: ItopWrite, now: datetime) -> m.ItopOutbox | None:
    """Queue one iTop write with its `ticket_update` log entry, in the caller's transaction.

    Returns None (and writes nothing) when a write with the same idempotency key already exists: deciding twice
    on the same evidence never writes twice (ARQ-01).
    """
    payload, idempotency_key = write.payload, write.idempotency_key
    kind = payload.get("kind")
    if kind not in _OPERATION:
        raise ValueError("unknown payload kind; build it with the *_payload helpers")
    if not idempotency_key.strip():
        raise ValueError("an idempotency key is required")
    update = m.TicketUpdate(
        ticket_id=write.ticket_id, action=write.action, assessment_id=write.assessment_id, created_at=now
    )
    session.add(update)
    session.flush()
    # Atomic against a concurrent writer of the same key: the insert waits for it and then does nothing.
    row_id = session.scalar(
        pg_insert(m.ItopOutbox)
        .values(
            ticket_update_id=update.id,
            idempotency_key=idempotency_key,
            operation=_OPERATION[str(kind)],
            payload=payload,
            status="pending",
            attempts=0,
            next_attempt_at=now,
            created_at=now,
        )
        .on_conflict_do_nothing(index_elements=["idempotency_key"])
        .returning(m.ItopOutbox.id)
    )
    if row_id is None:
        session.delete(update)
        session.flush()
        return None
    return session.get_one(m.ItopOutbox, row_id)


# --- transport --------------------------------------------------------------------------------------------------


@dataclass
class _ItopWriter(ItopReader):
    """iTop client that may also write. Private on purpose: only the outbox worker sends writes.

    One attempt per call: a write is never replayed blindly after a timeout (it may have been applied); the
    outbox retries later, and a create looks itself up first.
    """

    max_attempts: int = 1

    def call(self, operation: dict[str, Any]) -> dict[str, Any]:
        if operation.get("operation") not in WRITE_OPERATIONS | READ_OPERATIONS:
            raise ValueError("unsupported iTop operation")
        data = {"json_data": json.dumps(operation, ensure_ascii=False)}
        client = self.http or httpx.Client(timeout=httpx.Timeout(self.timeout))
        try:
            return self._call_with_retries(client, data)
        finally:
            if self.http is None:
                client.close()

    def write(self, operation: dict[str, Any]) -> tuple[str, str | None]:
        """Send a write and return the (id, ref) of the object iTop answered with."""
        body = self.call(operation)
        objects = body.get("objects") or {}
        if not isinstance(objects, dict) or len(objects) != 1:
            raise ItopUnavailableError("unexpected answer shape from an iTop write")
        raw = next(iter(objects.values()))
        key = str(raw.get("key", "")).strip()
        if not key or key == "0":
            raise ItopUnavailableError("iTop write answered without an object key")
        ref = (raw.get("fields") or {}).get("ref")
        return key, str(ref) if ref else None


def build_writer(base_url: str, token: str, *, http: httpx.Client | None = None, **options: Any) -> _ItopWriter:
    """The worker's iTop client; `http` is injectable for tests (`httpx.MockTransport`)."""
    return _ItopWriter(base_url, token, http=http, **options)


def writer_from_settings(settings: Settings, *, http: httpx.Client | None = None) -> _ItopWriter:
    """Fails closed when iTop is not configured (prototype C5)."""
    if settings.itop_url is None or settings.itop_token is None:
        raise ValueError("ITOP_URL and ITOP_TOKEN must be configured")
    return build_writer(str(settings.itop_url), settings.itop_token.get_secret_value(), http=http)


# --- worker -----------------------------------------------------------------------------------------------------


class _PermanentError(Exception):
    """The row can never succeed as stored; it ends as `failed` without further attempts."""


@dataclass(frozen=True)
class _Claim:
    row_id: uuid.UUID
    attempts: int
    ticket_id: uuid.UUID
    payload: dict[str, Any]
    itop_ticket_id: str | None

    @property
    def marker(self) -> str:
        """Stable reference written into what we send, to recognise our own write on a retry."""
        return f"[hermes:{self.row_id.hex}]"  # the whole id: the first 16 hex digits are mostly the timestamp

    @property
    def legacy_marker(self) -> str:
        """The shorter marker written before F12.2: a retry of an older row still recognises it (PRE-02)."""
        return f"[hermes:{self.row_id.hex[:16]}]"


@dataclass(frozen=True)
class _Result:
    itop_id: str | None = None
    ref: str | None = None
    note: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    remote_status: str | None = None
    human_urgency: bool = False


@dataclass(frozen=True)
class _Outcome:
    status: str
    result: _Result | None = None
    error: str | None = None
    delay: timedelta | None = None


# A create waits only for an older create of its ticket; any other write waits for every older write of its ticket
# and for any queued create of it (it needs the iTop id the create brings).
_CLAIM_SQL: Final = text(
    """
    SELECT o.id
      FROM itop_outbox o
      JOIN ticket_update u ON u.id = o.ticket_update_id
     WHERE o.status IN ('pending', 'in_progress')
       AND o.next_attempt_at <= :now
       AND NOT EXISTS (
             SELECT 1
               FROM itop_outbox o2
               JOIN ticket_update u2 ON u2.id = o2.ticket_update_id
              WHERE u2.ticket_id = u.ticket_id
                AND o2.id <> o.id
                AND o2.status IN ('pending', 'in_progress')
                AND (CASE WHEN o.operation = 'create'
                          THEN o2.operation = 'create' AND (o2.created_at, o2.id) < (o.created_at, o.id)
                          ELSE o2.operation = 'create' OR (o2.created_at, o2.id) < (o.created_at, o.id)
                     END))
     ORDER BY o.created_at, o.id
     LIMIT 1
       FOR UPDATE OF o SKIP LOCKED
    """
)


def backoff(attempts: int) -> timedelta:
    """1, 2, 4, 8 ... minutes after the 1st, 2nd, 3rd, 4th failed attempt; never more than an hour."""
    return timedelta(minutes=min(2 ** max(attempts - 1, 0), MAX_BACKOFF_MINUTES))


def _mentions_team(error: ItopError) -> bool:
    """TIC-09: iTop refused the team (outside the delivery model), not something else."""
    return "team_id" in error.attributes


@dataclass
class ItopOutboxWorker:
    """Sends queued writes to iTop. Safe to run in several processes at once."""

    session_factory: sessionmaker[Session]
    writer: _ItopWriter
    clock: Callable[[], datetime] = utcnow
    max_attempts: int = 10
    lease: timedelta = timedelta(minutes=5)

    def drain(self, limit: int = 100) -> int:
        """Process due rows until none is left or `limit` is reached; returns how many were processed."""
        done = 0
        while done < limit and self.run_once():
            done += 1
        return done

    def run_once(self) -> bool:
        """Claim and process one due row. False when nothing is due."""
        claim = self._claim()
        if claim is None:
            return False
        if isinstance(claim, str):
            return True  # an abandoned row was closed without a new attempt
        try:
            result = self._execute_checked(claim)
        except (_PermanentError, ItopError) as exc:
            self._finish(claim, _Outcome("failed", error=str(exc)))
        except ItopUnavailableError as exc:
            status = "failed" if claim.attempts >= self.max_attempts else "pending"
            self._finish(claim, _Outcome(status, error=str(exc), delay=backoff(claim.attempts)))
        else:
            self._finish(claim, _Outcome("done", result=result))
        return True

    # --- steps ----------------------------------------------------------------------------------------------
    def _claim(self) -> _Claim | str | None:
        now = self.clock()
        with self.session_factory() as session, session.begin():
            row_id = session.scalar(_CLAIM_SQL, {"now": now})
            if row_id is None:
                return None
            row = session.get_one(m.ItopOutbox, row_id)
            if row.status == "in_progress" and row.attempts >= self.max_attempts:
                # The worker died during the last allowed attempt: never exceed the attempt budget.
                row.status, row.next_attempt_at = "failed", None
                row.last_error = "lease expired during the last attempt"
                return "abandoned"
            update = session.get_one(m.TicketUpdate, row.ticket_update_id)
            ticket = session.get_one(m.Ticket, update.ticket_id)
            legacy = isinstance(row.payload, dict) and row.payload.get("kind") == "comment"
            if row.attempts == 0 and legacy and "marker" not in row.payload:
                # Queued before F12.2 but first sent now: it will write the whole id, so its retries must never look
                # for the short marker (another row's could match its prefix; F5.1 #43).
                row.payload = {**row.payload, "marker": "full"}
            row.status = "in_progress"
            row.attempts += 1
            row.next_attempt_at = now + self.lease
            return _Claim(row.id, row.attempts, ticket.id, dict(row.payload), ticket.itop_ticket_id)

    def _execute_checked(self, claim: _Claim) -> _Result:
        """A row whose payload or iTop answer has an unexpected shape fails at once instead of crashing the batch."""
        try:
            return self._execute(claim)
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise _PermanentError(f"malformed payload or answer ({type(exc).__name__})") from None

    def _execute(self, claim: _Claim) -> _Result:
        kind = claim.payload.get("kind")
        if kind == "create":
            return self._create(claim)
        if claim.itop_ticket_id is None:
            raise _PermanentError("the ticket has no iTop id and no create is queued")
        key = claim.itop_ticket_id
        if kind == "update":
            fields = dict(claim.payload["fields"])
            if "contacts_list" in fields:
                fields["contacts_list"] = self._merged_contacts(key, fields["contacts_list"])
            self.writer.write({"operation": "core/update", "class": TICKET_CLASS, "key": key, "fields": fields})
            return _Result(fields=fields)
        if kind == "comment":
            return self._comment(claim, key)
        if kind == "stimulus":
            return self._stimulus(claim, key)
        raise _PermanentError("unknown payload kind")

    def _comment(self, claim: _Claim, key: str) -> _Result:
        log_field = claim.payload["log"]
        if log_field not in LOG_FIELDS:
            raise _PermanentError("unknown log field")
        # Only a row first sent before F12.2 may have written the short marker; the others look for their own only.
        markers: tuple[str, ...] = (claim.marker,)
        if claim.payload.get("marker") != "full":
            # The short marker alone could be another row's (same prefix): only this row's whole entry, its text then
            # the short marker, counts as already written.
            markers = (claim.marker, f"{claim.payload['text']}\n\n{claim.legacy_marker}")
        if claim.attempts > 1 and self._remote_contains(key, log_field, markers):
            return _Result(note="already in iTop (retry)")  # a case log appends: never send twice (PRE-02)
        fields = {log_field: f"{claim.payload['text']}\n\n{claim.marker}"}
        self.writer.write({"operation": "core/update", "class": TICKET_CLASS, "key": key, "fields": fields})
        return _Result()

    def _stimulus(self, claim: _Claim, key: str) -> _Result:
        stimulus = claim.payload["stimulus"]
        if stimulus not in STIMULI:
            raise _PermanentError("unsupported stimulus")
        if claim.attempts > 1:
            current = self.writer.get(TICKET_CLASS, key, ["status"])
            if current and current[0].text("status") not in REOPENABLE:
                return _Result(note="already applied (retry)")
        operation = {"operation": "core/apply_stimulus", "class": TICKET_CLASS, "key": key, "stimulus": stimulus}
        self.writer.write({**operation, "fields": {}, "output_fields": "id"})
        return _Result()

    def _merged_contacts(self, key: str, wanted: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """A linked set write replaces the whole list: the contacts already on the ticket (a person may have added
        them by hand) are kept, with their role, and the owners we add go after them (pending F5.2 #54). It is a union:
        an owner whose CIs left the ticket is not removed; and a contact added in iTop between this read and the write
        would be lost (milliseconds; the REST API has no conditional update)."""
        found = self.writer.get(TICKET_CLASS, key, ["contacts_list"])
        current = found[0].fields.get("contacts_list") if found else None
        merged: dict[str, dict[str, Any]] = {}
        for entry in [*(current if isinstance(current, list) else []), *wanted]:
            contact = str(entry.get("contact_id") or "") if isinstance(entry, dict) else ""
            if contact and contact != "0" and contact not in merged:
                kept = {"contact_id": contact}
                for attribute in ("role", "role_code"):  # the writable link attributes (⚠️ P-011)
                    if entry.get(attribute):
                        kept[attribute] = str(entry[attribute])
                merged[contact] = kept
        return list(merged.values())

    def _remote_contains(self, key: str, field_name: str, markers: tuple[str, ...]) -> bool:
        found = self.writer.get(TICKET_CLASS, key, [field_name])
        if not found:
            return False
        text = json.dumps(found[0].fields.get(field_name), ensure_ascii=False)
        # Compare in the same JSON-escaped form (a case log entry keeps its line breaks as \n).
        return any(json.dumps(marker, ensure_ascii=False)[1:-1] in text for marker in markers)

    def _create(self, claim: _Claim) -> _Result:
        fields = dict(claim.payload["fields"])
        marker = f"Ref. Hermes: {claim.ticket_id}"
        fields["description"] = f"{fields.get('description', '')}\n\n{marker}"
        adopted = self._find_created(fields["title"], marker)
        if adopted is not None:
            return self._adopt(adopted, fields)
        try:
            itop_id, ref = self._send_create(fields)
        except ItopError as error:
            fallback = claim.payload.get("fallback_team_id")
            if not fallback or str(fields.get("team_id")) == str(fallback) or not _mentions_team(error):
                raise
            # TIC-09: the custodian team is outside the organization's delivery model.
            fields["team_id"] = fallback
            itop_id, ref = self._send_create(fields)
            return _Result(itop_id=itop_id, ref=ref, note="created with the default team (TIC-09)", fields=fields)
        return _Result(itop_id=itop_id, ref=ref, fields=fields)

    def _find_created(self, title: str, marker: str) -> ItopObject | None:
        """ARQ-01: a ticket we already created (same title, not closed, our marker in the description)."""
        candidates = self.writer.get(
            TICKET_CLASS,
            oql.select(TICKET_CLASS, oql.eq("title", title), f"status != {oql.quote('closed')}"),
            ["ref", "description", "status", "urgency", "impact"],
        )
        return next((c for c in candidates if marker in (c.text("description") or "")), None)

    @staticmethod
    def _adopt(found: ItopObject, requested: dict[str, Any]) -> _Result:
        """Mirror the adopted ticket as iTop holds it now; a different urgency was set by a person (D-007)."""
        remote = {name: found.text(name) for name in ("urgency", "impact") if found.text(name)}
        human = remote.get("urgency") is not None and remote.get("urgency") != str(requested.get("urgency"))
        return _Result(
            itop_id=found.key,
            ref=found.text("ref"),
            note="adopted an existing ticket",
            fields=remote,
            remote_status=found.text("status"),
            human_urgency=human,
        )

    def _send_create(self, fields: dict[str, Any]) -> tuple[str, str | None]:
        return self.writer.write(
            {"operation": "core/create", "class": TICKET_CLASS, "fields": fields, "output_fields": "id,ref"}
        )

    def _finish(self, claim: _Claim, outcome: _Outcome) -> None:
        now = self.clock()
        with self.session_factory() as session, session.begin():
            row = session.get(m.ItopOutbox, claim.row_id, with_for_update=True)
            if row is None or row.status != "in_progress" or row.attempts != claim.attempts:
                log.warning("itop outbox row %s was reclaimed while running; outcome dropped", claim.row_id)
                return
            row.status = outcome.status
            row.last_error = outcome.error if outcome.result is None else outcome.result.note
            row.done_at = now if outcome.status == "done" else None
            pending = outcome.status == "pending" and outcome.delay is not None
            row.next_attempt_at = now + outcome.delay if pending and outcome.delay is not None else None
            if outcome.result is not None:
                _apply_to_ticket(session.get_one(m.Ticket, claim.ticket_id), outcome.result, now)
        log.info("itop outbox row %s -> %s (attempt %d)", claim.row_id, outcome.status, claim.attempts)


def _apply_to_ticket(ticket: m.Ticket, result: _Result, now: datetime) -> None:
    """Mirror what iTop now holds: the new ticket's id and state, and the urgency and impact we wrote (D-007 shadow)."""
    if result.itop_id is not None:
        ticket.itop_ticket_id = result.itop_id
        ticket.itop_ref = result.ref
        ticket.status = "resolved" if result.remote_status == "resolved" else "open"
        ticket.resolved_at = now if ticket.status == "resolved" else ticket.resolved_at
        ticket.itop_created_at = ticket.itop_created_at or now
        ticket.closed_at = None
    if result.human_urgency:
        ticket.last_human_change_at, ticket.last_human_change_by = now, None
    if "urgency" in result.fields:
        ticket.current_urgency = int(result.fields["urgency"])
    if "impact" in result.fields:
        ticket.current_impact = _impact_name(str(result.fields["impact"]))


# iTop's UserRequest impact codes ⚠️ (P-011): 1 department, 2 service, 3 person.
IMPACT_CODES: Final[dict[str, str]] = {"department": "1", "service": "2"}


def _impact_name(code: str) -> str | None:
    return next((name for name, value in IMPACT_CODES.items() if value == code), None)
