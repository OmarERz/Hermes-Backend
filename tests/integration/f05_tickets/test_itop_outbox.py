"""The iTop outbox against PostgreSQL 18 and the iTop double: idempotent, ordered, retried, never duplicated."""

from __future__ import annotations

import json
import re
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import httpx
import pytest
from f05data import T0, make_team, make_ticket
from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from core.config import Settings
from core.db import models as m
from core.itop.outbox import (
    ItopOutboxWorker,
    ItopWrite,
    _Outcome,
    build_writer,
    comment_payload,
    create_payload,
    record_write,
    stimulus_payload,
    update_payload,
    writer_from_settings,
)
from doubles.itop import ItopDouble

pytestmark = pytest.mark.integration


@dataclass
class Clock:
    now: datetime = T0

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **delta: float) -> None:
        self.now += timedelta(**delta)


def ticket_fields(title: str = "CVE-2026-1000 · nginx · Platform Ops", team_id: str = "10") -> dict[str, Any]:
    return {
        "org_id": "1",
        "caller_id": "5",
        "title": title,
        "description": "Descripción",
        "team_id": team_id,
        "urgency": "3",
        "impact": "2",
        "functionalcis_list": [{"functionalci_id": "100", "impact_code": "manual"}],
    }


def worker(
    factory: sessionmaker[Session], double: ItopDouble, clock: Clock, http: httpx.Client | None = None, **kwargs: Any
) -> ItopOutboxWorker:
    writer = build_writer("http://localhost", str(double.token), http=http or double.client())
    return ItopOutboxWorker(factory, writer, clock=clock, **kwargs)


def losing_responses(double: ItopDouble, operation: str, times: int = 1) -> httpx.Client:
    """iTop applies the operation but the answer is lost on the way back (the ambiguous failure)."""
    left = {"n": times}

    def handle(request: httpx.Request) -> httpx.Response:
        response = double.transport.handle_request(request)
        sent = json.loads(dict(httpx.QueryParams(request.content.decode()))["json_data"])["operation"]
        if sent == operation and left["n"] > 0:
            left["n"] -= 1
            raise httpx.ReadTimeout("answer lost", request=request)
        return response

    return httpx.Client(transport=httpx.MockTransport(handle))


def queue(
    factory: sessionmaker[Session], ticket_id: uuid.UUID, payload: dict[str, Any], key: str, action: str = "create"
) -> uuid.UUID | None:
    with factory() as session, session.begin():
        row = record_write(session, ItopWrite(ticket_id, action, payload, key), T0)
        return row.id if row else None


def new_ticket(factory: sessionmaker[Session], **kwargs: Any) -> m.Ticket:
    with factory() as session, session.begin():
        return make_ticket(session, **kwargs)


def outbox_row(factory: sessionmaker[Session], row_id: uuid.UUID | None) -> m.ItopOutbox:
    assert row_id is not None
    with factory() as session:
        return session.get_one(m.ItopOutbox, row_id)


def reload(factory: sessionmaker[Session], ticket_id: uuid.UUID) -> m.Ticket:
    with factory() as session:
        return session.get_one(m.Ticket, ticket_id)


def refuse_team(double: ItopDouble, team_id: str) -> None:
    """The double answers like iTop when the team is outside the organization's delivery model (TIC-09)."""
    original = double.handle

    def handle(op: dict[str, Any]) -> dict[str, Any]:
        if op["operation"] == "core/create" and op["fields"].get("team_id") == team_id:
            return {"code": 100, "message": "Error: team_id: value not allowed"}
        return original(op)

    double.handle = handle


def test_create_sets_the_itop_id_and_the_shadow_urgency(factory: sessionmaker[Session]) -> None:
    double, clock = ItopDouble(), Clock()
    ticket = new_ticket(factory)
    row_id = queue(factory, ticket.id, create_payload(ticket_fields()), f"create:{ticket.id}")

    assert worker(factory, double, clock).drain() == 1

    stored = reload(factory, ticket.id)
    created = next(iter(double.data["UserRequest"].values()))
    assert stored.itop_ticket_id == created["id"]
    assert stored.itop_ref == created["ref"]
    assert created["description"] == f"Descripción<br><br>Ref. Hermes: {ticket.id}"  # iTop reads HTML (F12.3)
    assert (stored.status, stored.current_urgency, stored.current_impact) == ("open", 3, "service")
    assert stored.itop_created_at == T0
    row = outbox_row(factory, row_id)
    assert (row.status, row.attempts, row.done_at, row.last_error) == ("done", 1, T0, None)
    assert double.operations == ["core/get", "core/create"]


def test_the_same_idempotency_key_is_queued_once(factory: sessionmaker[Session]) -> None:
    ticket = new_ticket(factory)
    assert queue(factory, ticket.id, create_payload(ticket_fields()), "k-1") is not None
    assert queue(factory, ticket.id, create_payload(ticket_fields()), "k-1") is None
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(m.TicketUpdate)) == 1


def test_a_concurrent_writer_of_the_same_key_gets_none_and_keeps_its_transaction(
    factory: sessionmaker[Session],
) -> None:
    ticket = new_ticket(factory)
    results: list[object] = []
    first = factory()
    first.begin()
    assert record_write(first, ItopWrite(ticket.id, "comment", comment_payload("a"), "same"), T0) is not None

    def second_writer() -> None:
        with factory() as session, session.begin():
            row = record_write(session, ItopWrite(ticket.id, "comment", comment_payload("b"), "same"), T0)
            results.append(row)
            session.add(m.TicketUpdate(ticket_id=ticket.id, action="suggest", created_at=T0))  # its other work

    thread = threading.Thread(target=second_writer)
    thread.start()
    thread.join(timeout=1)
    assert thread.is_alive()  # waiting on the first transaction's key
    first.commit()
    first.close()
    thread.join(timeout=10)

    assert results == [None]
    with factory() as session:
        actions = sorted(session.scalars(select(m.TicketUpdate.action)).all())
        assert actions == ["comment", "suggest"]


def test_a_crash_after_itop_created_the_ticket_does_not_duplicate_it(factory: sessionmaker[Session]) -> None:
    double, clock = ItopDouble(), Clock()
    ticket = new_ticket(factory)
    row_id = queue(factory, ticket.id, create_payload(ticket_fields()), f"create:{ticket.id}")
    first = worker(factory, double, clock)
    claim = first._claim()  # claimed; iTop creates the ticket; the process dies before storing the answer
    assert claim is not None
    assert not isinstance(claim, str)
    marked = {**ticket_fields(), "description": f"Descripción\n\nRef. Hermes: {ticket.id}"}
    double.handle({"operation": "core/create", "class": "UserRequest", "fields": marked})

    clock.advance(minutes=6)  # the lease expires and another worker takes over
    assert worker(factory, double, clock).drain() == 1

    assert len(double.data["UserRequest"]) == 1
    assert reload(factory, ticket.id).itop_ticket_id == next(iter(double.data["UserRequest"]))
    row = outbox_row(factory, row_id)
    assert (row.status, row.attempts, row.last_error) == ("done", 2, "adopted an existing ticket")
    first._finish(claim, _Outcome("failed", error="late"))  # the dead worker's late outcome is dropped
    assert outbox_row(factory, row_id).status == "done"


def test_a_lost_create_answer_is_recovered_on_retry(factory: sessionmaker[Session]) -> None:
    double, clock = ItopDouble(), Clock()
    ticket = new_ticket(factory)
    row_id = queue(factory, ticket.id, create_payload(ticket_fields()), f"create:{ticket.id}")
    run = worker(factory, double, clock, http=losing_responses(double, "core/create"))

    run.drain()
    assert outbox_row(factory, row_id).status == "pending"
    clock.advance(minutes=1)
    run.drain()

    assert len(double.data["UserRequest"]) == 1
    assert outbox_row(factory, row_id).last_error == "adopted an existing ticket"


def test_adoption_mirrors_what_itop_holds_now(factory: sessionmaker[Session]) -> None:
    double, clock = ItopDouble(), Clock()
    ticket = new_ticket(factory)
    queue(factory, ticket.id, create_payload(ticket_fields()), f"create:{ticket.id}")
    run = worker(factory, double, clock, http=losing_responses(double, "core/create"))
    run.drain()
    created = next(iter(double.data["UserRequest"].values()))
    created.update(urgency="1", status="resolved")  # a person changed it before we recovered

    clock.advance(minutes=1)
    run.drain()

    stored = reload(factory, ticket.id)
    assert (stored.status, stored.current_urgency, stored.resolved_at) == ("resolved", 1, clock.now)
    assert (stored.last_human_change_at, stored.last_human_change_by) == (clock.now, None)


def test_a_ticket_of_another_custodian_with_the_same_title_is_not_adopted(factory: sessionmaker[Session]) -> None:
    double, clock = ItopDouble(), Clock()
    other = uuid.uuid4()
    double.add("UserRequest", 50, title=ticket_fields()["title"], status="new", description=f"x Ref. Hermes: {other}")
    double.add("UserRequest", 51, title=ticket_fields()["title"], status="closed", description="")
    ticket = new_ticket(factory)
    queue(factory, ticket.id, create_payload(ticket_fields()), f"create:{ticket.id}")

    worker(factory, double, clock).drain()

    assert reload(factory, ticket.id).itop_ticket_id not in {None, "50", "51"}


def test_transport_failures_back_off_and_end_as_failed(factory: sessionmaker[Session]) -> None:
    double, clock = ItopDouble(down=True), Clock()
    ticket = new_ticket(factory)
    row_id = queue(factory, ticket.id, create_payload(ticket_fields()), f"create:{ticket.id}")
    run = worker(factory, double, clock, max_attempts=3)

    assert run.drain() == 1
    row = outbox_row(factory, row_id)
    assert (row.status, row.attempts, row.next_attempt_at) == ("pending", 1, T0 + timedelta(minutes=1))
    assert row.last_error is not None
    assert "no response from iTop" in row.last_error
    assert run.drain() == 0  # not due yet

    clock.advance(minutes=1)
    run.drain()
    assert outbox_row(factory, row_id).next_attempt_at == clock.now + timedelta(minutes=2)
    clock.advance(minutes=2)
    run.drain()
    row = outbox_row(factory, row_id)
    assert (row.status, row.attempts, row.next_attempt_at) == ("failed", 3, None)
    assert reload(factory, ticket.id).status == "pending_creation"


def test_a_worker_dying_on_the_last_attempt_never_exceeds_the_budget(factory: sessionmaker[Session]) -> None:
    double, clock = ItopDouble(), Clock()
    ticket = new_ticket(factory)
    row_id = queue(factory, ticket.id, create_payload(ticket_fields()), f"create:{ticket.id}")
    run = worker(factory, double, clock, max_attempts=1)
    assert run._claim() is not None  # attempt 1 of 1 claimed, then the process dies

    clock.advance(minutes=6)
    assert run.run_once() is True

    row = outbox_row(factory, row_id)
    assert (row.status, row.attempts, row.last_error) == ("failed", 1, "lease expired during the last attempt")
    assert double.calls == []


def test_an_itop_refusal_is_final(factory: sessionmaker[Session]) -> None:
    double, clock = ItopDouble(), Clock()
    ticket = new_ticket(factory)
    fields = ticket_fields()
    del fields["caller_id"]  # the double refuses a UserRequest without its required fields
    row_id = queue(factory, ticket.id, create_payload(fields, fallback_team_id="99"), f"create:{ticket.id}")

    worker(factory, double, clock).drain()

    row = outbox_row(factory, row_id)
    assert (row.status, row.last_error) == ("failed", "iTop refused the operation (code 100)")
    assert [c.operation for c in double.writes] == ["core/create"]  # no team fallback for other refusals


def test_a_refused_team_falls_back_to_the_default_team(factory: sessionmaker[Session]) -> None:
    double, clock = ItopDouble(), Clock()
    refuse_team(double, "10")
    ticket = new_ticket(factory)
    row_id = queue(factory, ticket.id, create_payload(ticket_fields(), fallback_team_id="99"), f"create:{ticket.id}")

    worker(factory, double, clock).drain()

    created = next(iter(double.data["UserRequest"].values()))
    assert created["team_id"] == "99"
    row = outbox_row(factory, row_id)
    assert (row.status, row.last_error) == ("done", "created with the default team (TIC-09)")


def test_a_refused_team_without_another_fallback_fails(factory: sessionmaker[Session]) -> None:
    double, clock = ItopDouble(), Clock()
    refuse_team(double, "10")
    ticket = new_ticket(factory)
    row_id = queue(factory, ticket.id, create_payload(ticket_fields(), fallback_team_id="10"), f"create:{ticket.id}")

    worker(factory, double, clock).drain()

    assert outbox_row(factory, row_id).status == "failed"


def test_updates_wait_for_the_create_and_run_in_order(factory: sessionmaker[Session]) -> None:
    double, clock = ItopDouble(), Clock()
    ticket = new_ticket(factory)
    early = queue(factory, ticket.id, comment_payload("Anterior"), "c-0", action="comment")
    queue(factory, ticket.id, create_payload(ticket_fields()), f"create:{ticket.id}")
    queue(factory, ticket.id, comment_payload("Sigue presente"), "c-1", action="comment")
    queue(factory, ticket.id, update_payload({"urgency": "1"}), "u-1", action="raise_urgency")
    queue(factory, ticket.id, comment_payload("Nota privada", private=True), "c-2", action="suggest")
    with factory() as session, session.begin():  # a write older than the create (e.g. before a re-creation)
        session.get_one(m.ItopOutbox, early).created_at = T0 - timedelta(minutes=1)

    assert worker(factory, double, clock).drain() == 5

    assert double.operations[:2] == ["core/get", "core/create"]
    created = next(iter(double.data["UserRequest"].values()))
    assert created["public_log"].startswith("Sigue presente<br><br>[hermes:")  # iTop reads HTML (F12.3)
    assert created["private_log"].startswith("Nota privada<br><br>[hermes:")
    # The marker carries the whole row id (32 hex digits), not only its timestamp part (pending F5.1 #43).
    assert re.search(r"\[hermes:[0-9a-f]{32}\]", created["public_log"])
    assert created["urgency"] == "1"
    assert reload(factory, ticket.id).current_urgency == 1


def test_a_lost_comment_answer_is_not_sent_twice(factory: sessionmaker[Session]) -> None:
    double, clock = ItopDouble(), Clock()
    double.add("UserRequest", 60, title="t", status="new", ref="R-000060")
    ticket = new_ticket(factory, itop_id="60")
    row_id = queue(factory, ticket.id, comment_payload("Hola"), "c-1", action="comment")
    run = worker(factory, double, clock, http=losing_responses(double, "core/update"))

    run.drain()
    clock.advance(minutes=1)
    run.drain()

    assert [c.operation for c in double.writes] == ["core/update"]
    row = outbox_row(factory, row_id)
    assert (row.status, row.attempts, row.last_error) == ("done", 2, "already in iTop (retry)")


def test_a_write_for_a_ticket_that_will_never_exist_fails(factory: sessionmaker[Session]) -> None:
    ticket = new_ticket(factory)
    row_id = queue(factory, ticket.id, comment_payload("x"), "c-1", action="comment")

    worker(factory, ItopDouble(), Clock()).drain()

    row = outbox_row(factory, row_id)
    assert (row.status, row.last_error) == ("failed", "the ticket has no iTop id and no create is queued")


def test_reopen_applies_the_stimulus(factory: sessionmaker[Session]) -> None:
    double, clock = ItopDouble(), Clock()
    double.add("UserRequest", 70, title="t", status="resolved", ref="R-000070")
    ticket = new_ticket(factory, itop_id="70", status="resolved")
    row_id = queue(factory, ticket.id, stimulus_payload("ev_reopen"), "r-1", action="reopen")

    worker(factory, double, clock).drain()

    assert double.data["UserRequest"]["70"]["status"] == "assigned"
    assert outbox_row(factory, row_id).status == "done"


def test_a_lost_reopen_answer_is_not_applied_twice(factory: sessionmaker[Session]) -> None:
    double, clock = ItopDouble(), Clock()
    double.add("UserRequest", 72, title="t", status="resolved", ref="R-000072")
    ticket = new_ticket(factory, itop_id="72", status="resolved")
    row_id = queue(factory, ticket.id, stimulus_payload("ev_reopen"), "r-1", action="reopen")
    run = worker(factory, double, clock, http=losing_responses(double, "core/apply_stimulus"))

    run.drain()
    clock.advance(minutes=1)
    run.drain()

    row = outbox_row(factory, row_id)
    assert (row.status, row.last_error) == ("done", "already applied (retry)")


def test_a_stimulus_itop_refuses_fails(factory: sessionmaker[Session]) -> None:
    double, clock = ItopDouble(), Clock()
    double.add("UserRequest", 71, title="t", status="closed", ref="R-000071")
    ticket = new_ticket(factory, itop_id="71", status="closed")
    row_id = queue(factory, ticket.id, stimulus_payload("ev_reopen"), "r-1", action="reopen")

    worker(factory, double, clock).drain()

    assert outbox_row(factory, row_id).status == "failed"


def test_two_tickets_do_not_block_each_other(factory: sessionmaker[Session]) -> None:
    double, clock = ItopDouble(), Clock()
    with factory() as session, session.begin():
        team = make_team(session)
        blocked = make_ticket(session, team=team)
        free = make_ticket(session, team=team, itop_id="80")
    double.add("UserRequest", 80, title="t", status="new", ref="R-000080")
    double.down = True
    queue(factory, blocked.id, create_payload(ticket_fields(title="other")), "create-blocked")
    run = worker(factory, double, clock)
    run.drain()  # the create fails and waits for its retry
    double.down = False
    queue(factory, free.id, comment_payload("hola"), "c-free", action="comment")

    assert run.drain() == 1

    assert double.data["UserRequest"]["80"]["public_log"].startswith("hola")


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "comment", "log": "description", "text": "x"},
        {"kind": "stimulus", "stimulus": "ev_close"},
        {"kind": "delete"},
        {"kind": "comment", "log": "public_log"},
        {"kind": "update"},
        [],  # not even an object: still a permanent failure, never a stuck row
    ],
)
def test_a_corrupted_payload_fails_without_calling_itop(factory: sessionmaker[Session], payload: Any) -> None:
    double = ItopDouble()
    double.add("UserRequest", 90, title="t", status="new", ref="R-000090")
    ticket = new_ticket(factory, itop_id="90")
    row_id = queue(factory, ticket.id, comment_payload("x"), "c-1", action="comment")
    with factory() as session, session.begin():
        session.get_one(m.ItopOutbox, row_id).payload = payload

    worker(factory, double, Clock()).drain()

    assert outbox_row(factory, row_id).status == "failed"
    assert double.writes == []


def test_text_reaches_itop_html_encoded_and_the_payload_stays_plain(factory: sessionmaker[Session]) -> None:
    """F12.3 (ASVS V1.2.1): iTop stores the description and case logs as HTML and keeps links and remote images, so
    markup inside names, news or LLM text must arrive escaped, and line breaks as `<br>`."""
    double, clock = ItopDouble(), Clock()
    ticket = new_ticket(factory)
    hostile = 'Paso 1 <img src="https://evil.test/p.png">\nVer <a href="https://phish.test">parche</a> & "más"'
    create = queue(
        factory, ticket.id, create_payload({**ticket_fields(), "description": hostile}), f"create:{ticket.id}"
    )
    comment = queue(factory, ticket.id, comment_payload("<b>Nota</b>\nde Ana's", private=True), "c-1", action="suggest")

    assert worker(factory, double, clock).drain() == 2

    created = next(iter(double.data["UserRequest"].values()))
    assert created["description"] == (
        "Paso 1 &lt;img src=&quot;https://evil.test/p.png&quot;&gt;<br>"
        "Ver &lt;a href=&quot;https://phish.test&quot;&gt;parche&lt;/a&gt; &amp; &quot;más&quot;"
        f"<br><br>Ref. Hermes: {ticket.id}"
    )
    assert created["private_log"].startswith("&lt;b&gt;Nota&lt;/b&gt;<br>de Ana&#x27;s<br><br>[hermes:")
    assert "<img" not in json.dumps(double.data["UserRequest"]) and "<a " not in json.dumps(double.data["UserRequest"])
    assert outbox_row(factory, create).payload["fields"]["description"] == hostile  # stored as written
    assert outbox_row(factory, comment).payload["text"] == "<b>Nota</b>\nde Ana's"


def test_an_escaped_description_still_finds_our_ticket_on_retry(factory: sessionmaker[Session]) -> None:
    """The create marker has no character HTML escapes, so a retry still recognises our ticket (lost create answer)."""
    double, clock = ItopDouble(), Clock()
    ticket = new_ticket(factory)
    queue(factory, ticket.id, create_payload({**ticket_fields(), "description": "a < b"}), f"create:{ticket.id}")
    worker(factory, double, clock, http=losing_responses(double, "core/create")).drain()
    clock.advance(minutes=2)

    worker(factory, double, clock).drain()

    assert len(double.data["UserRequest"]) == 1
    assert reload(factory, ticket.id).itop_ticket_id is not None


def test_an_oversized_description_is_cut_but_the_ticket_is_created_and_found_again(
    factory: sessionmaker[Session],
) -> None:
    """iTop's description is a 65 535-byte TEXT column: escaping must not push a long description past it, and the
    `Ref. Hermes` marker (the create's idempotency) must survive the cut."""
    double, clock = ItopDouble(), Clock()
    ticket = new_ticket(factory)
    long_text = "\n".join(f"- CI {i} <expuesto> & dueño «Ñandú»" for i in range(4000))
    queue(factory, ticket.id, create_payload({**ticket_fields(), "description": long_text}), f"create:{ticket.id}")
    worker(factory, double, clock, http=losing_responses(double, "core/create")).drain()
    clock.advance(minutes=2)

    worker(factory, double, clock).drain()

    assert len(double.data["UserRequest"]) == 1  # the retry found the cut ticket by its marker
    created = next(iter(double.data["UserRequest"].values()))
    assert len(created["description"].encode()) < 65_535
    assert created["description"].endswith(
        f"Texto recortado: no cabe completo en iTop; el detalle está en Hermes.<br>Ref. Hermes: {ticket.id}"
    )
    assert reload(factory, ticket.id).itop_ticket_id == created["id"]


def test_every_write_carries_the_comment_itop_requires_as_its_userinfo(factory: sessionmaker[Session]) -> None:
    """iTop 3.2.2 refuses core/create, core/update and core/apply_stimulus without `comment` (checked live, F12.3)
    and keeps it as the change's userinfo, which TicketStateSync compares with ITOP_SYSTEM_USER (D-007)."""
    double, clock = ItopDouble(require_comment=True), Clock()
    ticket = new_ticket(factory)
    queue(factory, ticket.id, create_payload(ticket_fields()), f"create:{ticket.id}")
    queue(factory, ticket.id, update_payload({"urgency": "1"}), "u-1", action="raise_urgency")
    queue(factory, ticket.id, comment_payload("Sigue presente"), "c-1", action="comment")
    writer = build_writer("http://localhost", str(double.token), http=double.client(), track_info="hermes-system")

    assert ItopOutboxWorker(factory, writer, clock=clock).drain() == 3

    assert double.write_comments == ["hermes-system"] * 3
    with factory() as session:
        assert set(session.scalars(select(m.ItopOutbox.status))) == {"done"}


def test_the_writer_from_settings_signs_its_writes_with_the_system_user() -> None:
    settings = Settings(
        _env_file=None,
        cursor_signing_key=SecretStr("k" * 40),
        database_url=SecretStr("postgresql://app:pw@db/hermes"),
        firebase_project_id="demo-hermes",
        itop_url="https://itop.example.test",
        itop_token=SecretStr("t"),
        itop_system_user="  hermes-rest  ",
    )
    assert writer_from_settings(settings).track_info == "hermes-rest"
    unset = settings.model_copy(update={"itop_system_user": None})
    assert writer_from_settings(unset).track_info == "Hermes"


def test_a_comment_written_with_the_older_short_marker_is_not_sent_twice(factory: sessionmaker[Session]) -> None:
    """A row retried after the upgrade still finds the 16-digit marker of its first attempt (PRE-02, F5.1 #43)."""
    double, clock = ItopDouble(), Clock()
    ticket = new_ticket(factory, itop_id="61")
    legacy = {"kind": "comment", "log": "public_log", "text": "Hola"}  # queued before F12.2: no `marker` key
    row_id = queue(factory, ticket.id, legacy, "c-old", action="comment")
    # The first attempt (before the upgrade) wrote the comment with the short marker and lost the answer.
    earlier = f"Hola\n\n[hermes:{row_id.hex[:16]}]"
    double.add("UserRequest", 61, title="t", status="new", ref="R-000061", public_log=earlier)
    with factory() as session, session.begin():
        session.get_one(m.ItopOutbox, row_id).attempts = 1

    worker(factory, double, clock).drain()

    assert double.writes == []
    row = outbox_row(factory, row_id)
    assert (row.status, row.attempts, row.last_error) == ("done", 2, "already in iTop (retry)")


def test_a_newer_row_never_takes_the_short_marker_of_another_row(factory: sessionmaker[Session]) -> None:
    """A row queued after F12.2 only recognises its whole id, even if an older row's short marker matches its prefix
    (F5.1 #43, ARQ-01)."""
    double, clock = ItopDouble(), Clock()
    ticket = new_ticket(factory, itop_id="62")
    row_id = queue(factory, ticket.id, comment_payload("Hola"), "c-new", action="comment")
    other = f"Otro\n\n[hermes:{row_id.hex[:16]}]"  # same prefix, written by another, older row
    double.add("UserRequest", 62, title="t", status="new", ref="R-000062", public_log=other)
    with factory() as session, session.begin():
        session.get_one(m.ItopOutbox, row_id).attempts = 1

    worker(factory, double, clock).drain()

    assert [c.operation for c in double.writes] == ["core/update"]
    assert outbox_row(factory, row_id).status == "done"


def test_an_older_row_first_sent_after_the_change_is_stamped_and_ignores_short_markers(
    factory: sessionmaker[Session],
) -> None:
    """Queued before F12.2 (no `marker` key) but first sent now: it writes the whole id, so a retry never takes another
    row's short marker (F5.1 #43)."""
    double, clock = ItopDouble(), Clock()
    ticket = new_ticket(factory, itop_id="63")
    legacy = {"kind": "comment", "log": "public_log", "text": "Hola"}
    row_id = queue(factory, ticket.id, legacy, "c-legacy", action="comment")
    other = f"Otro\n\n[hermes:{row_id.hex[:16]}]"  # another row's short marker with the same prefix
    double.add("UserRequest", 63, title="t", status="new", ref="R-000063", public_log=other)
    run = worker(factory, double, clock, http=losing_responses(double, "core/update"))

    run.drain()  # first attempt: written with the whole id, answer lost
    clock.advance(minutes=1)
    run.drain()  # retry: finds its own whole-id marker

    row = outbox_row(factory, row_id)
    assert row.payload["marker"] == "full"
    assert (row.status, row.last_error) == ("done", "already in iTop (retry)")
    assert re.search(r"\[hermes:[0-9a-f]{32}\]", double.data["UserRequest"]["63"]["public_log"])


def test_a_legacy_row_does_not_take_another_comment_with_its_short_marker(factory: sessionmaker[Session]) -> None:
    """A row first tried before F12.2 only counts as written when its own text precedes the short marker (ARQ-01)."""
    double, clock = ItopDouble(), Clock()
    ticket = new_ticket(factory, itop_id="64")
    legacy = {"kind": "comment", "log": "public_log", "text": "Hola"}
    row_id = queue(factory, ticket.id, legacy, "c-legacy-2", action="comment")
    other = f"Otro comentario\n\n[hermes:{row_id.hex[:16]}]"  # another row's entry with the same short marker
    double.add("UserRequest", 64, title="t", status="new", ref="R-000064", public_log=other)
    with factory() as session, session.begin():
        session.get_one(m.ItopOutbox, row_id).attempts = 1  # its first attempt failed before writing

    worker(factory, double, clock).drain()

    assert [c.operation for c in double.writes] == ["core/update"]
    assert outbox_row(factory, row_id).status == "done"


def test_adding_an_owner_keeps_the_contacts_a_person_added(factory: sessionmaker[Session]) -> None:
    """`contacts_list` replaces the whole list in iTop: the worker merges it with what the ticket has (F5.2 #54)."""
    double, clock = ItopDouble(), Clock()
    manual = [{"contact_id": "7", "role": "Seguridad", "role_code": "manual", "contact_id_friendlyname": "Ana"}]
    double.add("UserRequest", 70, title="t", status="new", ref="R-000070", contacts_list=manual)
    ticket = new_ticket(factory, itop_id="70")
    owners = [{"contact_id": "9"}, {"contact_id": "7"}]
    queue(factory, ticket.id, update_payload({"contacts_list": owners}), "u-contacts", action="add_owner")

    worker(factory, double, clock).drain()

    assert double.data["UserRequest"]["70"]["contacts_list"] == [
        {"contact_id": "7", "role": "Seguridad", "role_code": "manual"},
        {"contact_id": "9"},
    ]
