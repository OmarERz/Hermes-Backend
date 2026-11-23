"""Outbox payload builders, backoff and the private iTop writer (no database: see tests/integration/f05_tickets)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
from pydantic import SecretStr

from core.itop.client import ItopError, ItopUnavailableError
from core.itop.outbox import (
    ItopWrite,
    backoff,
    build_writer,
    comment_payload,
    create_payload,
    record_write,
    stimulus_payload,
    update_payload,
    utcnow,
    writer_from_settings,
)
from doubles.itop import ItopDouble

pytestmark = pytest.mark.unit


def test_payload_builders_validate_their_input() -> None:
    assert create_payload({"title": "t"}, fallback_team_id="9") == {
        "kind": "create",
        "fields": {"title": "t"},
        "fallback_team_id": "9",
    }
    assert update_payload({"urgency": "2"}) == {"kind": "update", "fields": {"urgency": "2"}}
    assert comment_payload("hola") == {"kind": "comment", "log": "public_log", "text": "hola", "marker": "full"}
    assert comment_payload("x", private=True)["log"] == "private_log"
    assert stimulus_payload("ev_reopen") == {"kind": "stimulus", "stimulus": "ev_reopen"}
    with pytest.raises(ValueError, match="title"):
        create_payload({"title": "  "})
    with pytest.raises(ValueError, match="control characters"):
        create_payload({"title": "a\nb"})
    with pytest.raises(ValueError, match="at least one field"):
        update_payload({})
    with pytest.raises(ValueError, match="comment_payload"):
        update_payload({"public_log": "x"})
    with pytest.raises(ValueError, match="needs text"):
        comment_payload(" ")
    with pytest.raises(ValueError, match="unsupported stimulus"):
        stimulus_payload("ev_close")


def test_record_write_rejects_unknown_payloads_and_blank_keys() -> None:
    session = MagicMock()
    now = datetime(2026, 11, 22, tzinfo=UTC)
    with pytest.raises(ValueError, match="payload kind"):
        record_write(session, ItopWrite(uuid.uuid4(), "comment", {}, "k"), now)
    with pytest.raises(ValueError, match="idempotency key"):
        record_write(session, ItopWrite(uuid.uuid4(), "comment", comment_payload("x"), " "), now)
    session.add.assert_not_called()


@pytest.mark.parametrize(("attempts", "minutes"), [(0, 1), (1, 1), (2, 2), (3, 4), (6, 32), (7, 60), (10, 60)])
def test_backoff_doubles_up_to_an_hour(attempts: int, minutes: int) -> None:
    assert backoff(attempts) == timedelta(minutes=minutes)


def test_the_writer_sends_writes_with_one_attempt() -> None:
    double = ItopDouble(down=True)
    writer = build_writer("http://localhost", "test-token", http=double.client(), sleep=lambda _: None)
    with pytest.raises(ItopUnavailableError, match="after 1 attempts"):
        writer.write({"operation": "core/update", "class": "UserRequest", "key": "1", "fields": {"urgency": "1"}})


def test_the_writer_refuses_unknown_operations() -> None:
    writer = build_writer("http://localhost", "test-token", http=ItopDouble().client())
    with pytest.raises(ValueError, match="unsupported"):
        writer.call({"operation": "core/delete"})


@pytest.mark.parametrize(
    "body",
    [
        {"code": 0, "objects": None},
        {"code": 0, "objects": {"a": {"key": "1"}, "b": {"key": "2"}}},
        {"code": 0, "objects": {"a": {"key": "0", "fields": {}}}},
    ],
)
def test_the_writer_rejects_unexpected_answers(body: dict[str, Any]) -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body)))
    writer = build_writer("http://localhost", "test-token", http=client)
    with pytest.raises(ItopUnavailableError):
        writer.write({"operation": "core/update", "class": "UserRequest", "key": "1", "fields": {}})


def test_writer_from_settings_fails_closed() -> None:
    settings = MagicMock(itop_url=None, itop_token=None)
    with pytest.raises(ValueError, match="ITOP_URL"):
        writer_from_settings(settings)
    settings = MagicMock(itop_url="https://itop.example.test", itop_token=SecretStr("tok"))
    writer = writer_from_settings(settings)
    assert writer.endpoint == "https://itop.example.test/webservices/rest.php?version=1.3"
    assert writer.max_attempts == 1


def test_the_writer_opens_and_closes_its_own_client(monkeypatch: pytest.MonkeyPatch) -> None:
    double = ItopDouble()
    double.add("UserRequest", 7, title="t", status="new", ref="R-000007")
    opened: list[httpx.Client] = []
    real_client = httpx.Client

    def client_factory(**kwargs: Any) -> httpx.Client:
        client = real_client(transport=double.transport, **kwargs)
        opened.append(client)
        return client

    monkeypatch.setattr("core.itop.outbox.httpx.Client", client_factory)
    writer = build_writer("http://localhost", "test-token")
    assert writer.write({"operation": "core/update", "class": "UserRequest", "key": "7", "fields": {}}) == (
        "7",
        "R-000007",
    )
    assert opened[0].is_closed


def test_utcnow_is_aware() -> None:
    assert utcnow().tzinfo is UTC


def test_itop_error_keeps_only_the_attribute_names_it_knows() -> None:
    error = ItopError(100, "Error: team_id: ana.rivera@example.test not allowed")
    assert error.attributes == {"team_id"}
    assert "ana" not in str(error)
    assert "ana" not in repr(error.__dict__)
    assert error.args == ("iTop refused the operation (code 100)",)
