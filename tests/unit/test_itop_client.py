"""Read-only iTop client: authentication, retries, timeouts, URL safety and OQL escaping."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from core.config import Settings
from core.itop import oql
from core.itop.client import ItopError, ItopReader, ItopUnavailableError, reader_from_settings
from doubles.itop import ItopDouble

URL = "http://localhost:8080"
TOKEN = str(ItopDouble().token)  # the double's fake credential


def reader_for(double: ItopDouble, **kwargs: Any) -> ItopReader:
    return ItopReader(URL, TOKEN, http=double.client(), **kwargs)


def scripted(*steps: Callable[[httpx.Request], httpx.Response]) -> tuple[httpx.Client, list[httpx.Request]]:
    """A client whose n-th request is answered by the n-th step."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return steps[len(seen) - 1](request)

    return httpx.Client(transport=httpx.MockTransport(handler)), seen


def ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"code": 0, "message": "", "objects": None})


def test_get_returns_objects_with_their_real_class() -> None:
    reader = reader_for(ItopDouble.from_fixture())
    query = oql.select("FunctionalCI", oql.eq("name", "web-frontend-01"))
    found = reader.get("FunctionalCI", query, ["name", "owner_id"])
    assert [(o.class_name, o.text("name"), o.text("owner_id")) for o in found] == [("Server", "web-frontend-01", "20")]


def test_get_without_match_is_empty_and_unset_keys_are_none() -> None:
    reader = reader_for(ItopDouble.from_fixture())
    assert reader.get("Server", oql.select("Server", oql.eq("name", "nope"))) == []
    vm = reader.get("VirtualMachine", "SELECT VirtualMachine")[0]
    assert vm.text("owner_id") is None
    assert vm.text("missing_attribute") is None


def test_token_goes_in_the_header_and_never_in_the_url_or_logs(caplog: pytest.LogCaptureFixture) -> None:
    double = ItopDouble.from_fixture()
    reader = reader_for(double)
    assert reader.list_operations()[0] == "core/get"
    assert double.calls[0].auth == "token"
    assert TOKEN not in reader.endpoint
    assert TOKEN not in repr(reader)
    assert TOKEN not in caplog.text


def test_only_read_operations_are_sent() -> None:
    double = ItopDouble.from_fixture()
    reader = reader_for(double)
    reader.get("Server", "SELECT Server")
    reader.list_operations()
    assert set(double.operations) == {"core/get", "list_operations"}
    assert double.writes == []


def test_refused_operation_raises_itop_error_without_retry() -> None:
    sleeps: list[float] = []
    double = ItopDouble.from_fixture()
    reader = reader_for(double, sleep=sleeps.append)
    with pytest.raises(ItopError) as raised:
        reader.get("Server", "SELECT Server WHERE name ~~ 'x'")
    assert raised.value.code == 100
    assert len(double.calls) == 1
    assert sleeps == []


def test_bad_token_is_a_refusal_not_an_outage() -> None:
    double = ItopDouble.from_fixture()
    reader = ItopReader(URL, "wrong", http=double.client())
    with pytest.raises(ItopError) as raised:
        reader.list_operations()
    assert raised.value.code == 1


def test_retries_network_errors_with_exponential_backoff_then_succeeds() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    client, seen = scripted(boom, boom, ok)
    sleeps: list[float] = []
    reader = ItopReader(URL, TOKEN, http=client, sleep=sleeps.append, backoff_seconds=0.5)
    assert reader.get("Server", "SELECT Server") == []
    assert len(seen) == 3
    assert sleeps == [0.5, 1.0]


def test_gives_up_after_max_attempts_without_leaking_the_token() -> None:
    def down(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    client, seen = scripted(down, down)
    reader = ItopReader(URL, TOKEN, http=client, max_attempts=2, sleep=lambda _s: None)
    with pytest.raises(ItopUnavailableError, match="HTTP 503 after 2 attempts") as raised:
        reader.list_operations()
    assert len(seen) == 2
    assert TOKEN not in str(raised.value)


def test_retry_after_header_is_honoured_and_capped() -> None:
    def limited(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "7"})

    def very_limited(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "99999"})

    def garbage(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "tomorrow"})

    client, _ = scripted(limited, very_limited, garbage, ok)
    sleeps: list[float] = []
    reader = ItopReader(URL, TOKEN, http=client, max_attempts=4, sleep=sleeps.append, backoff_seconds=0.5)
    reader.get("Server", "SELECT Server")
    assert sleeps == [7.0, 30.0, 2.0]


def test_client_error_status_is_not_retried() -> None:
    client, seen = scripted(lambda request: httpx.Response(404, text="not found"))
    with pytest.raises(ItopUnavailableError, match="HTTP 404"):
        ItopReader(URL, TOKEN, http=client, sleep=lambda _s: None).get("Server", "SELECT Server")
    assert len(seen) == 1


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, text="<html>maintenance</html>"),
        httpx.Response(200, json=["not", "an", "object"]),
        httpx.Response(200, json={"message": "no code"}),
    ],
)
def test_answers_that_are_not_itop_json_are_unavailable(response: httpx.Response) -> None:
    client, _ = scripted(lambda request: response)
    with pytest.raises(ItopUnavailableError):
        ItopReader(URL, TOKEN, http=client).get("Server", "SELECT Server")


def test_unreachable_host_is_unavailable() -> None:
    reader = reader_for(ItopDouble.from_fixture(down=True), max_attempts=1)
    with pytest.raises(ItopUnavailableError, match="ConnectError"):
        reader.list_operations()


def test_request_has_an_explicit_timeout_and_form_payload() -> None:
    captured: list[httpx.Request] = []

    def spy(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return ok(request)

    client, _ = scripted(spy)
    ItopReader(URL, TOKEN, http=client).get("Server", "SELECT Server", ["name", "managementip"])
    request = captured[0]
    assert request.url.path == "/webservices/rest.php"
    assert request.url.params["version"] == "1.3"
    assert request.extensions["timeout"]["read"] == 15.0
    body = dict(httpx.QueryParams(request.content.decode()))
    assert json.loads(body["json_data"]) == {
        "operation": "core/get",
        "class": "Server",
        "key": "SELECT Server",
        "output_fields": "name,managementip",
    }


@pytest.mark.parametrize(
    "url",
    ["https://itop.example.com/", "http://localhost:8080", "http://127.0.0.1:8080", "http://host.docker.internal:8080"],
)
def test_safe_urls_are_accepted(url: str) -> None:
    assert ItopReader(url, TOKEN).endpoint.endswith("/webservices/rest.php?version=1.3")


@pytest.mark.parametrize(
    "url", ["http://itop.example.com", "ftp://localhost", "https://user:pw@itop.example.com", "not a url"]
)
def test_unsafe_urls_are_rejected(url: str) -> None:
    with pytest.raises(ValueError, match=r"iTop|plain http"):
        ItopReader(url, TOKEN)


def test_plain_http_to_remote_needs_an_explicit_switch_and_a_token_is_mandatory() -> None:
    assert ItopReader("http://itop.example.com", TOKEN, allow_insecure_http=True)
    with pytest.raises(ValueError, match="token"):
        ItopReader(URL, "  ")
    with pytest.raises(ValueError, match="max_attempts"):
        ItopReader(URL, TOKEN, max_attempts=0)


def test_default_client_is_created_and_closed_per_call(monkeypatch: pytest.MonkeyPatch) -> None:
    double = ItopDouble.from_fixture()
    scripted_client = double.client()
    monkeypatch.setattr(httpx, "Client", lambda **_kw: scripted_client)
    assert ItopReader(URL, TOKEN).list_operations()[0] == "core/get"


def settings(**values: Any) -> Settings:
    base: dict[str, Any] = {
        "_env_file": None,
        "database_url": SecretStr("postgresql://app:pw@db/hermes"),
        "firebase_project_id": "demo",
    }
    return Settings(**(base | values))


def test_reader_from_settings_fails_closed_when_unconfigured() -> None:
    with pytest.raises(ValueError, match="ITOP_URL and ITOP_TOKEN"):
        reader_from_settings(settings())
    configured = settings(itop_url="https://itop.example.com", itop_token=SecretStr("t0k"))
    assert reader_from_settings(configured).base_url == "https://itop.example.com"


def test_oql_quotes_and_rejects_injection() -> None:
    assert oql.quote("it's") == "'it\\'s'"
    assert oql.quote("a\\b") == "'a\\\\b'"
    assert oql.select("Server", oql.eq("name", "x' OR 1=1 --")) == "SELECT Server WHERE name = 'x\\' OR 1=1 --'"
    assert oql.select("Server", oql.in_("id", [1, 2]), oql.in_("status", ["obsolete"], negate=True)) == (
        "SELECT Server WHERE id IN ('1', '2') AND status NOT IN ('obsolete')"
    )
    assert oql.select("Server") == "SELECT Server"
    with pytest.raises(ValueError, match="control characters"):
        oql.quote("a\nb")
    with pytest.raises(ValueError, match="at least one"):
        oql.in_("id", [])
    for bad in ("", "Server; DROP", "na me", "ñame"):
        with pytest.raises(ValueError, match="invalid class or field name"):
            oql.select(bad)
        with pytest.raises(ValueError, match="invalid class or field name"):
            oql.eq(bad, "x")
