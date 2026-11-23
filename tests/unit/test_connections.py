"""Connection probes and checker (D-042, SEG-23): no network, no secret in any answer."""

from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from google.auth.exceptions import RefreshError

from core.config import Settings
from core.connections.checker import ConnectionChecker
from core.connections.probes import MSG_OFFLINE, MSG_OK, MSG_REJECTED, MSG_UNEXPECTED, NAMES, Name, ProbeResult, Probes

pytestmark = pytest.mark.unit
FAKE_KEY = "fake-credential-value-123"
BASE = {"database_url": "postgresql://a:b@db/h", "firebase_project_id": "p", "cursor_signing_key": "k" * 40}
ALL_KEYS = {
    "itop_url": "https://itop.example.test",
    "itop_token": FAKE_KEY,
    "deepseek_api_key": FAKE_KEY,
    "nvd_api_key": FAKE_KEY,
    "abusech_auth_key": FAKE_KEY,
    "ransomwarelive_api_key": FAKE_KEY,
    "firebase_credentials_file": "/run/secrets/firebase.json",
}
Handler = Callable[[httpx.Request], httpx.Response]


def settings(**values: str) -> Settings:
    return Settings.model_validate({**BASE, **values})


def probes(handler: Handler, *, token_fetcher: Callable[[Path], None] | None = None, **values: str) -> Probes:
    return Probes(
        settings(**values),
        httpx.Client(transport=httpx.MockTransport(handler)),
        clock=iter([0.0, 0.25] * 10).__next__,
        token_fetcher=token_fetcher,
        environ=lambda _name: None,
    )


def never(_request: httpx.Request) -> httpx.Response:
    raise AssertionError("no call is expected")


@pytest.mark.parametrize(
    ("name", "variable"),
    [
        ("itop", "ITOP_URL"),
        ("deepseek", "DEEPSEEK_API_KEY"),
        ("nvd", "NVD_API_KEY"),
        ("abusech", "ABUSECH_AUTH_KEY"),
        ("ransomwarelive", "RANSOMWARELIVE_API_KEY"),
        ("firebase", "FIREBASE_CREDENTIALS_FILE"),
    ],
)
def test_a_missing_variable_is_named_and_nothing_is_called(name: Name, variable: str) -> None:
    result = probes(never).get(name)()
    assert result == ProbeResult(
        ok=False, latency_ms=None, message=f"Variable faltante: {variable}", missing_variable=variable
    )


def test_itop_token_without_url_and_url_without_token() -> None:
    assert probes(never, itop_token=FAKE_KEY).itop().missing_variable == "ITOP_URL"
    assert probes(never, itop_url="https://itop.example.test").itop().missing_variable == "ITOP_TOKEN"


def ok_for_every_service(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    if host == "itop.example.test":
        assert request.headers["Auth-Token"] == FAKE_KEY
        return httpx.Response(200, json={"code": 0, "operations": []})
    if host == "api.deepseek.com":
        assert request.url.path.endswith("/models") and request.headers["Authorization"] == f"Bearer {FAKE_KEY}"
        return httpx.Response(200, json={"data": []})
    if host == "services.nvd.nist.gov":
        assert request.headers["apiKey"] == FAKE_KEY and request.url.params["cveId"] == "CVE-2021-44228"
        return httpx.Response(200, json={"vulnerabilities": []})
    if host == "urlhaus-api.abuse.ch":
        assert request.headers["Auth-Key"] == FAKE_KEY
        return httpx.Response(200, json={"query_status": "ok", "urls": []})
    if host == "api-pro.ransomware.live":
        assert request.headers["X-API-KEY"] == FAKE_KEY
        return httpx.Response(200, json={"collections": []})
    raise AssertionError(f"unexpected host {host}")


@pytest.mark.parametrize("name", NAMES)
def test_every_service_answers_ok_with_its_latency(name: Name) -> None:
    result = probes(ok_for_every_service, token_fetcher=lambda _path: None, **ALL_KEYS).get(name)()
    assert result == ProbeResult(ok=True, latency_ms=250, message=MSG_OK)


@pytest.mark.parametrize("name", ["deepseek", "nvd", "abusech", "ransomwarelive"])
@pytest.mark.parametrize(("status", "message"), [(401, MSG_REJECTED), (403, MSG_REJECTED), (500, MSG_UNEXPECTED)])
def test_http_answers_are_reduced_to_a_generic_message(name: Name, status: int, message: str) -> None:
    def echo(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text=f"bad key {request.headers}")

    result = probes(echo, **ALL_KEYS).get(name)()
    assert (result.ok, result.message) == (False, message)
    assert FAKE_KEY not in repr(result)


@pytest.mark.parametrize("name", ["itop", "deepseek", "nvd", "abusech", "ransomwarelive"])
def test_an_unreachable_service_is_offline(name: Name) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    assert probes(down, **ALL_KEYS).get(name)() == ProbeResult(ok=False, latency_ms=None, message=MSG_OFFLINE)


def test_urlhaus_must_confirm_the_query_and_itop_must_accept_the_token() -> None:
    not_json = probes(lambda _r: httpx.Response(200, text="<html>"), **ALL_KEYS)
    assert not_json.abusech().message == MSG_UNEXPECTED
    refused = probes(lambda _r: httpx.Response(200, json={"query_status": "unknown_auth_key"}), **ALL_KEYS)
    assert refused.abusech().message == MSG_UNEXPECTED
    unauthorized = probes(lambda _r: httpx.Response(200, json={"code": 1, "message": FAKE_KEY}), **ALL_KEYS)
    assert (unauthorized.itop().ok, unauthorized.itop().message) == (False, MSG_REJECTED)
    other = probes(lambda _r: httpx.Response(200, json={"code": 100}), **ALL_KEYS)
    assert other.itop().message == MSG_UNEXPECTED


def test_firebase_emulator_and_a_rejected_service_account() -> None:
    def emulator(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "http://auth:9099/"
        return httpx.Response(200, text="Ready")

    with_emulator = Probes(
        settings(), httpx.Client(transport=httpx.MockTransport(emulator)), environ=lambda _n: "auth:9099"
    )
    assert with_emulator.firebase().ok is True

    def refused(_path: Path) -> None:
        raise RefreshError(f"invalid_grant {FAKE_KEY}")

    result = probes(never, token_fetcher=refused, **ALL_KEYS).firebase()
    assert result == ProbeResult(ok=False, latency_ms=None, message=MSG_REJECTED)


def test_the_real_token_fetcher_refuses_a_missing_file(tmp_path: Path) -> None:
    result = probes(never, firebase_credentials_file=str(tmp_path / "absent.json")).firebase()
    assert (result.ok, result.message) == (False, MSG_REJECTED)
    broken = tmp_path / "broken.json"
    broken.write_text("{}")  # not a credential at all
    assert probes(never, firebase_credentials_file=str(broken)).firebase().ok is False


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


def counting(results: dict[Name, ProbeResult]) -> tuple[Callable[[Name], Callable[[], ProbeResult]], dict[str, int]]:
    calls: dict[str, int] = {}

    def probe_of(name: Name) -> Callable[[], ProbeResult]:
        def run() -> ProbeResult:
            calls[name] = calls.get(name, 0) + 1
            return results.get(name, ProbeResult(ok=True, latency_ms=10, message=MSG_OK))

        return run

    return probe_of, calls


def test_status_reuses_fresh_results_and_remembers_the_last_success() -> None:
    clock = Clock()
    results: dict[Name, ProbeResult] = {}
    probe_of, calls = counting(results)
    checker = ConnectionChecker(probe_of, clock=clock)
    first = checker.status()
    assert [s.name for s in first] == list(NAMES) and all(s.ok for s in first)
    clock.now += timedelta(minutes=1)
    checker.status()
    assert calls == dict.fromkeys(NAMES, 1)  # still fresh: nothing checked again
    clock.now += timedelta(minutes=5)
    results["nvd"] = ProbeResult(ok=False, latency_ms=None, message=MSG_OFFLINE)
    nvd = next(s for s in checker.status() if s.name == "nvd")
    assert (nvd.ok, nvd.checked_at, nvd.last_ok_at) == (False, clock.now, clock.now - timedelta(minutes=6))
    assert calls["nvd"] == 2


def test_test_forces_a_check_but_not_more_than_every_30_seconds() -> None:
    clock = Clock()
    probe_of, calls = counting({})
    checker = ConnectionChecker(probe_of, clock=clock)
    assert [s.name for s in checker.test(["itop", "nvd"])] == ["itop", "nvd"]
    clock.now += timedelta(seconds=10)
    checker.test(["itop"])
    assert calls == {"itop": 1, "nvd": 1}
    clock.now += timedelta(seconds=30)
    checker.test()
    assert calls["itop"] == 2 and calls["firebase"] == 1


def test_a_hung_probe_is_cut_at_the_deadline() -> None:
    release = threading.Event()

    def probe_of(_name: Name) -> Callable[[], ProbeResult]:
        def hang() -> ProbeResult:
            release.wait(5)
            return ProbeResult(ok=True, latency_ms=1, message=MSG_OK)

        return hang

    checker = ConnectionChecker(probe_of, deadline=0.05)
    try:
        states = checker.test(["deepseek"])
    finally:
        release.set()
    assert (states[0].ok, states[0].message) == (False, MSG_OFFLINE)
