"""Shared HTTP plumbing for the vulnerability sources."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from core.vulndata.http import JsonSource, RateLimiter, SourceRefusedError, SourceUnavailableError

URL = "https://source.test/api"


def scripted(*steps: Callable[[httpx.Request], httpx.Response]) -> tuple[httpx.Client, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return steps[len(seen) - 1](request)

    return httpx.Client(transport=httpx.MockTransport(handler)), seen


def ok(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"ok": True})


def status(code: int, **headers: str) -> Callable[[httpx.Request], httpx.Response]:
    return lambda _request: httpx.Response(code, headers=headers)


def test_get_and_post_return_json_and_send_params_headers_and_timeout() -> None:
    client, seen = scripted(ok, ok)
    source = JsonSource(http=client, timeout=7.0)
    assert source.get(URL, params={"a": 1}, headers={"apiKey": "k"}) == {"ok": True}
    assert source.post(URL, {"q": 1}) == {"ok": True}
    assert seen[0].url.params["a"] == "1" and seen[0].headers["apiKey"] == "k"
    assert seen[0].extensions["timeout"]["connect"] == 7.0
    assert seen[1].method == "POST" and seen[1].content == b'{"q":1}'


def test_retries_transport_errors_and_retryable_statuses_with_backoff() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    client, seen = scripted(boom, status(503), status(429, **{"Retry-After": "5"}), ok)
    sleeps: list[float] = []
    source = JsonSource(http=client, max_attempts=4, backoff_seconds=1.0, sleep=sleeps.append)
    assert source.get(URL) == {"ok": True}
    assert len(seen) == 4
    assert sleeps == [1.0, 2.0, 5.0]


def test_gives_up_with_a_message_that_has_no_url_or_key() -> None:
    client, _ = scripted(status(500), status(500))
    source = JsonSource(http=client, max_attempts=2, sleep=lambda _s: None)
    with pytest.raises(SourceUnavailableError, match="HTTP 500 after 2 attempts") as raised:
        source.get(URL, params={"apiKey": "secret-key"})
    assert "secret-key" not in str(raised.value) and "source.test" not in str(raised.value)


def test_non_retryable_status_is_refused_at_once() -> None:
    client, seen = scripted(status(404))
    with pytest.raises(SourceRefusedError) as raised:
        JsonSource(http=client).get(URL)
    assert raised.value.status == 404 and len(seen) == 1


def test_retryable_set_is_configurable() -> None:
    client, seen = scripted(status(403), ok)
    source = JsonSource(http=client, retryable=frozenset({403}), sleep=lambda _s: None)
    assert source.get(URL) == {"ok": True} and len(seen) == 2


def test_bad_json_is_unavailable() -> None:
    client, _ = scripted(lambda _r: httpx.Response(200, text="<html>"))
    with pytest.raises(SourceUnavailableError, match="JSON"):
        JsonSource(http=client).get(URL)


def test_oversized_answer_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("core.vulndata.http.MAX_BODY_BYTES", 5)
    client, _ = scripted(ok)
    with pytest.raises(SourceUnavailableError, match="too large"):
        JsonSource(http=client).get(URL)


def test_default_client_is_created_and_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    client, _ = scripted(ok)
    monkeypatch.setattr(httpx, "Client", lambda **_kw: client)
    assert JsonSource().get(URL) == {"ok": True}
    assert client.is_closed


def test_rate_limiter_waits_for_the_window_to_free_up() -> None:
    now = [0.0]
    slept: list[float] = []

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        now[0] += seconds

    limiter = RateLimiter(max_calls=2, period=30.0, clock=lambda: now[0], sleep=sleep)
    limiter.acquire()
    now[0] = 10.0
    limiter.acquire()
    limiter.acquire()  # third call inside the window: waits until the first one is 30 s old
    assert slept == [20.0]
    now[0] = 100.0
    limiter.acquire()
    assert slept == [20.0]


def test_limiter_is_applied_before_every_attempt() -> None:
    client, _ = scripted(status(503), ok)
    calls: list[int] = []
    limiter = RateLimiter(max_calls=100, period=1.0)
    object.__setattr__(limiter, "acquire", lambda: calls.append(1))
    JsonSource(http=client, limiter=limiter, sleep=lambda _s: None).get(URL)
    assert len(calls) == 2


def test_get_bytes_returns_the_raw_body_with_retries() -> None:
    client, seen = scripted(status(503), lambda _r: httpx.Response(200, content=b"\x1f\x8bdata"))
    assert JsonSource(http=client, sleep=lambda _s: None).get_bytes(URL) == b"\x1f\x8bdata"
    assert len(seen) == 2


def test_get_bytes_refuses_oversized_bodies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("core.vulndata.http.MAX_BODY_BYTES", 2)
    client, _ = scripted(lambda _r: httpx.Response(200, content=b"abc"))
    with pytest.raises(SourceUnavailableError, match="too large"):
        JsonSource(http=client).get_bytes(URL)
