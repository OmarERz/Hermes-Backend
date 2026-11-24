"""Prompt worker shutdown (#170): every client that waits on the network honours the worker's stop signal.

No network: respx, `httpx.MockTransport` and FakeWeb answer; the only real process is a short Python child.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from typing import Any

import httpx
import pytest

from core.ingestion.embeddings import EMBEDDING_DIMENSIONS, EMBEDDING_MODEL, HttpEmbedder, HttpEmbedderConfig
from core.ingestion.fetcher import Fetcher
from core.llm import ToolCall
from core.llm.stoppable import StoppableCaller, stoppable_runner
from core.shutdown import ShutdownRequested, StopSignal
from core.vulndata.http import JsonSource
from core.vulndata.nvd import nvd_client
from doubles.web import FakeWeb

pytestmark = pytest.mark.unit
FAST = 2.0  # seconds: every interrupted wait below would otherwise last 30 s or more


def set_after(signal: StopSignal, seconds: float) -> threading.Timer:
    timer = threading.Timer(seconds, signal.event.set)
    timer.start()
    return timer


# --- the signal ---------------------------------------------------------------------------------------------------
def test_a_default_signal_never_stops_and_sleeps_the_whole_time() -> None:
    signal = StopSignal()
    signal.check()
    started = time.monotonic()
    signal.sleep(0.05)
    assert time.monotonic() - started >= 0.05


def test_a_set_signal_raises_on_check_and_on_sleep() -> None:
    signal = StopSignal()
    signal.event.set()
    with pytest.raises(ShutdownRequested):
        signal.check()
    with pytest.raises(ShutdownRequested):
        signal.sleep(30)


def test_a_sleep_wakes_up_as_soon_as_the_signal_is_set() -> None:
    signal = StopSignal()
    set_after(signal, 0.05)
    started = time.monotonic()
    with pytest.raises(ShutdownRequested):
        signal.sleep(60)
    assert time.monotonic() - started < FAST


def test_shutdown_is_not_swallowed_by_the_per_item_guards() -> None:
    assert not issubclass(ShutdownRequested, Exception)  # `except Exception` keeps a cycle going, not a shutdown


# --- news fetcher and embeddings ----------------------------------------------------------------------------------
def test_the_fetcher_checks_the_signal_before_each_request() -> None:
    web = FakeWeb()
    web.serve("https://news.example.com/feed", b"<rss/>")
    signal = StopSignal()
    fetcher = Fetcher(transport=web.transport(), resolver=lambda _host: ["93.184.216.34"], stop=signal)
    assert fetcher.get("https://news.example.com/feed").body == b"<rss/>"
    signal.event.set()
    with pytest.raises(ShutdownRequested):
        fetcher.get("https://news.example.com/feed")
    assert len(web.requests) == 1  # nothing was sent after the stop


def vectors(n: int) -> dict[str, object]:
    return {"model": EMBEDDING_MODEL, "dimensions": EMBEDDING_DIMENSIONS, "vectors": [[0.5] * EMBEDDING_DIMENSIONS] * n}


def test_the_embedder_checks_the_signal_before_each_attempt() -> None:
    sent: list[httpx.Request] = []

    def answer(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json=vectors(1))

    signal = StopSignal()
    embed = HttpEmbedder(
        "http://embeddings:8080", http=httpx.Client(transport=httpx.MockTransport(answer)), stop=signal
    )
    assert len(embed(["passage: a"])) == 1
    signal.event.set()
    with pytest.raises(ShutdownRequested):
        embed(["passage: b"])
    assert len(sent) == 1


def test_the_embedder_backoff_sleeps_on_the_signal() -> None:
    signal = StopSignal()
    down = httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(503)))
    config = HttpEmbedderConfig(backoff_seconds=60.0, sleep=pytest.fail)  # the signal's sleep replaces this one
    embed = HttpEmbedder("http://embeddings:8080", config, http=down, stop=signal)
    set_after(signal, 0.05)
    started = time.monotonic()
    with pytest.raises(ShutdownRequested):
        embed(["passage: a"])
    assert time.monotonic() - started < FAST


# --- vulnerability sources ----------------------------------------------------------------------------------------
def test_a_json_source_checks_the_signal_before_each_attempt() -> None:
    sent: list[httpx.Request] = []

    def answer(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json={"ok": True})

    signal = StopSignal()
    source = JsonSource(http=httpx.Client(transport=httpx.MockTransport(answer)), stop=signal)
    assert source.get("https://kev.example.com/feed.json") == {"ok": True}
    signal.event.set()
    with pytest.raises(ShutdownRequested):
        source.get("https://kev.example.com/feed.json")
    assert len(sent) == 1


def test_a_json_source_backoff_sleeps_on_the_signal() -> None:
    signal = StopSignal()
    down = httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(503, headers={"Retry-After": "60"})))
    source = JsonSource(http=down, sleep=pytest.fail, stop=signal)
    set_after(signal, 0.05)
    started = time.monotonic()
    with pytest.raises(ShutdownRequested):
        source.get("https://epss.example.com/scores.json")
    assert time.monotonic() - started < FAST


def test_the_nvd_rate_limit_pause_sleeps_on_the_signal() -> None:
    page = {"vulnerabilities": [], "totalResults": 0}
    http = httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(200, json=page)))
    signal = StopSignal()
    client = nvd_client(http=http, stop=signal)
    for _ in range(5):  # the public limit: 5 calls in any 30 s; the sixth would wait for the window
        client.source.get(client.url)
    set_after(signal, 0.05)
    started = time.monotonic()
    with pytest.raises(ShutdownRequested):
        client.source.get(client.url)
    assert time.monotonic() - started < FAST


def test_without_a_signal_the_nvd_client_keeps_its_own_limiter() -> None:
    client = nvd_client()
    assert client.source.stop is None
    assert client.source.limiter is not None


# --- LLM ----------------------------------------------------------------------------------------------------------
class Recorder:
    def __init__(self) -> None:
        self.calls = 0

    def call_tool(self, **_kwargs: Any) -> ToolCall:
        self.calls += 1
        return ToolCall(name="t", arguments={})


def test_the_stoppable_caller_checks_the_signal_before_each_call() -> None:
    inner, signal = Recorder(), StopSignal()
    caller = StoppableCaller(inner, signal)
    assert caller.call_tool(model="m", messages=[], tools=[]).name == "t"
    signal.event.set()
    with pytest.raises(ShutdownRequested):
        caller.call_tool(model="m", messages=[], tools=[])
    assert inner.calls == 1


CHILD = [sys.executable, "-c", "import sys, time; data = sys.stdin.read(); time.sleep(float(data))"]


def test_the_runner_returns_like_subprocess_run() -> None:
    run = stoppable_runner(StopSignal(), poll_seconds=0.01)
    echo = [sys.executable, "-c", "import sys; print(sys.stdin.read().upper()); print('e', file=sys.stderr)"]
    done = run(echo, input="hola", capture_output=True, text=True, encoding="utf-8", timeout=30, check=False)
    assert (done.returncode, done.stdout.strip(), done.stderr.strip()) == (0, "HOLA", "e")


SLOW_READER = [
    sys.executable,
    "-c",
    "import sys, time; time.sleep(1); data = sys.stdin.read(); print(len(data))",
]


def test_the_runner_writes_a_prompt_larger_than_the_pipe_to_a_slow_reader() -> None:
    # The CLI starts slowly and the judge resends the whole conversation: the prompt must be written whole and stdin
    # closed even when the first writes block for longer than one poll (feature review P1).
    prompt = "x" * 300_000
    done = stoppable_runner(StopSignal(), poll_seconds=0.02)(
        SLOW_READER, input=prompt, capture_output=True, text=True, encoding="utf-8", timeout=30
    )
    assert (done.returncode, done.stdout.strip()) == (0, str(len(prompt)))


def test_the_runner_stops_while_a_large_prompt_is_still_being_written() -> None:
    signal = StopSignal()
    set_after(signal, 0.2)  # the child is still asleep: the parent is blocked writing the prompt
    started = time.monotonic()
    with pytest.raises(ShutdownRequested):
        stoppable_runner(signal, poll_seconds=0.02)(
            SLOW_READER, input="x" * 300_000, capture_output=True, text=True, timeout=30
        )
    assert time.monotonic() - started < FAST


def test_the_runner_kills_the_cli_when_the_worker_stops() -> None:
    signal = StopSignal()
    run = stoppable_runner(signal, poll_seconds=0.02)
    set_after(signal, 0.2)
    started = time.monotonic()
    with pytest.raises(ShutdownRequested):
        run(CHILD, input="30", capture_output=True, text=True, timeout=60)
    assert time.monotonic() - started < FAST


def test_the_runner_does_not_start_the_cli_once_stopping() -> None:
    signal = StopSignal()
    signal.event.set()
    with pytest.raises(ShutdownRequested):
        stoppable_runner(signal)(["/nonexistent/claude"], input="", timeout=1)  # never spawned


def test_the_runner_times_out_like_subprocess_run() -> None:
    run = stoppable_runner(StopSignal(), poll_seconds=0.02)
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        run(CHILD, input="30", capture_output=True, text=True, timeout=0.2)
    assert time.monotonic() - started < FAST
