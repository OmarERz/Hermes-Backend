"""The worker's periodic loop: due jobs run, failures do not stop the others, iTop jobs only when configured."""

from __future__ import annotations

import logging
import threading
import time
from unittest.mock import MagicMock

import pytest
from pydantic import SecretStr

from core.config import Settings
from core.shutdown import StopSignal
from workers.jobs import (
    DISPATCH_SECONDS,
    ITOP_OUTBOX_SECONDS,
    NIGHTLY_SECONDS,
    TICKET_SYNC_SECONDS,
    DispatchJob,
    PeriodicJob,
    build_jobs,
    run_jobs,
    run_jobs_in_threads,
)
from workers.pipeline_jobs import (
    NEWS_SECONDS,
    NIGHTLY_RECALC_SECONDS,
    RECALC_REQUEST_SECONDS,
    SCAN_REQUEST_SECONDS,
    _tickets,
)

pytestmark = pytest.mark.unit
SETTINGS = Settings(
    _env_file=None,
    database_url=SecretStr("postgresql://app:pw@db/hermes"),
    firebase_project_id="demo-hermes",
    cursor_signing_key=SecretStr("k" * 40),
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class SteppingStop(threading.Event):
    """Each wait advances the fake clock by 5 s; the loop stops after `rounds` waits."""

    def __init__(self, clock: FakeClock, rounds: int) -> None:
        super().__init__()
        self.clock, self.rounds = clock, rounds

    def wait(self, timeout: float | None = None) -> bool:
        self.clock.now += 5
        self.rounds -= 1
        if self.rounds == 0:
            self.set()
        return self.is_set()


def test_jobs_run_when_due_and_failures_are_isolated() -> None:
    clock = FakeClock()
    runs: list[str] = []

    def boom() -> None:
        runs.append("boom")
        raise RuntimeError("nope")

    def fast() -> None:
        runs.append("fast")

    jobs = [PeriodicJob("boom", 100, boom), PeriodicJob("fast", 10, fast)]
    run_jobs(SteppingStop(clock, rounds=4), jobs, clock=clock)

    assert runs == ["boom", "fast", "fast"]  # t=0 both; t=10 fast again; boom is not due before t=100


def test_a_stop_during_a_round_skips_the_remaining_jobs() -> None:
    stop = threading.Event()
    runs: list[str] = []
    jobs = [PeriodicJob("a", 1, lambda: (runs.append("a"), stop.set())), PeriodicJob("b", 1, lambda: runs.append("b"))]
    run_jobs(stop, jobs, tick=0)
    assert runs == ["a"]


PIPELINE = [
    ("news_cycle", NEWS_SECONDS, "pipeline"),
    ("scan_requests", SCAN_REQUEST_SECONDS, "pipeline"),
    ("recalculation_requests", RECALC_REQUEST_SECONDS, "pipeline"),
    ("nightly_recalculation", NIGHTLY_RECALC_SECONDS, "pipeline"),
    ("vulndata_refresh", 24 * 3600.0, "pipeline"),
]


def test_without_itop_the_dispatcher_metrics_calibration_and_pipeline_run() -> None:
    assert [(job.name, job.interval, job.lane) for job in build_jobs(SETTINGS, MagicMock())] == [
        ("notification_dispatch", DISPATCH_SECONDS, "notifications"),
        ("nightly_metrics", NIGHTLY_SECONDS, "nightly"),
        ("weekly_calibration", NIGHTLY_SECONDS, "nightly"),
        *PIPELINE,
    ]


def test_with_itop_the_outbox_and_the_sync_run() -> None:
    settings = SETTINGS.model_copy(update={"itop_url": "http://localhost:8080", "itop_token": SecretStr("tok")})
    jobs = build_jobs(settings, MagicMock())
    assert [(job.name, job.interval) for job in jobs] == [
        ("notification_dispatch", DISPATCH_SECONDS),
        ("nightly_metrics", NIGHTLY_SECONDS),
        ("weekly_calibration", NIGHTLY_SECONDS),
        *[(name, interval) for name, interval, _ in PIPELINE],
        ("inventory_refresh", 6 * 3600.0),
        ("itop_outbox", ITOP_OUTBOX_SECONDS),
        ("ticket_sync", TICKET_SYNC_SECONDS),
    ]


def test_lanes_run_in_parallel_and_jobs_of_a_lane_in_turn() -> None:
    stop = threading.Event()
    seen: list[tuple[str, str]] = []
    started = threading.Barrier(2, timeout=5)

    def slow() -> None:
        started.wait()
        seen.append(("slow", threading.current_thread().name))
        stop.wait(5)

    def same_lane() -> None:
        seen.append(("same_lane", threading.current_thread().name))

    def fast() -> None:
        started.wait()  # only passes if the slow lane is not blocking this one
        seen.append(("fast", threading.current_thread().name))
        stop.set()

    jobs = [
        PeriodicJob("slow", 60, slow, lane="itop"),
        PeriodicJob("same_lane", 60, same_lane, lane="itop"),
        PeriodicJob("fast", 60, fast, lane="notifications"),
    ]
    run_jobs_in_threads(stop, jobs, tick=0.01)

    assert ("slow", "lane-itop") in seen
    assert ("fast", "lane-notifications") in seen
    assert ("same_lane", "lane-itop") not in seen  # it waits behind the slow job of its lane


def test_registered_consumers_are_used_by_name() -> None:
    consumer = MagicMock()
    job = build_jobs(SETTINGS, MagicMock(), {"slack": consumer})[0]
    assert job.lane == "notifications"
    assert job.run.consumers == {"slack": consumer}


def test_a_shutdown_inside_a_job_ends_its_lane_quietly(caplog: pytest.LogCaptureFixture) -> None:
    stop = threading.Event()
    runs: list[str] = []

    def stopping() -> None:
        runs.append("stopping")
        stop.set()
        StopSignal(stop).check()  # what a cycle's fetcher, source or LLM call raises (#170)

    jobs = [PeriodicJob("cycle", 1, stopping), PeriodicJob("after", 1, lambda: runs.append("after"))]
    with caplog.at_level(logging.INFO, logger="workers.jobs"):
        run_jobs(stop, jobs, tick=0)
    assert runs == ["stopping"]
    assert "job cycle stopped: the worker is shutting down" in caplog.text
    assert "failed" not in caplog.text


def test_a_cycle_waiting_on_the_network_stops_within_a_second() -> None:
    stop = threading.Event()
    signal = StopSignal(stop)
    started = threading.Event()

    def cycle() -> None:
        started.set()
        signal.sleep(300)  # a rate-limit pause or a retry backoff of a long cycle

    timer = threading.Timer(0.1, lambda: started.wait(5) and stop.set())
    timer.start()
    begin = time.monotonic()
    run_jobs_in_threads(stop, [PeriodicJob("news_cycle", 3600, cycle, lane="pipeline")], tick=0.01, grace=8)
    assert time.monotonic() - begin < 1.5


def test_a_lane_stuck_in_a_request_is_left_to_the_process_exit(caplog: pytest.LogCaptureFixture) -> None:
    stop = threading.Event()
    release = threading.Event()
    started = threading.Event()

    def stuck() -> None:
        started.set()
        release.wait(30)  # a request already on the wire ignores the stop signal until its own timeout

    timer = threading.Timer(0.05, lambda: started.wait(5) and stop.set())
    timer.start()
    begin = time.monotonic()
    with caplog.at_level(logging.WARNING, logger="workers.jobs"):
        run_jobs_in_threads(stop, [PeriodicJob("vulndata_refresh", 60, stuck, lane="pipeline")], tick=0.01, grace=0.2)
    elapsed = time.monotonic() - begin
    release.set()
    assert elapsed < 2
    assert "shutdown: lane-pipeline still busy after 0.2s; it ends with the process" in caplog.text


def test_the_pipeline_jobs_receive_the_worker_stop_signal(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[object] = []

    def fake_pipeline_jobs(settings: object, factory: object, job: object, stop: object = None) -> list[PeriodicJob]:
        seen.append(stop)
        return []

    monkeypatch.setattr("workers.jobs.pipeline_jobs", fake_pipeline_jobs)
    stop = threading.Event()
    build_jobs(SETTINGS, MagicMock(), stop=stop)
    build_jobs(SETTINGS, MagicMock())
    assert isinstance(seen[0], StopSignal)
    assert seen[0].event is stop
    assert seen[1] is None


def test_links_in_events_and_tickets_use_the_itop_console_url() -> None:
    # F16.1: on the shared Docker network the backend reaches http://itop:8080; people open the published console.
    settings = SETTINGS.model_copy(
        update={
            "itop_url": "http://itop:8080/",
            "itop_console_url": "http://127.0.0.1:8080/",
            "itop_token": SecretStr("tok"),
            "itop_org_id": "1",
            "itop_caller_id": "2",
        }
    )
    dispatch = build_jobs(settings, MagicMock())[0]
    assert dispatch.name == "notification_dispatch"
    assert isinstance(dispatch.run, DispatchJob)
    assert dispatch.run.itop_base_url == "http://127.0.0.1:8080/"
    lifecycle = _tickets(settings)
    assert lifecycle is not None
    assert lifecycle.itop_base_url == "http://127.0.0.1:8080/"
