"""The worker's periodic loop: due jobs run, failures do not stop the others, iTop jobs only when configured."""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from pydantic import SecretStr

from core.config import Settings
from notifications_api import LogConsumer
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


def _factory_with_consumer_setting(value: str) -> MagicMock:
    """Sessions answering the `notifications.consumer` query with `factory.state["consumer"]`, any count with 0."""
    state = {"consumer": value}
    session = MagicMock()
    session.scalar.side_effect = lambda statement, *_: 0 if "count(*)" in str(statement) else state["consumer"]
    factory = MagicMock()
    factory.return_value.__enter__.return_value = session
    factory.state = state
    return factory


def test_the_worker_leaves_slack_events_to_the_slack_service(caplog: pytest.LogCaptureFixture) -> None:
    """notifications.consumer = slack: the Slack service (slack_app) delivers; the worker claims nothing."""
    job = DispatchJob(_factory_with_consumer_setting("slack"))
    with caplog.at_level(logging.INFO, logger="workers.jobs"):
        assert job() == 0
        assert job() == 0
    assert [r.getMessage() for r in caplog.records].count(
        "notification events are delivered by the slack service; this worker leaves them"
    ) == 1  # once, not every cycle
    assert job.consumers == {}


def test_a_registered_slack_consumer_still_delivers_in_the_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    drained: list[object] = []

    class Dispatcher:
        def __init__(self, _factory: object, consumer: object, **_: object) -> None:
            drained.append(consumer)

        def drain(self, stop: object = None) -> int:
            return 1

    monkeypatch.setattr("workers.jobs.NotificationDispatcher", Dispatcher)
    consumer = MagicMock()
    job = DispatchJob(_factory_with_consumer_setting("slack"), consumers={"slack": consumer})
    assert job() == 1
    assert drained == [consumer]


def test_switching_back_to_log_delivers_again(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("workers.jobs.NotificationDispatcher", MagicMock(return_value=MagicMock(drain=lambda stop: 2)))
    factory = _factory_with_consumer_setting("slack")
    job = DispatchJob(factory)
    assert job() == 0
    factory.state["consumer"] = "log"
    assert job() == 2
    assert isinstance(job.consumers["log"], LogConsumer)


def test_events_waiting_for_the_slack_service_raise_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    """A stopped Slack service must not leave events waiting unseen (NOT-03): a WARNING, at most every 10 minutes."""
    session = MagicMock()
    session.scalar.side_effect = ["slack", 3, "slack", "slack", 0]  # setting, waiting count, setting, ...
    factory = MagicMock()
    factory.return_value.__enter__.return_value = session
    now = [datetime(2026, 11, 23, 10, 0, tzinfo=UTC)]
    job = DispatchJob(factory, clock=lambda: now[0])
    with caplog.at_level(logging.WARNING, logger="workers.jobs"):
        assert job() == 0
        now[0] += timedelta(minutes=1)
        assert job() == 0  # checked again only after 10 minutes
        now[0] += timedelta(minutes=10)
        assert job() == 0  # nothing waiting now: no warning
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings == [
        "3 immediate notification event(s) have waited over 5 minutes for the slack service; is it running?"
    ]
    counts = [c for c in session.scalar.call_args_list if len(c.args) > 1]
    sinces = [c.args[1]["since"] for c in counts]
    start = datetime(2026, 11, 23, 10, 0, tzinfo=UTC)
    assert sinces == [start - timedelta(minutes=5), start + timedelta(minutes=6)]  # due 5 minutes ago or earlier


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
