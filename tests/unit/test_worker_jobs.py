"""The worker's periodic loop: due jobs run, failures do not stop the others, iTop jobs only when configured."""

from __future__ import annotations

import threading
from unittest.mock import MagicMock

import pytest
from pydantic import SecretStr

from core.config import Settings
from workers.jobs import (
    ITOP_OUTBOX_SECONDS,
    NIGHTLY_SECONDS,
    TICKET_SYNC_SECONDS,
    PeriodicJob,
    build_jobs,
    run_jobs,
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


def test_without_itop_only_the_nightly_metrics_run() -> None:
    assert [(job.name, job.interval) for job in build_jobs(SETTINGS, MagicMock())] == [
        ("nightly_metrics", NIGHTLY_SECONDS)
    ]


def test_with_itop_the_outbox_and_the_sync_run() -> None:
    settings = SETTINGS.model_copy(update={"itop_url": "http://localhost:8080", "itop_token": SecretStr("tok")})
    jobs = build_jobs(settings, MagicMock())
    assert [(job.name, job.interval) for job in jobs] == [
        ("nightly_metrics", NIGHTLY_SECONDS),
        ("itop_outbox", ITOP_OUTBOX_SECONDS),
        ("ticket_sync", TICKET_SYNC_SECONDS),
    ]
