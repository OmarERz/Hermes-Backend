"""The worker's pipeline jobs: built from the configuration, fail closed, queued scans picked one at a time."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest
from pydantic import SecretStr

from core.config import Settings
from core.pipeline.wiring import engine_dismissal_package, engine_evaluate
from core.scan.engine import ScanAlreadyRunningError
from workers.jobs import PeriodicJob
from workers.pipeline_jobs import QueuedScans, build_pipeline, pipeline_jobs

pytestmark = pytest.mark.unit
SETTINGS = Settings(
    _env_file=None,
    database_url=SecretStr("postgresql://app:pw@db/hermes"),
    firebase_project_id="demo-hermes",
    cursor_signing_key=SecretStr("k" * 40),
)


def test_without_the_embeddings_extra_the_news_cycle_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("workers.pipeline_jobs.importlib.util.find_spec", lambda _name: None)
    assert build_pipeline(SETTINGS, MagicMock()).steps.news is None
    monkeypatch.setattr("workers.pipeline_jobs.importlib.util.find_spec", lambda _name: object())
    assert build_pipeline(SETTINGS, MagicMock()).steps.news is not None


def test_without_keys_there_is_no_judge_nor_tickets_but_scoring_runs() -> None:
    steps = build_pipeline(SETTINGS, MagicMock()).steps
    assert steps.refresh is not None
    assert (steps.judge_caller, steps.tickets) == (None, None)
    assert steps.evaluate is engine_evaluate
    assert steps.recalculate is not None
    assert steps.dismissal_package is engine_dismissal_package
    assert steps.scan is not None


def test_with_keys_and_identity_the_judge_and_tickets_are_wired() -> None:
    settings = SETTINGS.model_copy(
        update={
            "deepseek_api_key": SecretStr("sk-test-" + "x" * 20),
            "itop_url": "http://localhost:8080",
            "itop_token": SecretStr("tok"),
            "itop_org_id": "1",
            "itop_caller_id": "5",
        }
    )
    steps = build_pipeline(settings, MagicMock()).steps
    assert steps.judge_caller is not None
    assert steps.tickets is not None


def test_the_inventory_refresh_needs_itop() -> None:
    assert "inventory_refresh" not in [job.name for job in pipeline_jobs(SETTINGS, MagicMock(), PeriodicJob)]
    with_itop = SETTINGS.model_copy(update={"itop_url": "http://localhost:8080", "itop_token": SecretStr("tok")})
    refresh = [j for j in pipeline_jobs(with_itop, MagicMock(), PeriodicJob) if j.name == "inventory_refresh"]
    assert [j.interval for j in refresh] == [6 * 3600.0]


def test_the_scheduled_scan_is_optional() -> None:
    names = [job.name for job in pipeline_jobs(SETTINGS, MagicMock(), PeriodicJob)]
    assert "scheduled_scan" not in names
    every_six = SETTINGS.model_copy(update={"scan_interval_hours": 6})
    scheduled = [j for j in pipeline_jobs(every_six, MagicMock(), PeriodicJob) if j.name == "scheduled_scan"]
    assert [j.interval for j in scheduled] == [6 * 3600.0]


@pytest.fixture(autouse=True)
def no_stale_scans(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    closed: list[object] = []
    monkeypatch.setattr("workers.pipeline_jobs.fail_stale_scans", closed.append)
    return closed


def test_queued_scans_run_one_request_per_tick(monkeypatch: pytest.MonkeyPatch, no_stale_scans: list[object]) -> None:
    pipeline = MagicMock()
    queued = uuid.uuid4()
    waiting = [queued, None]
    monkeypatch.setattr("workers.pipeline_jobs.next_queued_scan", lambda _s: waiting.pop(0))
    job = QueuedScans(pipeline, MagicMock())
    assert job() is True
    pipeline.scan_cycle.assert_called_once_with(queued, "manual")
    assert job() is False
    assert len(no_stale_scans) == 2  # a crashed scan is closed before each pick


def test_a_request_waits_while_another_scan_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    pipeline = MagicMock()
    pipeline.scan_cycle.side_effect = ScanAlreadyRunningError("busy")
    monkeypatch.setattr("workers.pipeline_jobs.next_queued_scan", lambda _s: uuid.uuid4())
    assert QueuedScans(pipeline, MagicMock())() is False
