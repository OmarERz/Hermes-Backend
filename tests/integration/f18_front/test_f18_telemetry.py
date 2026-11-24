"""F18.1: agent telemetry, the history timeline and the run filters, over a real database."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from f18data import Front
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration
Get = Callable[..., Any]


def _agent(summary: dict[str, Any], name: str) -> dict[str, Any]:
    return next(a for a in summary["agents"] if a["agent"] == name)


def test_summary_counts_the_window_and_never_reports_a_key(get: Get, front: Front) -> None:
    summary = get("/api/telemetry/summary", window="24h")
    assert summary["window"] == "24h"
    assert summary["runs_succeeded"] >= 1 and summary["runs_failed"] >= 1 and summary["runs_running"] >= 1
    scans = next(r for r in summary["runs"] if r["kind"] == "scan")
    assert scans["succeeded"] >= 1
    judge = _agent(summary, "judge")
    # One valid review and one fallback in the last 24 h: 50 %, mean latency 2 s; the F10.2 reviews are older.
    assert judge["reviews"] == 2
    assert judge["by_status"] == {"applied": 1, "no_judge_review": 1}
    assert judge["success_percent"] == "50.0"
    assert judge["latency_avg_ms"] == 2000
    assert judge["latency_p95_ms"] >= 2000
    assert judge["provider"] == "deepseek" and judge["model"] == "deepseek-v4-pro"
    assert judge["ladder_level"] == 0 and judge["active"] is True
    assert judge["cost_usd"] == "0.040000"
    cve = _agent(summary, "cve_analyst")
    assert cve["reviews"] == 1 and cve["success_percent"] == "100.0" and cve["ladder_level"] is None
    news = _agent(summary, "news_analyst")
    assert news["reviews"] == 0 and news["success_percent"] is None
    assert summary["ladder_label"] == "Normal"
    assert summary["daily_budget_usd"] == "5.000000"


def test_summary_of_thirty_days_includes_the_reasons_the_judge_used(get: Get) -> None:
    summary = get("/api/telemetry/summary", window="30d")
    reasons = {r["code"]: r for r in summary["top_reasons"]}
    assert reasons["mass_exploitation"]["accepted"] >= 1
    assert reasons["unverified_poc"]["rejected"] >= 1
    assert reasons["mass_exploitation"]["label"]


def test_summary_refuses_an_unknown_window(client: TestClient) -> None:
    response = client.get("/api/telemetry/summary", params={"window": "1y"})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_daily_series_is_zero_filled_and_ends_today(get: Get) -> None:
    daily = get("/api/telemetry/daily", days=3)
    assert daily["days"] == 3 and len(daily["series"]) == 3
    today = datetime.now(UTC).date().isoformat()
    assert daily["series"][-1]["date"] == today
    last = daily["series"][-1]
    judge = next(a for a in last["agents"] if a["agent"] == "judge")
    assert judge["reviews"] >= 2
    assert [a["agent"] for a in daily["series"][0]["agents"]] == ["news_analyst", "cve_analyst", "judge"]


@pytest.mark.parametrize("days", [0, 91])
def test_daily_series_bounds_the_days(client: TestClient, days: int) -> None:
    assert client.get("/api/telemetry/daily", params={"days": days}).status_code == 422


def test_review_log_filters_pages_and_links_the_assessment(get: Get, front: Front) -> None:
    fallback = get("/api/telemetry/reviews", agent="judge", status="no_judge_review")
    assert [r["id"] for r in fallback["items"]] == [str(front.reviews["fallback"])]
    assert fallback["items"][0]["attempts"] == 2
    first = get("/api/telemetry/reviews", limit=1)
    assert len(first["items"]) == 1 and first["next_cursor"]
    second = get("/api/telemetry/reviews", limit=1, cursor=first["next_cursor"])
    assert second["items"][0]["id"] != first["items"][0]["id"]
    every = get("/api/telemetry/reviews", agent="judge", limit=50)["items"]
    linked = {r["id"]: r for r in every if r["assessment_id"] == str(front.scenario.assessments["A2"])}
    first, second = linked[str(front.reviews["first"])], linked[str(front.reviews["second"])]
    assert first["reasons_accepted"] == 1 and first["reasons_rejected"] == 1 and first["second_review"] is False
    assert second["second_review"] is True  # the blind review links to the assessment of the first
    assert not any(field in every[0] for field in ("calls", "parameters", "response_model", "input_ref"))


def test_review_log_refuses_a_cursor_of_another_list(client: TestClient) -> None:
    runs = client.get("/api/runs", params={"limit": 1}).json()
    assert runs["next_cursor"]
    response = client.get("/api/telemetry/reviews", params={"cursor": runs["next_cursor"]})
    assert response.status_code == 400 and response.json()["error"]["code"] == "invalid_cursor"


def test_history_joins_runs_reviews_and_configuration_changes(get: Get, front: Front) -> None:
    events = get("/api/history", limit=200)["items"]
    types = {e["type"] for e in events}
    assert types == {"run", "llm_review", "config_change"}
    scan = next(e for e in events if e["id"] == str(front.runs["scan"]))
    assert scan["actor"] == "Ana Analista" and scan["trigger"] == "manual" and scan["duration_seconds"] == 600
    assert scan["title"] == "Escaneo simulado" and scan["run_kind"] == "scan" and scan["status"] == "succeeded"
    change = next(e for e in events if e["type"] == "config_change")
    assert (
        change["config_version"] == 2 and change["title"] == "Cambió: dead_zone" and change["actor"] == "Ana Analista"
    )
    review = next(e for e in events if e["id"] == str(front.reviews["fallback"]))
    assert review["actor"] == "Juez" and review["status"] == "no_judge_review" and review["duration_seconds"] == 3
    times = [e["at"] for e in events]
    assert times == sorted(times, reverse=True)


def test_history_filters_and_pages(get: Get, front: Front) -> None:
    failed = get("/api/history", type="run", status="failed")["items"]
    assert [e["id"] for e in failed] == [str(front.runs["news"])]
    first = get("/api/history", limit=2)
    second = get("/api/history", limit=2, cursor=first["next_cursor"])
    assert {e["id"] for e in first["items"]}.isdisjoint({e["id"] for e in second["items"]})
    assert get("/api/history", date_from="2999-01-01T00:00:00Z")["items"] == []


def test_history_refuses_a_malformed_status(client: TestClient) -> None:
    assert client.get("/api/history", params={"status": "DROP TABLE"}).status_code == 422


def test_runs_filter_by_kind_and_status_and_say_who_launched_them(get: Get, front: Front) -> None:
    scans = get("/api/runs", kind="scan", status="succeeded")["items"]
    mine = next(r for r in scans if r["id"] == str(front.runs["scan"]))
    assert mine["triggered_by"] == "Ana Analista" and mine["trigger_reason"] == "manual"
    assert all(r["kind"] == "scan" and r["status"] == "succeeded" for r in scans)
    news = get("/api/runs", kind="ingestion")["items"]
    assert [r["id"] for r in news] == [str(front.runs["news"])]
    assert news[0]["triggered_by"] is None and news[0]["trigger_reason"] == "schedule"
    assert get("/api/runs", date_from="2999-01-01T00:00:00Z")["items"] == []
