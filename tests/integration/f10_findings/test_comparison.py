"""Score history, raw vs processed comparison and waterfall against PostgreSQL (EVA-05, EVA-11 to EVA-13)."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from decimal import Decimal
from itertools import combinations
from typing import Any

import pytest
from f10data import Scenario
from fastapi.testclient import TestClient
from hypothesis import given
from hypothesis import strategies as st

from core.views.comparison import kendall_tau_b, main_cause

pytestmark = pytest.mark.integration
Get = Callable[..., Any]


def test_history_of_a_finding_is_its_ci_score_oldest_first(get: Get, scenario: Scenario) -> None:
    points = get(f"/api/findings/{scenario.findings[('G1', 'CI-1')]}/history")
    assert points == [
        {"date": "2026-11-20T12:00:00Z", "base": 80, "judge_adjustment": 0, "final": 80},
        {"date": "2026-11-21T12:00:00Z", "base": 82, "judge_adjustment": 8, "final": 90},
    ]
    retired = get(f"/api/findings/{scenario.findings[('G1', 'CI-4')]}/history")
    assert [p["final"] for p in retired] == [99]


@pytest.mark.parametrize(("finding", "status"), [("x", 422), (str(uuid.UUID(int=5)), 404)])  # F12.3: 422 if not a UUID
def test_history_of_an_unknown_finding_is_404(client: TestClient, finding: str, status: int) -> None:
    assert client.get(f"/api/findings/{finding}/history").status_code == status


def test_breakdown_bars_add_up_from_the_raw_value_to_the_final(get: Get, scenario: Scenario) -> None:
    body = get(f"/api/assessments/{scenario.assessments['A2']}/breakdown")
    # CI-4 (99) is decommissioned: the top live CI is CI-1.
    assert (body["ci_id"], body["raw"], body["final"]) == ("CI-1", 98, 90)
    bars = body["waterfall"]
    # S 0.98, P 1.0, T 0, A 1.0, D 1.0: P = 30·0.02 = 0.6 → 1, T = 20·(0-0.98) = -19.6 → -20, A 0.3 → 0, D 0.2 → 0.
    assert {k: bars[k] for k in ("P", "T", "A", "D", "judge", "floor", "clamp", "version")} == {
        "P": 1,
        "T": -20,
        "A": 0,
        "D": 0,
        "judge": 8,
        "floor": 0,
        "clamp": 0,
        "version": 0,
    }
    assert body["raw"] + sum(bars.values()) == body["final"]


def test_breakdown_of_a_chosen_ci_and_the_kev_floor(get: Get, client: TestClient, scenario: Scenario) -> None:
    ci2 = get(f"/api/assessments/{scenario.assessments['A2']}/breakdown", ci_id="CI-2")
    assert (ci2["ci_id"], ci2["final"], ci2["raw"] + sum(ci2["waterfall"].values())) == ("CI-2", 62, 62)
    # A1 has no judge review and CI-1 is in KEV and exposed, so today's rules would lift 80 to the floor (90), but
    # A1 stored 80. The stored final wins: the whole difference from the base (0) goes to the judge bar.
    a1 = get(f"/api/assessments/{scenario.assessments['A1']}/breakdown", ci_id="CI-1")
    assert (a1["final"], a1["waterfall"]["judge"], a1["waterfall"]["floor"]) == (80, 0, 0)
    assert a1["raw"] + sum(a1["waterfall"].values()) == 80
    for url in (
        f"/api/assessments/{scenario.assessments['A2']}/breakdown?ci_id=CI-404",
        f"/api/assessments/{uuid.UUID(int=9)}/breakdown",
        f"/api/assessments/{scenario.assessments['A2']}/breakdown?ci_id=CI%00",
    ):
        assert client.get(url).status_code == 404


def test_comparison_table_lists_current_findings_by_largest_change(get: Get) -> None:
    body = get("/api/comparison/table")
    rows = [(r["cve"], r["ci_id"], r["cvss"], r["raw"], r["final"], r["delta"]) for r in body["items"]]
    assert rows == [
        ("CVE-2026-10002", "CI-1", None, 80, 70, -10),
        ("CVE-2026-10001", "CI-1", "9.8", 98, 90, -8),
        ("CVE-2026-10002", "CI-3", None, 80, 75, -5),
    ]
    assert [r["main_cause"] for r in body["items"]] == [
        "Explotación (-18)",
        "Contexto de amenaza (-20)",
        "Explotación (-18)",
    ]
    assert body["items"][1]["judge_adjustment"] == 8


def test_comparison_table_pages_with_its_own_cursor(get: Get, client: TestClient) -> None:
    first = get("/api/comparison/table", limit=2)
    second = get("/api/comparison/table", limit=2, cursor=first["next_cursor"])
    assert [r["ci_id"] for r in first["items"] + second["items"]] == ["CI-1", "CI-1", "CI-3"]
    assert second["next_cursor"] is None
    groups_cursor = get("/api/vulnerabilities", limit=1)["next_cursor"]
    assert client.get("/api/comparison/table", params={"cursor": groups_cursor}).status_code == 400


def test_comparison_summary(get: Get) -> None:
    body = get("/api/comparison/summary")
    matrix = body["reclassification_matrix"]
    assert matrix["critical"] == {"critical": 1, "high": 0, "medium": 0, "low": 0}
    assert sum(sum(row.values()) for row in matrix.values()) == 1  # findings without CVSS stay out
    funnel = {"raw": 3, "groups": 2, "with_threat_context": 0, "judge_adjusted": 1, "high_or_critical": 2}
    assert body["funnel"] == funnel
    assert (body["reclassified_percent"], body["hidden_criticals"], body["avoided_noise"]) == ("0.0", 0, 0)
    assert body["rank_correlation"] == "0.00"  # one rated finding: undefined


def test_main_cause_names_the_largest_bar() -> None:
    assert main_cause({"P": 3, "T": -5, "A": 0, "D": 0, "judge": 4, "floor": 0}) == "Contexto de amenaza (-5)"
    assert main_cause({"P": 0, "T": 0, "A": 0, "D": 0, "judge": 0, "floor": 0}) == "Sin cambio frente al CVSS"
    assert main_cause({"P": 0, "floor": 12}) == "Piso de KEV con el activo expuesto (+12)"


def _tau_brute(xs: list[int], ys: list[int]) -> Decimal | None:
    concordant = discordant = tied_x = tied_y = 0
    for (x1, y1), (x2, y2) in combinations(zip(xs, ys, strict=True), 2):
        dx, dy = x1 - x2, y1 - y2
        if dx == 0 and dy == 0:
            continue
        if dx == 0:
            tied_x += 1
        elif dy == 0:
            tied_y += 1
        elif dx * dy > 0:
            concordant += 1
        else:
            discordant += 1
    denominator = (Decimal(concordant + discordant + tied_x) * Decimal(concordant + discordant + tied_y)).sqrt()
    return None if denominator == 0 else Decimal(concordant - discordant) / denominator


@given(st.lists(st.tuples(st.integers(0, 6), st.integers(0, 6)), max_size=30))
def test_kendall_tau_b_matches_the_pairwise_definition(pairs: list[tuple[int, int]]) -> None:
    xs, ys = [x for x, _ in pairs], [y for _, y in pairs]
    fast = kendall_tau_b([Decimal(x) for x in xs], [Decimal(y) for y in ys])
    slow = _tau_brute(xs, ys) if len(pairs) >= 2 else None
    assert (fast is None) == (slow is None)
    if fast is not None and slow is not None:
        assert abs(fast - slow) < Decimal("1e-20")


def test_kendall_tau_b_of_identical_and_reversed_orders() -> None:
    values = [Decimal(v) for v in (1, 2, 3, 4)]
    assert kendall_tau_b(values, values) == 1
    assert kendall_tau_b(values, values[::-1]) == -1
