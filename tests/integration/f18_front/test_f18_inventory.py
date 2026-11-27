"""F18.1: inventory, software and source descriptions over a real database (the F10.2 scenario: CI-1 to CI-3 live,
CI-4 decommissioned, OpenSSL on every CI, "Software sin mapeo CPE" with version N/A on CI-2)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from f18data import Front
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration
Get = Callable[..., Any]
ITOP_CI = "https://itop.example.test/pages/UI.php?operation=details&class="


def _by_ci(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {item["ci_id"]: item for item in items}


def test_inventory_lists_every_live_ci_with_or_without_findings(get: Get, front: Front) -> None:
    items = get("/api/inventory/assets")["items"]
    assets = _by_ci(items)
    assert set(assets) == {"CI-1", "CI-2", "CI-3"}  # CI-4 is decommissioned
    assert [a["name"].casefold() for a in items] == sorted(a["name"].casefold() for a in items)
    payments = assets["CI-1"]
    # G1 (90, KEV) and G2 (70) are open on CI-1: two findings, one in KEV, risk = the highest final, never a sum.
    assert payments["open_findings"] == 2 and payments["kev_findings"] == 1
    assert payments["risk"] == 90 and payments["level"] == "critical"
    assert payments["itop_class"] == "Server" and payments["owner"] == "Dueña de Pagos"
    assert payments["itop_url"] == f"{ITOP_CI}Server&id=CI-1"
    intranet = assets["CI-2"]  # its only finding is fixed
    assert intranet["open_findings"] == 0 and intranet["risk"] is None and intranet["level"] is None
    assert intranet["software_count"] == 2
    orphan = assets["CI-3"]
    assert orphan["owner"] is None and orphan["custodian"] is None and orphan["exposed"] is None
    assert orphan["criticality"] == "unknown" and orphan["risk"] == 75


def test_inventory_filters_search_and_pages(get: Get) -> None:
    assert [a["ci_id"] for a in get("/api/inventory/assets", q="PAGOS")["items"]] == ["CI-1"]
    assert {a["ci_id"] for a in get("/api/inventory/assets", itop_class="Server")["items"]} == {"CI-1", "CI-3"}
    assert [a["ci_id"] for a in get("/api/inventory/assets", with_findings=False)["items"]] == ["CI-2"]
    assert [a["ci_id"] for a in get("/api/inventory/assets", criticality="unknown")["items"]] == ["CI-3"]
    assert [a["ci_id"] for a in get("/api/inventory/assets", exposed=True)["items"]] == ["CI-1"]
    assert get("/api/inventory/assets", custodian="Nadie")["items"] == []
    first = get("/api/inventory/assets", limit=2)
    second = get("/api/inventory/assets", limit=2, cursor=first["next_cursor"])
    assert len(first["items"]) == 2 and len(second["items"]) == 1 and second["next_cursor"] is None
    assert {a["ci_id"] for a in first["items"] + second["items"]} == {"CI-1", "CI-2", "CI-3"}


def test_inventory_refuses_bad_filters(client: TestClient) -> None:
    for params in ({"criticality": "extreme"}, {"q": "x" * 101}, {"with_findings": "maybe"}):
        response = client.get("/api/inventory/assets", params=params)
        assert response.status_code == 422, params
        assert response.json()["error"]["code"] == "validation_error"


def test_summary_counts_the_live_inventory_and_the_software_health(get: Get) -> None:
    summary = get("/api/inventory/summary")
    assert summary["total_assets"] == 3
    assert summary["by_class"] == {"Server": 2, "VirtualMachine": 1}
    assert summary["by_criticality"] == {"high": 1, "medium": 1, "unknown": 1}
    assert summary["by_exposure"] == {"exposed": 1, "internal": 1, "unknown": 1}
    assert summary["owners"] == 1 and summary["without_owner"] == 1 and summary["custodians"] == 1
    assert summary["with_open_findings"] == 2 and summary["with_kev_findings"] == 1
    assert summary["last_sync_at"].endswith("Z")
    software = summary["software"]
    # OpenSSL: CPE, version 3.0.7, a critical open finding. The unmapped product: no CPE, N/A, nothing open.
    assert software["total"] == 2
    assert software["with_cpe"] == 1 and software["cpe_percent"] == "50.0"
    assert software["with_known_version"] == 1 and software["known_version_percent"] == "50.0"
    assert software["without_critical"] == 1 and software["without_critical_percent"] == "50.0"


def test_software_lists_versions_cpe_and_worst_level(get: Get) -> None:
    items = {s["name"]: s for s in get("/api/inventory/software")["items"]}
    openssl = items["OpenSSL"]
    assert openssl["versions"] == ["3.0.7"] and openssl["version_known"] is True
    assert openssl["instances"] == 3 and openssl["ci_count"] == 3  # CI-4 is decommissioned
    assert openssl["has_cpe"] is True and openssl["cpe"].startswith("cpe:2.3:a:openssl:openssl:")
    assert openssl["open_vulnerabilities"] == 2 and openssl["worst_level"] == "critical"
    unmapped = items["Software sin mapeo CPE"]
    assert unmapped["versions"] == [] and unmapped["version_known"] is False
    assert unmapped["has_cpe"] is False and unmapped["cpe"] is None and unmapped["worst_level"] is None
    assert [s["name"] for s in get("/api/inventory/software", has_cpe=False)["items"]] == ["Software sin mapeo CPE"]
    assert [s["name"] for s in get("/api/inventory/software", worst_level="critical")["items"]] == ["OpenSSL"]
    assert [s["name"] for s in get("/api/inventory/software", q="openssl")["items"]] == ["OpenSSL"]
    first = get("/api/inventory/software", limit=1)
    assert first["next_cursor"] and len(get("/api/inventory/software", cursor=first["next_cursor"])["items"]) == 1


def test_asset_software_shows_the_installed_versions(get: Get, client: TestClient) -> None:
    items = get("/api/inventory/assets/CI-2/software")
    assert [(i["name"], i["version"], i["version_known"]) for i in items] == [
        ("OpenSSL", "3.0.7", True),
        ("Software sin mapeo CPE", "N/A", False),
    ]
    assert items[0]["open_vulnerabilities"] == 0  # its G1 finding is fixed
    payments = get("/api/inventory/assets/CI-1/software")
    assert payments[0]["open_vulnerabilities"] == 2 and payments[0]["worst_level"] == "critical"
    for ci in ("CI-4", "CI-404"):  # decommissioned or unknown
        response = client.get(f"/api/inventory/assets/{ci}/software")
        assert response.status_code == 404 and response.json()["error"]["code"] == "not_found"


def test_sources_carry_their_refresh_interval(get: Get) -> None:
    sources = {s["name"]: s for s in get("/api/sources")["items"]}
    own = sources["Noticias de prueba"]  # not a factory source: no text, the news cycle's period
    assert own["description"] is None and own["provider"] is None and own["refresh_interval_minutes"] == 60
