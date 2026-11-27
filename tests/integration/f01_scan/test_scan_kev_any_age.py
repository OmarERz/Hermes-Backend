"""A KEV CVE counts whatever its age (ESC-09, ESC-10): the refresh brings its NVD record and the scan matches it.

F20 dry run, P0-1: the refresh only read the 90-day NVD window, so old KEV CVEs had no stored range and the scan
never matched them (kernel 6.1.0 CVE-2024-1086, Go 1.21.0 CVE-2023-44487, MongoDB 6.0.0 CVE-2025-14847, Vite 4.5.0
CVE-2025-31125...). Recorded answers: `nvd_kev_page.json` is NVD's `hasKev` answer of 27 Nov 2026 and
`kev_any_age.json` the CISA catalogue of the same day, both trimmed to these CVEs (descriptions in English, two
references, the product's configuration entries plus two of other products). CVE-2024-53104 is in NVD's answer but
left out of the CISA file on purpose: the scan follows CISA's catalogue.
"""

from __future__ import annotations

import gzip
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from core.pipeline.wiring import refresh_vulndata
from core.scan.engine import ScanOptions, run_scan
from core.vulndata.epss import EPSS_DAILY_URL
from core.vulndata.http import JsonSource
from core.vulndata.kev import KEV_URL
from core.vulndata.nvd import NVD_URL, NvdClient

pytestmark = pytest.mark.integration
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "vulndata"
SCAN_AT = datetime(2026, 11, 27, 9, 34, 35, tzinfo=UTC)
EMPTY_PAGE: dict[str, Any] = {"vulnerabilities": [], "totalResults": 0}
INSTALLS = (  # CI, product, NVD vendor, NVD product, version (the F20 inventory)
    ("eks-nodo-01", "Linux Kernel", "linux", "linux_kernel", "6.1.0"),
    ("svc-viajes", "Go", "golang", "go", "1.21.0"),
    ("svc-desbloqueo", "Go", "golang", "go", "1.21.0"),
    ("mongodb-telemetria", "MongoDB", "mongodb", "mongodb", "6.0.0"),
    ("pc-build-movil-01", "Vite", "vitejs", "vite", "4.5.0"),
    ("redis-cache", "Redis", "redis", "redis", "7.0.0"),
)
EXPECTED = {
    ("eks-nodo-01", "CVE-2023-0386"),
    ("eks-nodo-01", "CVE-2024-1086"),
    ("eks-nodo-01", "CVE-2024-36971"),
    ("eks-nodo-01", "CVE-2025-39682"),
    ("svc-viajes", "CVE-2023-44487"),
    ("svc-desbloqueo", "CVE-2023-44487"),
    ("mongodb-telemetria", "CVE-2025-14847"),
    ("pc-build-movil-01", "CVE-2025-31125"),
}


def recorded(name: str) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return loaded


def epss_file(day: str) -> bytes:
    text_ = f"#model_version:v2025.03.14,score_date:{day}T00:00:00Z\ncve,epss,percentile\nCVE-2024-1086,0.8,0.99\n"
    return gzip.compress(text_.encode())


class Sources:
    """NVD, CISA and FIRST behind one mock transport; it records each NVD query."""

    def __init__(self, kev_page: dict[str, Any], catalogue: dict[str, Any], by_id: dict[str, Any] | None = None):
        self.kev_page, self.catalogue, self.by_id = kev_page, catalogue, by_id or {}
        self.nvd_queries: list[dict[str, str]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = f"{request.url.scheme}://{request.url.host}{request.url.path}"
        if url == KEV_URL:
            return httpx.Response(200, json=self.catalogue)
        if url == EPSS_DAILY_URL:
            return httpx.Response(200, content=epss_file("2026-11-27"))
        assert url == NVD_URL, url
        params = dict(request.url.params)
        self.nvd_queries.append(params)
        if "hasKev" in params:
            return httpx.Response(200, json=self.kev_page)
        if "cveId" in params:
            record = self.by_id.get(params["cveId"])
            return httpx.Response(200, json={"vulnerabilities": [record], "totalResults": 1} if record else EMPTY_PAGE)
        return httpx.Response(200, json=EMPTY_PAGE)  # the recency window: nothing recent in this test

    def refresh(self, factory: sessionmaker[Session]) -> Any:
        http = httpx.Client(transport=httpx.MockTransport(self.handler))
        return refresh_vulndata(factory, NvdClient(JsonSource(http=http)), JsonSource(http=http))()


def run(engine: Engine, statement: str, params: dict[str, Any] | None = None) -> None:
    with engine.begin() as conn:
        conn.execute(text(statement), params or {})


def rows(engine: Engine, statement: str, params: dict[str, Any] | None = None) -> list[tuple[Any, ...]]:
    with engine.connect() as conn:
        return [tuple(r) for r in conn.execute(text(statement), params or {})]


@pytest.fixture
def world(engine: Engine) -> sessionmaker[Session]:
    """The F20 inventory's CIs for the products with old KEV CVEs, each product mapped to its NVD name."""
    products: dict[str, uuid.UUID] = {}
    for ci, product, vendor, nvd_product, version in INSTALLS:
        asset = uuid.uuid4()
        run(
            engine,
            "INSERT INTO asset (id, itop_ci_id, itop_class, name, criticality, confidentiality, synced_at) "
            "VALUES (:id, :ci, 'Server', :ci, 'high', 'classified', now())",
            {"id": asset, "ci": ci},
        )
        if product not in products:
            products[product] = uuid.uuid4()
            run(
                engine,
                "INSERT INTO software_product (id, itop_name, first_seen_at) VALUES (:id, :name, now())",
                {"id": products[product], "name": product},
            )
            run(
                engine,
                "INSERT INTO cpe_mapping (software_product_id, nvd_vendor, nvd_product, origin, mapped_at) "
                "VALUES (:p, :v, :n, 'manual', now())",
                {"p": products[product], "v": vendor, "n": nvd_product},
            )
        run(
            engine,
            "INSERT INTO installed_software (itop_instance_id, asset_id, software_product_id, version, synced_at) "
            "VALUES (:iid, :asset, :product, :version, now())",
            {"iid": f"SI-{ci}-{product}", "asset": asset, "product": products[product], "version": version},
        )
    return sessionmaker(engine, expire_on_commit=False)


def findings(engine: Engine) -> dict[tuple[str, str], str]:
    found = rows(
        engine,
        "SELECT a.name, g.cve_id, f.match_source FROM finding f "
        "JOIN finding_group g ON g.id = f.finding_group_id "
        "JOIN installed_software i ON i.id = f.installed_software_id JOIN asset a ON a.id = i.asset_id",
    )
    return {(ci, cve): source for ci, cve, source in found}


def test_old_kev_cves_of_mapped_products_are_found_after_the_refresh(engine: Engine, world: sessionmaker[Session]):
    sources = Sources(recorded("nvd_kev_page.json"), recorded("kev_any_age.json"))

    _nvd, _kev, _epss, kev_records = sources.refresh(world)
    result = run_scan(world, ScanOptions(), now=SCAN_AT)

    assert set(findings(engine)) == EXPECTED  # nothing for Redis (no comparable range) nor CVE-2016-5195 (fixed)
    assert set(findings(engine).values()) == {"nvd_cpe"}  # NVD ranges: certainty 1.0
    assert result.new == len(EXPECTED)
    assert kev_records.stored == recorded("nvd_kev_page.json")["totalResults"]
    assert [q for q in sources.nvd_queries if "hasKev" in q] == [
        {"hasKev": "", "resultsPerPage": "2000", "startIndex": "0"}
    ]
    published = rows(engine, "SELECT published_at FROM cve WHERE id = 'CVE-2024-1086'")[0][0]
    assert published.year == 2024  # far outside the 90-day window


def test_a_cve_nvd_flags_but_the_cisa_catalogue_does_not_list_stays_outside_the_window(
    engine: Engine, world: sessionmaker[Session]
) -> None:
    Sources(recorded("nvd_kev_page.json"), recorded("kev_any_age.json")).refresh(world)
    run_scan(world, ScanOptions(), now=SCAN_AT)

    assert rows(engine, "SELECT count(*) FROM cve_affected_range WHERE cve_id = 'CVE-2024-53104'")[0][0] > 0
    assert not [key for key in findings(engine) if key[1] == "CVE-2024-53104"]  # 6.1.0 is affected, but not in KEV


def test_a_second_refresh_does_not_rewrite_unchanged_kev_records(engine: Engine, world: sessionmaker[Session]) -> None:
    page = recorded("nvd_kev_page.json")
    sources = Sources(page, recorded("kev_any_age.json"))
    sources.refresh(world)
    fetched = "SELECT id, fetched_at FROM cve WHERE id IN ('CVE-2024-1086', 'CVE-2025-31125') ORDER BY id"
    before = rows(engine, fetched)
    changed = next(v for v in page["vulnerabilities"] if v["cve"]["id"] == "CVE-2025-31125")
    changed["cve"]["lastModified"] = "2026-11-27T10:00:00.000"

    *_, again = sources.refresh(world)

    after = dict(rows(engine, fetched))
    assert after["CVE-2024-1086"] == dict(before)["CVE-2024-1086"]  # same lastModified: not written again
    assert after["CVE-2025-31125"] > dict(before)["CVE-2025-31125"]  # NVD changed it: stored again
    assert (again.stored, again.unchanged) == (1, page["totalResults"] - 1)


def test_a_cve_cisa_just_added_and_nvd_does_not_flag_yet_is_looked_up_by_id(
    engine: Engine, world: sessionmaker[Session]
) -> None:
    today = datetime.now(UTC).date().isoformat()
    catalogue = recorded("kev_any_age.json")
    entry = {
        "cveID": "CVE-2026-120705",
        "vendorProject": "OSGeo",
        "product": "GeoServer",
        "dateAdded": today,
        "requiredAction": "Apply mitigations per vendor instructions.",
        "knownRansomwareCampaignUse": "Unknown",
    }
    stale = entry | {"cveID": "CVE-2020-0001", "dateAdded": "2025-01-01"}  # NVD never had it: not asked forever
    unknown = entry | {"cveID": "CVE-2026-120706"}  # NVD does not know it yet: asked, nothing stored
    catalogue["vulnerabilities"] += [entry, stale, unknown]
    record = {
        "cve": {
            "id": "CVE-2026-120705",
            "published": "2026-03-02T10:00:00.000",
            "lastModified": "2026-11-27T12:00:00.000",
            "descriptions": [{"lang": "en", "value": "GeoServer flaw."}],
            "configurations": [
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:osgeo:geoserver:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "2.25.6",
                                }
                            ],
                        }
                    ]
                }
            ],
        }
    }
    sources = Sources(recorded("nvd_kev_page.json"), catalogue, {"CVE-2026-120705": record})

    *_, kev_records = sources.refresh(world)

    asked = [q["cveId"] for q in sources.nvd_queries if "cveId" in q]
    assert sorted(asked) == ["CVE-2026-120705", "CVE-2026-120706"]
    assert rows(
        engine, "SELECT vendor, product, version_end FROM cve_affected_range WHERE cve_id = 'CVE-2026-120705'"
    ) == [("osgeo", "geoserver", "2.25.6")]
    assert rows(engine, "SELECT fetched_at IS NULL FROM cve WHERE id = 'CVE-2026-120706'") == [(True,)]
    assert kev_records.stored == recorded("nvd_kev_page.json")["totalResults"] + 1
