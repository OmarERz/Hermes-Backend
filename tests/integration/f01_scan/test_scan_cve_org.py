"""The CVE.org path (ESC-05, ESC-09, D-103): the refresh loads the CNA records of the CVEs NIST has not enriched that
may concern a mapped product, and the scan matches their `affected[]` with certainty 0.9 (`cna_affected`).

F20 dry run, P1-1: the path was never used (2,294 expected findings, 2,095 of them on the kernel). Recorded answers,
trimmed (English description cut, two references, no ADP container; the kernel's git entries cut to two):
`nvd_cna_window.json` holds NVD's records of 27 Nov 2026 for these CVEs (all unenriched but CVE-2026-100070, which NVD
configured) and `cveorg/` their cvelistV5 files of the same day. Product names are those of the F20 inventory.
"""

from __future__ import annotations

import copy
import gzip
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session, sessionmaker

from core.cpe.mapping import MappingInput, set_mapping
from core.db import models as m
from core.pipeline.cycles import Pipeline, ScanCycleOutput, Steps
from core.pipeline.wiring import refresh_vulndata
from core.scan.engine import ScanOptions, run_scan
from core.vulndata import cna_discovery
from core.vulndata.cvelist import RAW_URL, CveOrgClient
from core.vulndata.epss import EPSS_DAILY_URL
from core.vulndata.http import JsonSource, SourceUnavailableError
from core.vulndata.kev import KEV_URL
from core.vulndata.nvd import NVD_URL, NvdClient

pytestmark = pytest.mark.integration
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "vulndata"
SCAN_AT = datetime(2026, 11, 27, 9, 34, 35, tzinfo=UTC)
EMPTY_PAGE: dict[str, Any] = {"vulnerabilities": [], "totalResults": 0}
# CI, product, version, NVD (part, vendor, product), CNA (vendor, product)
INSTALLS = (
    ("eks-nodo-01", "Linux Kernel", "6.1.0", ("o", "linux", "linux_kernel"), ("Linux", "Linux")),
    ("rds-pagos", "PostgreSQL", "15.4", ("a", "postgresql", "postgresql"), ("n/a", "PostgreSQL")),
    ("web-dashboard-operaciones", "Next.js", "13.5.0", ("a", "vercel", "next.js"), ("vercel", "next.js")),
    ("svc-flotas", "Python", "3.11.0", ("a", "python", "python"), ("Python Software Foundation", "CPython")),
    ("msk-eventos", "Apache Kafka", "3.5.0", ("a", "apache", "kafka"), ("Apache Software Foundation", "Apache Kafka")),
    ("pc-build-movil-01", "Vite", "4.5.0", ("a", "vitejs", "vite"), ("vitejs", "vite")),
    ("svc-viajes", "Go", "1.21.0", ("a", "golang", "go"), None),  # the Go CNA cannot be named with one pair
)
EXPECTED = {
    ("eks-nodo-01", "CVE-2026-100080"): "cna_affected",  # introduced in 3.16, fixed in 6.1.192
    ("eks-nodo-01", "CVE-2026-100070"): "nvd_cpe",  # NVD configured it: no CVE.org request
    ("rds-pagos", "CVE-2026-116303"): "cna_affected",  # vendor `n/a`, 15 <= v < 15.20
    ("web-dashboard-operaciones", "CVE-2026-75604"): "cna_affected",  # `>= 13.4.0, < 15.5.24`
    ("svc-flotas", "CVE-2026-115557"): "cna_affected",  # its description names Python
    ("svc-flotas", "CVE-2026-114583"): "cna_affected",  # `tarfile…`: found through its CNA (cna@python.org)
    ("msk-eventos", "CVE-2026-110952"): "cna_affected",  # `A Kafka broker…`: named by the NVD product
    ("pc-build-movil-01", "CVE-2026-112945"): "cna_affected",  # `< 6.4.4`
}


def recorded(name: str) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return loaded


def epss_file() -> bytes:
    return gzip.compress(b"#model_version:v2025.03.14,score_date:2026-11-27T00:00:00Z\ncve,epss,percentile\n")


class Sources:
    """NVD, CISA, FIRST and GitHub (cvelistV5 raw files) behind one mock transport; records the GitHub requests."""

    def __init__(self, window: dict[str, Any], kev: list[dict[str, Any]] | None = None) -> None:
        self.window = window
        self.kev = kev or []
        self.github: list[str] = []
        self.github_down = False
        self.flaky = False  # every record answers 503 once, then the file
        self.epss_broken = False
        self.extra: dict[str, dict[str, Any]] = {}  # CVE.org documents served besides the fixtures

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = f"{request.url.scheme}://{request.url.host}{request.url.path}"
        if url == KEV_URL:
            return httpx.Response(200, json={"vulnerabilities": []})
        if url == EPSS_DAILY_URL:
            return httpx.Response(200, content=b"not the EPSS file" if self.epss_broken else epss_file())
        if url.startswith(RAW_URL):
            return self.cve_org(url.rsplit("/", 1)[-1].removesuffix(".json"))
        assert url == NVD_URL, url
        return httpx.Response(200, json=self.nvd(dict(request.url.params)))

    def cve_org(self, cve_id: str) -> httpx.Response:
        retry = self.flaky and self.github.count(cve_id) == 0
        self.github.append(cve_id)
        if self.github_down or retry:
            return httpx.Response(503)
        if cve_id in self.extra:
            return httpx.Response(200, json=self.extra[cve_id])
        path = FIXTURES / "cveorg" / f"{cve_id}.json"
        return httpx.Response(200, text=path.read_text(encoding="utf-8")) if path.exists() else httpx.Response(404)

    def nvd(self, params: dict[str, str]) -> dict[str, Any]:
        if "hasKev" in params:
            return {"vulnerabilities": self.kev, "totalResults": len(self.kev)}
        return EMPTY_PAGE if "cveId" in params else self.window  # otherwise the recency window

    def refresh(self, factory: sessionmaker[Session], attempts: int = 1) -> Any:
        return self.refresh_step(factory, attempts)()

    def refresh_step(self, factory: sessionmaker[Session], attempts: int = 1) -> Any:
        """The worker's refresh step (`Steps.refresh`) against these sources."""
        http = httpx.Client(transport=httpx.MockTransport(self.handler))
        source = JsonSource(http=http, max_attempts=attempts, sleep=lambda _s: None)
        return refresh_vulndata(factory, NvdClient(JsonSource(http=http)), source)


def run(engine: Engine, statement: str, params: dict[str, Any] | None = None) -> None:
    with engine.begin() as conn:
        conn.execute(text(statement), params or {})


def rows(engine: Engine, statement: str, params: dict[str, Any] | None = None) -> list[tuple[Any, ...]]:
    with engine.connect() as conn:
        return [tuple(r) for r in conn.execute(text(statement), params or {})]


@pytest.fixture
def world(engine: Engine) -> sessionmaker[Session]:
    for ci, product, version, nvd, cna in INSTALLS:
        asset, item = uuid.uuid4(), uuid.uuid4()
        run(
            engine,
            "INSERT INTO asset (id, itop_ci_id, itop_class, name, criticality, confidentiality, synced_at) "
            "VALUES (:id, :ci, 'Server', :ci, 'high', 'classified', now())",
            {"id": asset, "ci": ci},
        )
        run(
            engine,
            "INSERT INTO software_product (id, itop_name, first_seen_at) VALUES (:id, :name, now())",
            {"id": item, "name": product},
        )
        run(
            engine,
            "INSERT INTO cpe_mapping (software_product_id, nvd_part, nvd_vendor, nvd_product, cna_vendor, cna_product, "
            "origin, mapped_at) VALUES (:p, :part, :v, :n, :cv, :cp, 'manual', now())",
            {"p": item, "part": nvd[0], "v": nvd[1], "n": nvd[2], "cv": cna and cna[0], "cp": cna and cna[1]},
        )
        run(
            engine,
            "INSERT INTO installed_software (itop_instance_id, asset_id, software_product_id, version, synced_at) "
            "VALUES (:iid, :asset, :product, :version, now())",
            {"iid": f"SI-{ci}", "asset": asset, "product": item, "version": version},
        )
    return sessionmaker(engine, expire_on_commit=False)


def findings(engine: Engine) -> dict[tuple[str, str], str]:
    found = rows(
        engine,
        "SELECT a.itop_ci_id, g.cve_id, f.match_source FROM finding f "
        "JOIN finding_group g ON g.id = f.finding_group_id "
        "JOIN installed_software i ON i.id = f.installed_software_id JOIN asset a ON a.id = i.asset_id",
    )
    return {(ci, cve): source for ci, cve, source in found}


def test_the_refresh_loads_cna_records_and_the_scan_matches_them_with_certainty_0_9(
    engine: Engine, world: sessionmaker[Session]
) -> None:
    sources = Sources(recorded("nvd_cna_window.json"))
    *_, cve_org = sources.refresh(world)
    # Only unenriched CVEs that name a mapped product, then the rest of a CNA that published one; never Go's (no CNA
    # pair), nor the one NVD configured, nor the kernel CVE twice.
    assert set(sources.github) == {cve for (_, cve), src in EXPECTED.items() if src == "cna_affected"} | {
        "CVE-2026-80872"
    }
    assert sorted(sources.github) == sorted(set(sources.github))
    assert "cna@python.org" in cve_org.followed_sources
    assert (cve_org.stored, cve_org.missing, cve_org.capped, cve_org.interrupted) == (8, 0, False, False)
    assert cve_org.git_only == 2  # the git-commit entries of the two kernel records: counted, never compared
    run_scan(world, ScanOptions(), now=SCAN_AT)
    assert findings(engine) == EXPECTED  # CVE-2026-80872 starts in 6.6: 6.1.0 is not affected


def test_a_second_refresh_asks_nothing_when_nvd_shows_no_change(engine: Engine, world: sessionmaker[Session]) -> None:
    sources = Sources(recorded("nvd_cna_window.json"))
    sources.refresh(world)
    sources.github.clear()
    *_, cve_org = sources.refresh(world)
    assert sources.github == []
    assert cve_org.unchanged == 8
    window = copy.deepcopy(sources.window)  # NVD re-dates one record (it took in a CNA update): only it is asked
    entry = next(v for v in window["vulnerabilities"] if v["cve"]["id"] == "CVE-2026-116303")
    entry["cve"]["lastModified"] = "2026-11-28T10:00:00.000"
    sources.window = window
    sources.refresh(world)
    assert sources.github == ["CVE-2026-116303"]


def test_a_cve_org_finding_that_nvd_confirms_takes_the_nvd_source(engine: Engine, world: sessionmaker[Session]) -> None:
    sources = Sources(recorded("nvd_cna_window.json"))
    sources.refresh(world)
    run_scan(world, ScanOptions(), now=SCAN_AT)
    assert findings(engine)[("eks-nodo-01", "CVE-2026-100080")] == "cna_affected"
    window = copy.deepcopy(sources.window)
    entry = next(v for v in window["vulnerabilities"] if v["cve"]["id"] == "CVE-2026-100080")
    entry["cve"]["lastModified"] = "2026-11-28T10:00:00.000"
    entry["cve"]["configurations"] = [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "3.16",
                            "versionEndExcluding": "6.1.192",
                        }
                    ],
                }
            ]
        }
    ]
    sources.window = window
    sources.github.clear()
    sources.refresh(world)
    assert "CVE-2026-100080" not in sources.github  # configured by NVD: no longer a CVE.org candidate
    result = run_scan(world, ScanOptions(), now=datetime(2026, 11, 28, 12, tzinfo=UTC))
    assert findings(engine)[("eks-nodo-01", "CVE-2026-100080")] == "nvd_cpe"
    assert result.source_changes == 1
    assert len(findings(engine)) == len(EXPECTED)  # one finding per CI and CVE, never a second one


def test_the_cna_cvss_is_used_when_nvd_has_none(engine: Engine, world: sessionmaker[Session]) -> None:
    """D-104: NVD's CVSS first, then the CNA's. Here NVD's record of the Next.js CVE carries no metrics."""
    window = copy.deepcopy(recorded("nvd_cna_window.json"))
    entry = next(v for v in window["vulnerabilities"] if v["cve"]["id"] == "CVE-2026-75604")
    entry["cve"].pop("metrics")
    Sources(window).refresh(world)
    assert rows(engine, "SELECT cvss_source, cvss_version, cvss_score FROM cve WHERE id = 'CVE-2026-75604'") == [
        ("cna", "3.1", pytest.approx(9.0))
    ]


def test_an_outage_of_github_stops_only_the_cve_org_step(engine: Engine, world: sessionmaker[Session]) -> None:
    sources = Sources(recorded("nvd_cna_window.json"))
    sources.github_down = True
    nvd, *_, cve_org = sources.refresh(world)
    assert cve_org.interrupted and cve_org.stored == 0 and len(sources.github) == 1
    assert nvd.stored == 10  # the NVD window was stored before
    run_scan(world, ScanOptions(), now=SCAN_AT)
    assert findings(engine) == {("eks-nodo-01", "CVE-2026-100070"): "nvd_cpe"}


def test_without_cna_names_nothing_is_asked(engine: Engine, world: sessionmaker[Session]) -> None:
    run(engine, "UPDATE cpe_mapping SET cna_vendor = NULL, cna_product = NULL")
    sources = Sources(recorded("nvd_cna_window.json"))
    *_, cve_org = sources.refresh(world)
    assert sources.github == [] and cve_org.candidates == 0


def test_the_request_budget_bounds_a_refresh(
    engine: Engine, world: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cna_discovery, "MAX_REQUESTS", 6)  # a record is asked while 4 more requests fit: 3 records
    sources = Sources(recorded("nvd_cna_window.json"))
    *_, cve_org = sources.refresh(world)
    assert len(sources.github) == 3 and cve_org.capped and cve_org.requests == 3
    assert cve_org.budget == 6 and cve_org.waiting == cve_org.candidates - 3


def kernel_sighting(n: int) -> dict[str, Any]:
    """An unenriched kernel CVE of the window, newer than the recorded ones; cvelistV5 has no file for it (404)."""
    return {
        "cve": {
            "id": f"CVE-2026-9{n:05d}",
            "sourceIdentifier": "416baaa9-dc9f-4396-8d5f-8c081fb06d67",
            "published": "2026-11-20T00:00:00.000",
            "lastModified": "2026-11-21T00:00:00.000",
            "vulnStatus": "Received",
            "descriptions": [{"lang": "en", "value": "In the Linux kernel, the following vulnerability was resolved."}],
        }
    }


def test_a_fresh_mapping_converges_in_one_refresh_beyond_the_old_cap(
    engine: Engine, world: sessionmaker[Session], caplog: pytest.LogCaptureFixture
) -> None:
    """Rehearsal 2, P2-A: the first refresh after mapping had 5,124 candidates and stopped at the fixed cap of 5,000
    requests, so a CNA learned from its records (here CPython's, whose CVE-2026-114583 names `tarfile`, not Python)
    waited a day for its pass. The budget now follows the candidates (two requests each, ceiling 12,000) and each CNA
    learned gets its pass in the same refresh: the recorded records all arrive, and the scan finds them all."""
    window = recorded("nvd_cna_window.json")
    observed = cna_discovery.Observed()
    for item in [*(kernel_sighting(n) for n in range(5_124)), *window["vulnerabilities"]]:
        observed.see(item)
    sources = Sources(window)
    http = httpx.Client(transport=httpx.MockTransport(sources.handler))
    client = CveOrgClient(JsonSource(http=http, max_attempts=1, sleep=lambda _s: None))
    with caplog.at_level(logging.INFO, logger=cna_discovery.__name__):
        result = cna_discovery.refresh_cve_org(world, client, observed, {})
    assert (result.capped, result.waiting, result.passes) == (False, 0, 2)
    assert result.candidates == result.requests == 5_124 + 8  # 7 named + CPython's tarfile record in the 2nd pass
    assert result.budget == 2 * result.candidates <= cna_discovery.MAX_REQUESTS
    assert (result.stored, result.missing) == (8, 5_124)
    assert "cna@python.org" in result.followed_sources and sources.github[-1] == "CVE-2026-114583"
    assert f"budget of {result.budget} (2 per candidate, at least 500, ceiling 12000)" in caplog.text
    run_scan(world, ScanOptions(), now=SCAN_AT)
    assert {key for key, src in findings(engine).items() if src == "cna_affected"} == {
        key for key, src in EXPECTED.items() if src == "cna_affected"
    }


def test_the_budget_never_passes_its_ceiling(
    engine: Engine, world: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The budget grows with the candidates but stops at `MAX_REQUESTS`; what it leaves is counted and logged."""
    monkeypatch.setattr(cna_discovery, "MAX_REQUESTS", 600)
    observed = cna_discovery.Observed()
    for n in range(1_000):
        observed.see(kernel_sighting(n))
    sources = Sources(EMPTY_PAGE)
    http = httpx.Client(transport=httpx.MockTransport(sources.handler))
    client = CveOrgClient(JsonSource(http=http, max_attempts=1, sleep=lambda _s: None))
    with caplog.at_level(logging.INFO, logger=cna_discovery.__name__):
        result = cna_discovery.refresh_cve_org(world, client, observed, {})
    assert result.budget == 600 and result.capped
    assert result.requests == len(sources.github) == 597  # a record is asked while its worst case (4) still fits
    assert result.waiting == 1_000 - 597
    assert "ran out: 403 candidates wait for the next refresh" in caplog.text


def test_retries_count_against_the_request_budget(
    engine: Engine, world: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    """T4 review r2: the budget is HTTP requests, retries included, and a record is only asked when its worst case
    (2 attempts x 4 hops here) still fits."""
    monkeypatch.setattr(cna_discovery, "MAX_REQUESTS", 20)
    sources = Sources(recorded("nvd_cna_window.json"))
    sources.flaky = True
    *_, cve_org = sources.refresh(world, attempts=2)
    assert cve_org.requests == len(sources.github) <= 20
    assert cve_org.capped and cve_org.stored == len(sources.github) // 2


def redated(window: dict[str, Any], cve_ids: set[str], when: str = "2026-11-28T10:00:00.000") -> dict[str, Any]:
    copied = copy.deepcopy(window)
    for entry in copied["vulnerabilities"]:
        if entry["cve"]["id"] in cve_ids:
            entry["cve"]["lastModified"] = when
    return copied


def test_a_record_due_again_that_an_outage_kept_out_is_asked_on_the_next_refresh(
    engine: Engine, world: sessionmaker[Session]
) -> None:
    """The cache date only advances when the CNA record is stored (T4 review, P1): NVD re-dates CVE-2026-116303, GitHub
    is down during that refresh, and the next refresh asks for it again instead of keeping the old ranges."""
    sources = Sources(recorded("nvd_cna_window.json"))
    sources.refresh(world)
    sources.window = redated(sources.window, {"CVE-2026-116303"})
    sources.github_down = True
    sources.refresh(world)
    sources.github_down = False
    sources.github.clear()
    sources.refresh(world)
    assert sources.github == ["CVE-2026-116303"]
    sources.github.clear()
    sources.refresh(world)
    assert sources.github == []  # stored this time: the cache holds again


def test_the_budget_goes_to_the_newest_candidates_whatever_made_them_candidates(
    engine: Engine, world: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Named candidates and those of a CNA already known compete for the budget by publication date (T4 review, P1)."""
    sources = Sources(recorded("nvd_cna_window.json"))
    sources.refresh(world)
    due = {cve for (_, cve), src in EXPECTED.items() if src == "cna_affected"} | {"CVE-2026-80872"}
    sources.window = redated(sources.window, due)
    published = {
        v["cve"]["id"]: v["cve"]["published"] for v in sources.window["vulnerabilities"] if v["cve"]["id"] in due
    }
    monkeypatch.setattr(cna_discovery, "MAX_REQUESTS", 6)  # 3 records (1 attempt, up to 3 redirects each)
    sources.github.clear()
    sources.refresh(world)
    newest = sorted(published, key=lambda cve: published[cve], reverse=True)[:3]
    assert sorted(sources.github) == sorted(newest)


def test_old_kev_records_do_not_count_against_following_a_cna(
    engine: Engine, world: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`LEARN_MAX` counts the CNA's unenriched CVEs published in the window, not its old KEV ones (T4 review, P1)."""
    monkeypatch.setattr(cna_discovery, "LEARN_MAX", 2)  # cna@python.org has 2 in the window
    old = {
        "cve": {
            "id": "CVE-2020-99999",
            "sourceIdentifier": "cna@python.org",
            "published": "2020-01-01T00:00:00",
            "lastModified": "2020-01-02T00:00:00",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "An old record."}],
        }
    }
    sources = Sources(recorded("nvd_cna_window.json"), kev=[old])
    *_, cve_org = sources.refresh(world)
    assert "cna@python.org" in cve_org.followed_sources
    assert "CVE-2026-114583" in sources.github


def test_a_failure_before_cve_org_does_not_hide_a_record_nvd_redated(
    engine: Engine, world: sessionmaker[Session]
) -> None:
    """T4 review r2: EPSS fails after NVD stored the new date, so CVE.org never ran; the next refresh asks for it."""
    sources = Sources(recorded("nvd_cna_window.json"))
    sources.refresh(world)
    sources.window = redated(sources.window, {"CVE-2026-116303"})
    sources.epss_broken = True
    sources.github.clear()
    with pytest.raises(SourceUnavailableError):
        sources.refresh(world)
    assert sources.github == []
    sources.epss_broken = False
    sources.refresh(world)
    assert sources.github == ["CVE-2026-116303"]


def test_a_known_cna_is_still_followed_when_nist_enriched_its_known_records(
    engine: Engine, world: sessionmaker[Session]
) -> None:
    """T4 review r2: the CPython CNA was learned from two records NVD later enriched; its new record, which names a
    module and not Python, is still asked because the CNA of an enriched record is still seen in NVD's pages."""
    sources = Sources(recorded("nvd_cna_window.json"))
    sources.refresh(world)
    window = copy.deepcopy(sources.window)
    for entry in window["vulnerabilities"]:
        if entry["cve"]["id"] in {"CVE-2026-115557", "CVE-2026-114583"}:
            entry["cve"]["configurations"] = [{"nodes": []}]
            entry["cve"]["lastModified"] = "2026-11-28T10:00:00.000"
    new = copy.deepcopy(next(v for v in window["vulnerabilities"] if v["cve"]["id"] == "CVE-2026-114583"))
    new["cve"]["id"] = "CVE-2026-199999"
    new["cve"].pop("configurations")
    window["vulnerabilities"].append(new)
    sources.window = window
    document = recorded("cveorg/CVE-2026-114583.json")
    document["cveMetadata"]["cveId"] = "CVE-2026-199999"
    sources.extra["CVE-2026-199999"] = document
    sources.github.clear()
    sources.refresh(world)
    assert sources.github == ["CVE-2026-199999"]


def test_a_rejected_cve_loses_its_cna_ranges(engine: Engine, world: sessionmaker[Session]) -> None:
    """T4 review r2: NVD rejects one CVE and CVE.org another; neither keeps CNA ranges, and the scan stops matching."""
    sources = Sources(recorded("nvd_cna_window.json"))
    sources.refresh(world)
    run_scan(world, ScanOptions(), now=SCAN_AT)
    window = copy.deepcopy(sources.window)
    for entry in window["vulnerabilities"]:
        if entry["cve"]["id"] == "CVE-2026-100080":
            entry["cve"]["vulnStatus"] = "Rejected"
    sources.window = redated(window, {"CVE-2026-116303"})
    rejected = recorded("cveorg/CVE-2026-116303.json")
    rejected["cveMetadata"]["state"] = "REJECTED"
    sources.extra["CVE-2026-116303"] = rejected
    *_, cve_org = sources.refresh(world)
    assert cve_org.cleared == 2
    left = rows(
        engine,
        "SELECT DISTINCT cve_id FROM cve_affected_range WHERE source = 'cna_affected' "
        "AND cve_id IN ('CVE-2026-100080', 'CVE-2026-116303')",
    )
    assert left == []
    result = run_scan(world, ScanOptions(), now=datetime(2026, 11, 28, 12, tzinfo=UTC))
    assert result.fixed == 2


def test_a_cve_nvd_rejects_loses_its_cna_ranges_even_if_a_later_step_fails(
    engine: Engine, world: sessionmaker[Session]
) -> None:
    """T4 review r3: EPSS fails after NVD rejected CVE-2026-100080; its CNA ranges go anyway."""
    sources = Sources(recorded("nvd_cna_window.json"))
    sources.refresh(world)
    window = copy.deepcopy(sources.window)
    for entry in window["vulnerabilities"]:
        if entry["cve"]["id"] == "CVE-2026-100080":
            entry["cve"]["vulnStatus"] = "Rejected"
    sources.window = window
    sources.epss_broken = True
    with pytest.raises(SourceUnavailableError):
        sources.refresh(world)
    assert rows(
        engine, "SELECT count(*) FROM cve_affected_range WHERE cve_id = 'CVE-2026-100080' AND source = 'cna_affected'"
    ) == [(0,)]


def test_the_readme_flow_brings_cve_org_findings_without_restarting_the_worker(
    engine: Engine, world: sessionmaker[Session]
) -> None:
    """Rehearsal 2, P2-B: load the inventory, scan, `make itop-map-cpe` (it adds the CNA names), scan again. The second
    scan gave 0 CVE.org findings until the worker restarted; now it refreshes first because a mapping changed after
    the last refresh, and a third scan does not refresh again."""
    cna = {product: names for _, product, _, _, names in INSTALLS if names}
    run(engine, "UPDATE cpe_mapping SET cna_vendor = NULL, cna_product = NULL, mapped_at = :t", {"t": SCAN_AT})
    sources = Sources(recorded("nvd_cna_window.json"))
    clock = [SCAN_AT + timedelta(hours=1)]

    def scan(run_id: uuid.UUID | None, reason: str) -> ScanCycleOutput:
        return ScanCycleOutput(run_scan(world, ScanOptions(reason=reason, run_id=run_id), now=SCAN_AT).run_id)

    steps = Steps(news=None, scan=scan, refresh=sources.refresh_step(world))
    pipeline = Pipeline(world, steps, clock=lambda: clock[0])
    pipeline.refresh_cycle()  # at worker start, before the CNA names exist: nothing to ask CVE.org
    assert sources.github == []
    pipeline.scan_cycle()
    assert findings(engine) == {("eks-nodo-01", "CVE-2026-100070"): "nvd_cpe"}
    clock[0] += timedelta(minutes=30)
    with world() as session, session.begin():  # what `PUT /api/mappings/{software}` does for each product
        for row in session.execute(
            select(m.CpeMapping, m.SoftwareProduct.itop_name).join(
                m.SoftwareProduct, m.SoftwareProduct.id == m.CpeMapping.software_product_id
            )
        ).all():
            mapping, product = row
            if product in cna:
                names = MappingInput(mapping.nvd_vendor, mapping.nvd_product, *cna[product], mapping.nvd_part)
                set_mapping(session, mapping.software_product_id, names, now=clock[0])
    clock[0] += timedelta(minutes=30)
    report = pipeline.scan_cycle()
    assert "vulnerability data refreshed first: a CPE mapping changed since the last refresh" in report.notes
    assert findings(engine) == EXPECTED
    asked = len(sources.github)
    pipeline.scan_cycle()
    assert len(sources.github) == asked  # no second refresh for the same change


def test_a_scan_after_an_interrupted_refresh_refreshes_again(engine: Engine, world: sessionmaker[Session]) -> None:
    """GitHub fails during the refresh a mapping change triggered: the refresh is incomplete, so the next scan tries
    again (the CVE.org cache skips what was stored) instead of waiting a day for the scheduled one."""
    sources = Sources(recorded("nvd_cna_window.json"))
    clock = [SCAN_AT]

    def scan(run_id: uuid.UUID | None, reason: str) -> ScanCycleOutput:
        return ScanCycleOutput(run_scan(world, ScanOptions(reason=reason, run_id=run_id), now=SCAN_AT).run_id)

    pipeline = Pipeline(world, Steps(news=None, scan=scan, refresh=sources.refresh_step(world)), clock=lambda: clock[0])
    sources.github_down = True
    first = pipeline.scan_cycle()  # no refresh has completed in this process: it refreshes, GitHub is down
    assert "CVE.org did not finish this refresh; the next scan refreshes again" in first.notes
    assert findings(engine) == {("eks-nodo-01", "CVE-2026-100070"): "nvd_cpe"}
    sources.github_down = False
    clock[0] += timedelta(hours=1)
    pipeline.scan_cycle()
    assert findings(engine) == EXPECTED and pipeline.refreshed_at == clock[0]
