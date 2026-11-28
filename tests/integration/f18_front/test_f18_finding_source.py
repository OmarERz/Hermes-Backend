"""F18.9: how each finding was matched (ESC-09) and its certainty, over the F18.1 scenario.

Changed here: CI-1's G1 finding came from KEV through the CNA's ranges (`kev`), and CI-1 gets a second OpenSSL
installation whose G2 finding came from CVE.org only (`cna_affected`) and reopened, so it is that CI's most pressing
instance of G2 while its first instance (`nvd_cpe`, new) stays. Everything else stays `nvd_cpe`; CI-2's G1 finding is
fixed, so it does not speak for G1.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from f18data import Front
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from core.db import models as m

pytestmark = pytest.mark.integration
Get = Callable[..., Any]
T0 = datetime(2026, 11, 28, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def sourced(database: tuple[str, Engine], front: Front) -> Front:
    sc = front.scenario
    with Session(database[1]) as session, session.begin():
        session.get_one(m.Finding, sc.findings[("G1", "CI-1")]).match_source = "kev"
        openssl = session.scalars(select(m.SoftwareProduct.id).where(m.SoftwareProduct.itop_name == "OpenSSL")).one()
        second = m.InstalledSoftware(
            itop_instance_id="SI-1B",
            asset_id=sc.assets["CI-1"],
            software_product_id=openssl,
            version="1.1.1",
            synced_at=T0,
        )
        session.add(second)
        session.flush()
        reopened = m.Finding(
            finding_group_id=sc.groups["G2"],
            installed_software_id=second.id,
            match_source="cna_affected",
            created_at=T0,
        )
        session.add(reopened)
        session.flush()
        session.add(
            m.FindingStatusChange(
                finding_id=reopened.id, run_id=sc.run_id, status="reopened", observed_version="1.1.1", changed_at=T0
            )
        )
        sc.findings[("G2", "CI-1b")] = reopened.id
    return front


def _by_cve(groups: list[dict[str, Any]]) -> dict[str, list[str]]:
    return {g["cve"]: g["match_sources"] for g in groups}


def test_each_affected_asset_says_how_its_finding_was_matched(get: Get, sourced: Front) -> None:
    sc = sourced.scenario
    g1 = {a["ci_id"]: a for a in get(f"/api/vulnerabilities/{sc.groups['G1']}")["assets"]}
    assert {ci: (a["match_source"], a["certainty"]) for ci, a in g1.items()} == {
        "CI-1": ("kev", "1.0"),
        "CI-2": ("nvd_cpe", "1.0"),
    }
    g2 = {a["ci_id"]: a for a in get(f"/api/vulnerabilities/{sc.groups['G2']}")["assets"]}
    # CI-1's reopened CVE.org instance is its most pressing one: source, finding and status all come from it
    assert {k: g2["CI-1"][k] for k in ("match_source", "certainty", "finding_id", "finding_status")} == {
        "match_source": "cna_affected",
        "certainty": "0.9",
        "finding_id": str(sc.findings[("G2", "CI-1b")]),
        "finding_status": "reopened",
    }
    assert (g2["CI-3"]["match_source"], g2["CI-3"]["certainty"]) == ("nvd_cpe", "1.0")


def test_a_group_lists_the_sources_of_the_cis_that_speak_for_it(get: Get, sourced: Front) -> None:
    groups = _by_cve(get("/api/vulnerabilities")["groups"])
    assert groups == {
        "CVE-2026-10001": ["kev"],  # CI-2 (nvd_cpe) is fixed: only CI-1 speaks
        "CVE-2026-10002": ["nvd_cpe", "cna_affected"],  # most certain first
        "CVE-2026-10003": ["nvd_cpe"],  # every finding fixed: they all speak
    }
    bands = get("/api/vulnerabilities", view="criticality")["bands"]
    assert _by_cve([g for band in bands for g in band["groups"]]) == groups
    detail = get(f"/api/vulnerabilities/{sourced.scenario.groups['G2']}")
    assert detail["match_sources"] == ["nvd_cpe", "cna_affected"]


def test_the_asset_detail_gives_each_finding_the_source_of_that_ci(get: Get, sourced: Front) -> None:
    findings = _by_cve(get("/api/assets/CI-1")["findings"])
    assert findings == {"CVE-2026-10001": ["kev"], "CVE-2026-10002": ["cna_affected"]}  # the group says two sources
