"""Correlation against the demo inventory: OpenSSL 3.0.7 on two CIs, CVE-2026-10001 in an active group."""

from __future__ import annotations

from datetime import timedelta

import pytest
from correlation_support import NOW, add_story, demo_group
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.correlation.engine import (
    correlate_new_groups,
    correlate_stories,
    correlate_story,
    load_active_groups,
    load_match_types,
)
from core.db import models as m
from core.db.ids import new_id

pytestmark = pytest.mark.integration
CVE = "CVE-2026-10001"


def add_range(session: Session, end: str | None, start: str | None = None) -> None:
    session.add(
        m.CveAffectedRange(
            id=new_id(),
            cve_id=CVE,
            source="nvd_cpe",
            vendor="openssl",
            product="openssl",
            version_start=start,
            start_inclusive=True if start else None,
            version_end=end,
            end_inclusive=False if end else None,
        )
    )
    session.flush()


def second_group(session: Session, cve_id: str) -> m.FindingGroup:
    """A second active group on the same product, with a finding on the first CI of the demo."""
    session.add(m.Cve(id=cve_id, description="Otra", fetched_at=NOW))
    session.flush()
    first = session.scalars(select(m.FindingGroup)).first()
    assert first is not None
    group = m.FindingGroup(id=new_id(), cve_id=cve_id, software_product_id=first.software_product_id, created_at=NOW)
    session.add(group)
    session.flush()
    inst = session.scalars(select(m.InstalledSoftware).order_by(m.InstalledSoftware.itop_instance_id)).first()
    run = session.scalars(select(m.Run).where(m.Run.kind == "scan")).first()
    assert inst is not None
    assert run is not None
    finding = m.Finding(
        id=new_id(), finding_group_id=group.id, installed_software_id=inst.id, match_source="nvd_cpe", created_at=NOW
    )
    session.add(finding)
    session.flush()
    session.add(
        m.FindingStatusChange(
            id=new_id(),
            finding_id=finding.id,
            run_id=run.id,
            status="new",
            observed_version=inst.version,
            changed_at=NOW,
        )
    )
    session.flush()
    return group


def test_the_demo_group_is_loaded_with_its_cis_and_names(session: Session) -> None:
    (group,) = load_active_groups(session)
    assert group.cve_id == CVE
    assert group.vendor_products == (("openssl", "openssl"),)
    assert "OpenSSL" in group.product_names
    assert sorted(ci.version for ci in group.cis) == ["3.0.7", "3.0.7"]


def test_match_types_come_from_the_database(session: Session) -> None:
    types = load_match_types(session)
    assert {c: str(t.strength) for c, t in types.items()} == {
        "cve_exact": "1.00",
        "product_version": "0.90",
        "product": "0.60",
        "os": "0.60",
        "vector": "0.60",
    }


def test_exact_cve_with_exploitation_is_r1_and_is_stored_once(session: Session) -> None:
    story = add_story(session, cves={CVE: "active"})
    outcome = correlate_story(session, story.id, NOW)
    assert outcome is not None
    assert [(p.match_code, p.relevance) for p in outcome.matches] == [("cve_exact", "R1")]
    assert outcome.alert_id is None
    again = correlate_story(session, story.id, NOW + timedelta(hours=1))
    assert again is not None
    rows = session.scalars(select(m.Correlation).where(m.Correlation.story_id == story.id)).all()
    assert [(r.match_type, r.relevance) for r in rows] == [("cve_exact", "R1")]


@pytest.mark.parametrize("level", ["denied", "attempted", "none", None])
def test_a_cve_without_reported_exploitation_is_not_r1(session: Session, level: str | None) -> None:
    story = add_story(session, cves={CVE: level or "unknown"})
    outcome = correlate_story(session, story.id, NOW)
    assert outcome is not None
    assert outcome.matches[0].match_code == "cve_exact"
    assert outcome.matches[0].relevance is None


def test_product_in_the_affected_range_is_product_version_r2(session: Session) -> None:
    add_range(session, end="3.0.8")
    story = add_story(session, products=[("OpenSSL", "OpenSSL", "9.9")])  # the news text version is never used
    outcome = correlate_story(session, story.id, NOW)
    assert outcome is not None
    assert [(p.match_code, p.relevance) for p in outcome.matches] == [("product_version", "R2")]


def test_a_product_outside_the_range_does_not_cross_the_group_but_is_still_an_alert(session: Session) -> None:
    add_range(session, end="3.0.5")
    story = add_story(session, products=[("openssl", "openssl", "3.0.7")])
    outcome = correlate_story(session, story.id, NOW)
    assert outcome is not None
    assert outcome.matches == []
    assert outcome.alert_id is not None
    alert = session.get(m.Alert, outcome.alert_id)
    assert alert is not None
    assert (alert.relevance, alert.status) == ("R2", "open")
    assets = session.scalars(select(m.AlertAsset).where(m.AlertAsset.alert_id == alert.id)).all()
    assert len(assets) == 2
    assert all(a.version_confirmed for a in assets)  # the news names 3.0.7 and the CIs run 3.0.7


def test_product_without_range_data_is_the_weaker_product_key(session: Session) -> None:
    story = add_story(session, products=[("OpenSSL", "OpenSSL", None)])
    outcome = correlate_story(session, story.id, NOW)
    assert outcome is not None
    assert [(p.match_code, p.relevance) for p in outcome.matches] == [("product", "R2")]


def test_a_version_that_cannot_be_compared_falls_back_to_product(session: Session) -> None:
    add_range(session, end="3.0.8")
    for change in session.scalars(select(m.FindingStatusChange)):
        change.observed_version = "weird-build"
    session.flush()
    outcome = correlate_story(session, add_story(session, products=[("openssl", "openssl", None)]).id, NOW)
    assert outcome is not None
    assert [p.match_code for p in outcome.matches] == ["product"]


def test_a_single_word_never_crosses(session: Session) -> None:
    for products in ([(None, "openssl", None)], [("openssl", "", None)], [("openssl", "ssl", None)]):
        outcome = correlate_story(session, add_story(session, products=products).id, NOW)
        assert outcome is not None
        assert outcome.matches == []
        assert outcome.alert_id is None


def test_os_key_needs_family_and_version_in_the_ci(session: Session) -> None:
    asset = session.scalars(select(m.Asset).order_by(m.Asset.itop_ci_id)).first()
    assert asset is not None
    asset.os = "Ubuntu 22.04 LTS"
    session.flush()
    outcome = correlate_story(session, add_story(session, products=[("canonical", "ubuntu", "22.04")]).id, NOW)
    assert outcome is not None
    assert [(p.match_code, p.relevance) for p in outcome.matches] == [("os", "R2")]
    other = correlate_story(session, add_story(session, products=[("canonical", "ubuntu", "20.04")]).id, NOW)
    assert other is not None
    assert other.matches == []


def test_an_attack_vector_that_is_a_product_in_itop_is_r3(session: Session) -> None:
    outcome = correlate_story(session, add_story(session, vectors=["openssl"]).id, NOW)
    assert outcome is not None
    assert [(p.match_code, p.relevance) for p in outcome.matches] == [("vector", "R3")]
    nothing = correlate_story(session, add_story(session, vectors=["ssl"]).id, NOW)
    assert nothing is not None
    assert nothing.matches == []


def test_the_strongest_key_per_group_wins(session: Session) -> None:
    add_range(session, end="3.0.8")
    story = add_story(session, cves={CVE: "mass"}, products=[("openssl", "openssl", None)], vectors=["openssl"])
    outcome = correlate_story(session, story.id, NOW)
    assert outcome is not None
    assert [(p.match_code, p.relevance) for p in outcome.matches] == [("cve_exact", "R1")]


def test_the_per_news_cap_keeps_the_strongest_groups(session: Session) -> None:
    other = second_group(session, "CVE-2026-10002")
    session.add(
        m.SettingValue(
            id=new_id(), setting_key="max_matches_per_news", version=1, value=1, origin="seed", changed_at=NOW
        )
    )
    session.flush()
    story = add_story(session, cves={"CVE-2026-10002": "active"}, products=[("openssl", "openssl", None)])
    outcome = correlate_story(session, story.id, NOW)
    assert outcome is not None
    assert outcome.dropped == 1
    assert [(p.group_id, p.match_code) for p in outcome.matches] == [(other.id, "cve_exact")]
    assert session.scalar(select(func.count()).select_from(m.Correlation)) == 1


def test_peer_victim_makes_an_alert_r3(session: Session) -> None:
    peer = m.PeerCompany(id=new_id(), name="Globex Corp", created_at=NOW)
    session.add(peer)
    session.flush()
    session.add(m.PeerCompanyAlias(peer_company_id=peer.id, alias="Globex"))
    outcome = correlate_story(session, add_story(session, victims=[{"name": "GLOBEX"}]).id, NOW)
    assert outcome is not None
    assert outcome.relevances == {"R3"}
    assert outcome.alert_id is not None
    by_id = correlate_story(
        session, add_story(session, victims=[{"name": "Unrelated", "peer_company_id": peer.id}]).id, NOW
    )
    assert by_id is not None
    assert by_id.relevances == {"R3"}


def test_a_victim_in_the_profile_sector_makes_an_alert_r3_and_other_sectors_do_not(session: Session) -> None:
    session.add(m.ProfileSector(sector_code="healthcare", is_primary=True))
    session.flush()
    inside = correlate_story(
        session, add_story(session, victims=[{"name": "Clinic", "sector_code": "healthcare"}]).id, NOW
    )
    outside = correlate_story(
        session,
        add_story(session, victims=[{"name": "Shop", "sector_code": "retail"}], event_types=["other"]).id,
        NOW,
    )
    assert inside is not None
    assert inside.relevances == {"R3"}
    assert outside is not None
    assert outside.relevances == set()
    assert outside.alert_id is None


def test_an_actor_with_history_against_the_profile_is_r4(session: Session) -> None:
    session.add(m.ProfileSector(sector_code="healthcare", is_primary=True))
    session.flush()
    add_story(session, actors=["Lockbit"], victims=[{"name": "Old clinic", "sector_code": "healthcare"}])
    fresh = add_story(session, actors=["Lockbit"], victims=[{"name": "Somewhere", "sector_code": "retail"}])
    outcome = correlate_story(session, fresh.id, NOW)
    assert outcome is not None
    assert outcome.relevances == {"R4"}
    assert session.get(m.Alert, outcome.alert_id) is not None
    stranger = add_story(session, actors=["Nobody"], victims=[{"name": "Somewhere", "sector_code": "retail"}])
    quiet = correlate_story(session, stranger.id, NOW)
    assert quiet is not None
    assert quiet.relevances == set()


def test_actor_history_needs_a_profile_to_compare_with(session: Session) -> None:
    add_story(session, actors=["Lockbit"], victims=[{"name": "Old clinic", "sector_code": "healthcare"}])
    fresh = add_story(session, actors=["Lockbit"])
    outcome = correlate_story(session, fresh.id, NOW)
    assert outcome is not None
    assert outcome.relevances == set()


def test_a_security_event_that_crossed_with_nothing_is_a_dismissal_candidate(session: Session) -> None:
    candidate = correlate_story(session, add_story(session, event_types=["active_exploitation"]).id, NOW)
    harmless = correlate_story(session, add_story(session, event_types=["patch_advisory"]).id, NOW)
    assert candidate is not None
    assert (candidate.matches, candidate.alert_id, candidate.dismissal_candidate) == ([], None, True)
    assert harmless is not None
    assert harmless.dismissal_candidate is False


def test_a_story_without_analysis_is_skipped(session: Session) -> None:
    story = add_story(session)
    bare = m.Story(
        id=new_id(),
        representative_article_id=story.representative_article_id,
        relevance_status="relevant",
        created_at=NOW,
    )
    session.add(bare)
    session.flush()
    assert correlate_story(session, bare.id, NOW) is None


def test_new_scan_correlates_the_new_group_with_recent_stories(session: Session) -> None:
    group = demo_group(session)
    recent = add_story(session, cves={CVE: "limited"})
    outcomes = correlate_new_groups(session, {group}, NOW + timedelta(hours=1))
    assert [o.story_id for o in outcomes] == [recent.id]
    assert correlate_new_groups(session, set(), NOW) == []
    session.execute(m.Correlation.__table__.delete())
    session.execute(m.Alert.__table__.delete())
    session.commit()


def test_new_news_correlates_each_story_and_commits(session: Session) -> None:
    story = add_story(session, cves={CVE: "active"})
    outcomes = correlate_stories(session, [story.id], NOW)
    assert [o.matches[0].match_code for o in outcomes] == ["cve_exact"]
    session.execute(m.Correlation.__table__.delete())
    session.commit()


def test_a_scan_with_an_unrelated_group_does_not_turn_a_correlated_story_into_an_alert(session: Session) -> None:
    story = add_story(
        session, cves={CVE: "active"}, products=[("openssl", "openssl", None)], event_types=["active_exploitation"]
    )
    first = correlate_story(session, story.id, NOW)
    assert first is not None
    assert len(first.matches) == 1
    unrelated = correlate_story(session, story.id, NOW + timedelta(hours=1), groups=[])
    assert unrelated is not None
    assert (unrelated.matches, unrelated.alert_id, unrelated.dismissal_candidate) == ([], None, False)
    assert session.scalar(select(func.count()).select_from(m.Alert)) == 0


def test_a_news_item_naming_an_os_in_itop_is_an_r2_alert_on_those_cis(session: Session) -> None:
    asset = m.Asset(
        id=new_id(),
        itop_ci_id="CI-900",
        itop_class="Server",
        name="srv-windows",
        os="Windows Server 2019",
        criticality="medium",
        confidentiality="public",
        synced_at=NOW,
    )
    session.add(asset)
    session.flush()
    outcome = correlate_story(session, add_story(session, products=[("microsoft", "windows server", "2019")]).id, NOW)
    assert outcome is not None
    assert outcome.relevances == {"R2"}
    assert outcome.alert_id is not None
    touched = session.scalars(select(m.AlertAsset.asset_id).where(m.AlertAsset.alert_id == outcome.alert_id)).all()
    assert touched == [asset.id]
