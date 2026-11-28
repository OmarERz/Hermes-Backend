"""Review packages: schema, fingerprint without weights (D-033), top news and storage."""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from correlation_support import NOW, add_story, demo_group
from jsonschema import Draft202012Validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.correlation.engine import GroupCtx, StoryFacts, correlate_story, load_active_groups, load_match_types
from core.correlation.packages import (
    NewsMatch,
    ScoredGroup,
    build_alert_package,
    build_dismissal_package,
    build_finding_package,
    store_package,
)
from core.db import models as m

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]
SCHEMA = Draft202012Validator(json.loads((ROOT / "schemas" / "review_package.schema.json").read_text()))
CVE = "CVE-2026-10001"


class StubScorer:
    """Stands in for the scoring engine (F4.2); `score` changes with the weights, the fingerprint must not."""

    def __init__(self, score: int = 75) -> None:
        self.score = score

    def score_group(self, session: Session, group: GroupCtx, matches: list[NewsMatch]) -> ScoredGroup:
        ci = {"A": 1.0, "D": 0.5, "score": self.score, "floor_applicable": False}
        base = {
            "S": 0.98,
            "P": 1.0,
            "T": 0.2,
            "A": 1.0,
            "D": 0.5,
            "score": self.score,
            "details": [],
            "floor_applicable": False,
        }
        return ScoredGroup(base, {c.asset_id: dict(ci) for c in group.cis})

    def score_story(self, session: Session, facts: StoryFacts, asset_ids: list[uuid.UUID]) -> dict[str, Any]:
        return {
            "S": 0.0,
            "P": 0.2,
            "T": 0.0,
            "A": 0.5,
            "D": 0.5,
            "score": self.score,
            "details": [],
            "floor_applicable": False,
        }


def errors(package: dict[str, Any]) -> list[str]:
    return [e.message for e in SCHEMA.iter_errors(package)]


def exact(session: Session, story: m.Story, relevance: str | None = "R1") -> NewsMatch:
    return NewsMatch(story.id, load_match_types(session)["cve_exact"], relevance)


def test_a_finding_package_follows_the_schema(session: Session) -> None:
    story = add_story(session, cves={CVE: "active"}, event_types=["active_exploitation"])
    (group,) = load_active_groups(session)
    package = build_finding_package(session, group, [exact(session, story)], StubScorer())
    assert errors(package) == []
    assert package["type"] == "finding"
    assert package["group"]["cve"] == CVE
    assert [ci["ci_id"] for ci in package["group"]["cis"]] == ["CI-1", "CI-2"]
    assert package["base"]["relevance"] == ["R1"]
    assert package["kev"]["listed"] is True
    assert package["epss"]["percentile"] == pytest.approx(0.99)
    assert package["news"][0]["match"] == {"type": "exact_cve", "strength": 1.0}
    assert package["news"][0]["source_level"] == "N3"
    assert package["news"][0]["story_id"] == str(story.id)


def test_the_fingerprint_ignores_weights_and_scores_but_not_the_group_the_news_or_the_profile(session: Session) -> None:
    story = add_story(session, cves={CVE: "active"})
    (group,) = load_active_groups(session)
    first = build_finding_package(session, group, [exact(session, story)], StubScorer(75))
    again = build_finding_package(session, group, [exact(session, story)], StubScorer(12))
    assert first["base"]["score"] != again["base"]["score"]
    assert first["fingerprint"] == again["fingerprint"]
    # another linked story changes it
    other = add_story(session, cves={CVE: "limited"})
    more = build_finding_package(session, group, [exact(session, story), exact(session, other)], StubScorer())
    assert more["fingerprint"] != first["fingerprint"]
    # a CI attribute from iTop changes it
    asset = session.scalars(select(m.Asset).order_by(m.Asset.itop_ci_id)).first()
    assert asset is not None
    asset.criticality = "low"
    session.flush()
    edited = build_finding_package(session, group, [exact(session, story)], StubScorer())
    assert edited["fingerprint"] != first["fingerprint"]
    asset.criticality = "high"
    # the profile version changes it
    session.add(m.CompanyProfile(id=1, company_name="Acme", output_language="es", updated_at=NOW))
    session.flush()
    profiled = build_finding_package(session, group, [exact(session, story)], StubScorer())
    assert profiled["versions"]["profile"] == NOW.isoformat()
    assert profiled["fingerprint"] != edited["fingerprint"]


def test_only_the_five_strongest_and_most_recent_news_go_in(session: Session) -> None:
    (group,) = load_active_groups(session)
    types = load_match_types(session)
    matches = []
    for hours in (30, 20, 10, 5, 3, 1):
        story = add_story(session, cves={CVE: "active"}, hours_ago=hours, title=f"{hours}h")
        matches.append(NewsMatch(story.id, types["cve_exact"], "R1"))
    weak = add_story(session, products=[("openssl", "openssl", None)], hours_ago=0.1, title="weak but newest")
    matches.append(NewsMatch(weak.id, types["product"], "R2"))
    package = build_finding_package(session, group, matches, StubScorer())
    titles = [n["title"] for n in package["news"]]
    assert titles == ["1h", "3h", "5h", "10h", "20h"]  # strength first, then the most recent; the rest are left out
    assert [n["element_id"] for n in package["news"]] == ["N1", "N2", "N3", "N4", "N5"]
    cut = [m_.story_id for m_ in matches if str(m_.story_id) not in {n["story_id"] for n in package["news"]}]
    expected = session.scalars(select(m.RawArticle.canonical_url).where(m.RawArticle.story_id.in_(cut))).all()
    assert len(cut) == 2
    assert sorted(package["additional_urls"]) == sorted(expected)
    assert errors(package) == []


def test_an_alert_package_has_no_group(session: Session) -> None:
    story = add_story(session, products=[("openssl", "openssl", "3.0.7")])
    session.add(m.ProfileSector(sector_code="healthcare", is_primary=True))
    session.flush()
    # an alert only exists when no group matched: make the product fall outside the CVE range
    session.add(
        m.CveAffectedRange(
            id=uuid.uuid4(),
            cve_id=CVE,
            source="nvd_cpe",
            vendor="openssl",
            product="openssl",
            version_end="3.0.1",
            end_inclusive=False,
        )
    )
    session.flush()
    outcome = correlate_story(session, story.id, NOW)
    assert outcome is not None
    assert outcome.alert_id is not None
    package = build_alert_package(session, outcome.alert_id, StubScorer())
    assert errors(package) == []
    assert (package["type"], package["group"], package["cve_data"]) == ("alert", None, None)
    assert package["base"]["relevance"] == ["R2"]
    assert package["news"][0]["match"] == {"type": "none", "strength": 0.0}
    assert "OpenSSL 3.0.7" in package["profile_summary"]["stack_summary"]
    assert package["profile_summary"]["sector"] == "Salud"


def test_a_dismissal_candidate_package(session: Session) -> None:
    story = add_story(session, event_types=["actor_campaign"])
    package = build_dismissal_package(session, story.id, StubScorer())
    assert errors(package) == []
    assert package["type"] == "dismissal_candidate"
    assert package["base"]["relevance"] == []


def test_missing_subjects_are_reported(session: Session) -> None:
    with pytest.raises(LookupError):
        build_alert_package(session, uuid.uuid4(), StubScorer())
    with pytest.raises(LookupError):
        build_dismissal_package(session, uuid.uuid4(), StubScorer())


def test_a_package_is_stored_once_per_fingerprint(session: Session) -> None:
    story = add_story(session, cves={CVE: "active"})
    (group,) = load_active_groups(session)
    package = build_finding_package(session, group, [exact(session, story)], StubScorer())
    first = store_package(session, package, NOW)
    same = store_package(session, build_finding_package(session, group, [exact(session, story)], StubScorer(3)), NOW)
    assert same.id == first.id
    assert (first.kind, first.finding_group_id, first.fingerprint) == (
        "finding",
        demo_group(session),
        package["fingerprint"],
    )
    other = add_story(session, cves={CVE: "mass"})
    changed = store_package(
        session,
        build_finding_package(session, group, [exact(session, story), exact(session, other)], StubScorer()),
        NOW + timedelta(hours=1),
    )
    assert changed.id != first.id
    dismissal = store_package(session, build_dismissal_package(session, other.id, StubScorer()), NOW)
    assert (dismissal.kind, dismissal.story_id) == ("dismissal", other.id)
    assert session.scalar(select(func.count()).select_from(m.ReviewPackage)) == 3


def test_the_group_carries_the_cna_pair_outside_the_fingerprint(session: Session) -> None:
    """F15.9 (D-103, #206): the CNA's own names reach the judge's package, so JUE-MIT-10 checks the ranges the CNA
    publishes under them; adding them does not change the fingerprint (no group is re-reviewed for it)."""
    story = add_story(session, cves={CVE: "active"})
    (group,) = load_active_groups(session)
    before = build_finding_package(session, group, [exact(session, story)], StubScorer())
    assert before["group"]["cna"] is None
    mapping = session.scalars(select(m.CpeMapping)).one()
    mapping.cna_vendor, mapping.cna_product = "OpenSSL", "OpenSSL"
    session.flush()
    (named,) = load_active_groups(session)
    after = build_finding_package(session, named, [exact(session, story)], StubScorer())
    assert errors(after) == []
    assert after["group"]["cna"] == {"vendor": "OpenSSL", "product": "OpenSSL"}
    assert after["group"]["cpe"] == before["group"]["cpe"]
    assert after["fingerprint"] == before["fingerprint"]
