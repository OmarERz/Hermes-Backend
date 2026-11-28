"""STIX builders: deterministic ids, escaped patterns, validator-clean objects and the compact view."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
import stix2

from core.stix import builders as b
from core.stix.compact import compact_view
from core.stix.export import validate_bundle
from core.stix.ids import stix_id

T0 = datetime(2026, 11, 1, 10, 0, tzinfo=UTC)
MARK = stix2.TLP_AMBER.id


def test_ids_are_deterministic_and_typed() -> None:
    assert stix_id("vulnerability", "CVE-2026-0001") == stix_id("vulnerability", "CVE-2026-0001")
    assert stix_id("vulnerability", "CVE-2026-0001") != stix_id("vulnerability", "CVE-2026-0002")
    assert stix_id("indicator", "a", "b") != stix_id("indicator", "ab")
    assert stix_id("malware", "x").startswith("malware--")


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        ("url", "http://evil.example/a?b='c'", "[url:value = 'http://evil.example/a?b=\\'c\\'']"),
        ("domain", "Evil.Example", "[domain-name:value = 'evil.example']"),
        ("ip", "203.0.113.7", "[ipv4-addr:value = '203.0.113.7']"),
        ("ip", "2001:db8::1", "[ipv6-addr:value = '2001:db8::1']"),
        ("md5", "D41D8CD98F00B204E9800998ECF8427E", "[file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']"),
        ("sha256", "a" * 64, "[file:hashes.'SHA-256' = '" + "a" * 64 + "']"),
    ],
)
def test_patterns(kind: str, value: str, expected: str) -> None:
    assert b.indicator_pattern(kind, value) == expected


@pytest.mark.parametrize(
    ("kind", "value"),
    [("ip", "999.1.1.1"), ("md5", "xyz"), ("sha256", "a" * 63), ("url", "  "), ("url", "a\nb"), ("other", "x")],
)
def test_invalid_indicators_are_dropped(kind: str, value: str) -> None:
    assert b.indicator_pattern(kind, value) is None
    assert b.indicator(b.IndicatorRecord(kind, value, T0, T0), MARK) is None


def test_the_cpe_is_escaped() -> None:
    assert b.cpe_name("f5", "nginx", "1.24.0") == "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"
    assert b.cpe_name("vendor:inc", "wid+get", None) == "cpe:2.3:a:vendor\\:inc:wid\\+get:*:*:*:*:*:*:*:*"


def test_the_cpe_keeps_the_part_of_the_mapping() -> None:
    """D-107 (F20 dry run, P2-1): an operating system is exported with part `o`, never the old fixed `a`."""
    assert b.cpe_name("linux", "linux_kernel", "6.1.0", "o") == "cpe:2.3:o:linux:linux_kernel:6.1.0:*:*:*:*:*:*:*"
    assert b.cpe_name("cisco", "asa_5505", None, "h") == "cpe:2.3:h:cisco:asa_5505:*:*:*:*:*:*:*:*"
    assert b.cpe_name("f5", "nginx", None, None) == "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
    kernel = b.software(b.SoftwareRecord("Linux Kernel", "linux", "6.1.0", "linux", "linux_kernel", "o"), MARK)
    assert kernel.cpe == "cpe:2.3:o:linux:linux_kernel:6.1.0:*:*:*:*:*:*:*"


def sample_bundle() -> stix2.Bundle:
    vuln = b.vulnerability(
        b.VulnerabilityRecord(
            "CVE-2026-0001",
            T0,
            T0 + timedelta(days=1),
            "Overflow",
            base_score=74,
            judge_adjustment=12,
            final_score=86,
            reasons=("mass_exploitation",),
            ticket_status=("open",),
            classification="classified",
            affected_assets=2,
        ),
        MARK,
    )
    soft = b.software(b.SoftwareRecord("nginx", "F5", "1.24.0", "f5", "nginx"), MARK)
    ind = b.indicator(b.IndicatorRecord("domain", "evil.example", T0, T0 + timedelta(days=2), "Mirai"), MARK)
    assert ind is not None
    mal = b.malware("Mirai", T0, MARK)
    actor = b.intrusion_set(b.ActorRecord("APT-X", ("APT-X", "Group X")), T0, MARK)
    sector = b.sector_identity("finance", "Finanzas", T0, MARK)
    news = b.report(b.ReportRecord("https://news.example/a", "Explotan CVE-2026-0001", T0), [vuln.id, mal.id], MARK)
    rels = [
        b.relationship("has", soft.id, vuln.id, T0, MARK),
        b.relationship("indicates", ind.id, mal.id, T0, MARK),
        b.relationship("exploits", mal.id, vuln.id, T0, MARK),
        b.relationship("targets", actor.id, vuln.id, T0, MARK),
        b.relationship("targets", actor.id, sector.id, T0, MARK),
    ]
    objects = [stix2.TLP_AMBER, vuln, soft, ind, mal, actor, sector, news, *rels]
    return stix2.Bundle(id=stix_id("bundle", "sample"), objects=objects, allow_custom=True)


def test_objects_are_valid_stix_and_deterministic() -> None:
    first, second = sample_bundle().serialize(sort_keys=True), sample_bundle().serialize(sort_keys=True)
    assert first == second
    outcome = validate_bundle(first)
    assert outcome.errors == []
    data = json.loads(first)
    vuln = next(o for o in data["objects"] if o["type"] == "vulnerability")
    assert vuln["x_final_score"] == 86 and vuln["x_reasons"] == ["mass_exploitation"] and vuln["x_affected_assets"] == 2
    assert {r["source_name"] for r in vuln["external_references"]} == {"cve", "nvd"}
    actor = next(o for o in data["objects"] if o["type"] == "intrusion-set")
    assert actor["aliases"] == ["Group X"]  # the name itself is not repeated as an alias
    software = next(o for o in data["objects"] if o["type"] == "software")
    assert software["cpe"].startswith("cpe:2.3:a:f5:nginx:1.24.0")
    assert stix2.parse(first, allow_custom=True).type == "bundle"


def test_the_compact_view_keeps_ids_and_drops_the_rest() -> None:
    data = json.loads(sample_bundle().serialize(sort_keys=True))
    view = compact_view(data)
    assert all(item["id"] in {o["id"] for o in data["objects"]} for item in view)
    assert not any(item["type"] == "marking-definition" for item in view)
    vuln = next(i for i in view if i["type"] == "vulnerability")
    assert vuln["name"] == "CVE-2026-0001" and vuln["x_final_score"] == 86
    assert "description" not in vuln and "external_references" not in vuln
    rel = next(i for i in view if i["type"] == "relationship" and i["relationship_type"] == "exploits")
    assert set(rel) == {"type", "id", "relationship_type", "source_ref", "target_ref"}
    report = next(i for i in view if i["type"] == "report")
    assert len(report["object_refs"]) == 2
    assert len(json.dumps(view)) < len(json.dumps(data))
    assert compact_view({}) == []
