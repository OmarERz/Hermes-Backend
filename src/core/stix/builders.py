"""Builders of STIX 2.1 objects from plain records (STX-02). Pure: no database, no clock, no randomness.

Every identifier comes from `ids.stix_id` and every timestamp from the record, so two runs over the same data give
the same objects. Names of company assets never reach these builders: only the product, the indicators and
the news that the sharing scope allows (docs/plans/f7.md).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

import stix2

from core.stix.ids import stix_id

HEX: Final = {"sha256": (re.compile(r"^[0-9a-fA-F]{64}$"), "SHA-256"), "md5": (re.compile(r"^[0-9a-fA-F]{32}$"), "MD5")}
FIRST_PRINTABLE: Final = 32
IPV4: Final = 4
EXTERNAL_NVD: Final = "https://nvd.nist.gov/vuln/detail/"


@dataclass(frozen=True)
class VulnerabilityRecord:
    cve_id: str
    created: datetime
    modified: datetime
    description: str | None = None
    base_score: int | None = None
    judge_adjustment: int | None = None
    final_score: int | None = None
    reasons: tuple[str, ...] = ()
    ticket_status: tuple[str, ...] = ()
    classification: str | None = None
    affected_assets: int = 0  # a count: asset names, addresses and owners never leave the instance


@dataclass(frozen=True)
class SoftwareRecord:
    name: str
    vendor: str | None = None
    version: str | None = None
    cpe_vendor: str | None = None
    cpe_product: str | None = None


@dataclass(frozen=True)
class IndicatorRecord:
    ioc_type: str  # url | domain | ip | sha256 | md5
    value: str
    first_seen: datetime
    last_seen: datetime
    malware_family: str | None = None


@dataclass(frozen=True)
class ActorRecord:
    name: str
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReportRecord:
    url: str
    title: str
    published: datetime


def _quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _ip_pattern(text: str) -> str | None:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    kind = "ipv4-addr" if address.version == IPV4 else "ipv6-addr"
    return f"[{kind}:value = {_quote(str(address))}]"


def indicator_pattern(ioc_type: str, value: str) -> str | None:
    """The STIX pattern for an indicator of compromise, or None when the value is not valid for its type."""
    text = value.strip()
    if not text or any(ord(ch) < FIRST_PRINTABLE for ch in text):  # control characters never enter a pattern
        return None
    if ioc_type == "ip":
        return _ip_pattern(text)
    if ioc_type == "url":
        return f"[url:value = {_quote(text)}]"
    if ioc_type == "domain":
        return f"[domain-name:value = {_quote(text.lower())}]"
    if ioc_type in HEX and HEX[ioc_type][0].match(text):
        return f"[file:hashes.'{HEX[ioc_type][1]}' = {_quote(text.lower())}]"
    return None


def cpe_name(vendor: str, product: str, version: str | None) -> str:
    def escape(part: str) -> str:
        return re.sub(r"([^A-Za-z0-9_.\-])", r"\\\1", part)

    return f"cpe:2.3:a:{escape(vendor)}:{escape(product)}:{escape(version) if version else '*'}:*:*:*:*:*:*:*"


def marking_refs(marking_id: str | None) -> list[str] | None:
    return [marking_id] if marking_id else None


def vulnerability(rec: VulnerabilityRecord, marking_id: str | None) -> Any:
    custom: dict[str, Any] = {"x_affected_assets": rec.affected_assets}
    for key, value in (
        ("x_base_score", rec.base_score),
        ("x_judge_adjustment", rec.judge_adjustment),
        ("x_final_score", rec.final_score),
        ("x_classification", rec.classification),
    ):
        if value is not None:
            custom[key] = value
    if rec.reasons:
        custom["x_reasons"] = list(rec.reasons)
    if rec.ticket_status:
        custom["x_ticket_status"] = list(rec.ticket_status)
    return stix2.Vulnerability(
        id=stix_id("vulnerability", rec.cve_id),
        name=rec.cve_id,
        description=rec.description or None,
        created=rec.created,
        modified=rec.modified,
        external_references=[
            stix2.ExternalReference(source_name="cve", external_id=rec.cve_id),
            stix2.ExternalReference(source_name="nvd", url=EXTERNAL_NVD + rec.cve_id),
        ],
        object_marking_refs=marking_refs(marking_id),
        custom_properties=custom,
    )


def software(rec: SoftwareRecord, marking_id: str | None) -> Any:
    cpe = cpe_name(rec.cpe_vendor, rec.cpe_product, rec.version) if rec.cpe_vendor and rec.cpe_product else None
    return stix2.Software(
        name=rec.name,
        vendor=rec.vendor or None,
        version=rec.version or None,
        cpe=cpe,
        object_marking_refs=marking_refs(marking_id),
    )


def indicator(rec: IndicatorRecord, marking_id: str | None) -> Any | None:
    pattern = indicator_pattern(rec.ioc_type, rec.value)
    if pattern is None:
        return None
    return stix2.Indicator(
        id=stix_id(
            "indicator", rec.ioc_type, rec.value.strip().lower() if rec.ioc_type != "url" else rec.value.strip()
        ),
        name=f"{rec.ioc_type}: {rec.value.strip()[:100]}",
        pattern=pattern,
        pattern_type="stix",
        valid_from=rec.first_seen,
        created=rec.first_seen,
        modified=max(rec.first_seen, rec.last_seen),
        indicator_types=["malicious-activity"],
        object_marking_refs=marking_refs(marking_id),
    )


def malware(family: str, created: datetime, marking_id: str | None) -> Any:
    return stix2.Malware(
        id=stix_id("malware", family.strip().lower()),
        name=family.strip(),
        is_family=True,
        created=created,
        modified=created,
        object_marking_refs=marking_refs(marking_id),
    )


def intrusion_set(rec: ActorRecord, created: datetime, marking_id: str | None) -> Any:
    return stix2.IntrusionSet(
        id=stix_id("intrusion-set", rec.name.strip().lower()),
        name=rec.name.strip(),
        aliases=sorted({a.strip() for a in rec.aliases if a.strip() and a.strip() != rec.name.strip()}) or None,
        created=created,
        modified=created,
        object_marking_refs=marking_refs(marking_id),
    )


def sector_identity(code: str, name: str, created: datetime, marking_id: str | None) -> Any:
    return stix2.Identity(
        id=stix_id("identity", "sector", code),
        name=name,
        identity_class="class",
        sectors=[code],
        created=created,
        modified=created,
        object_marking_refs=marking_refs(marking_id),
    )


def report(rec: ReportRecord, object_refs: list[str], marking_id: str | None) -> Any:
    return stix2.Report(
        id=stix_id("report", rec.url),
        name=rec.title.strip()[:300] or rec.url,
        report_types=["threat-report"],
        published=rec.published,
        created=rec.published,
        modified=rec.published,
        object_refs=sorted(set(object_refs)),
        external_references=[stix2.ExternalReference(source_name="news", url=rec.url)],
        object_marking_refs=marking_refs(marking_id),
    )


def relationship(kind: str, source_id: str, target_id: str, created: datetime, marking_id: str | None) -> Any:
    return stix2.Relationship(
        id=stix_id("relationship", kind, source_id, target_id),
        relationship_type=kind,
        source_ref=source_id,
        target_ref=target_id,
        created=created,
        modified=created,
        object_marking_refs=marking_refs(marking_id),
    )
