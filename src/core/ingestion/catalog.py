"""Default source list (docs/03 §3, D-009, D-041) and how it reaches the `source` table."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id
from core.ingestion.connectors import FieldMapping


@dataclass(frozen=True)
class SourceDefinition:
    code: str
    name: str
    kind: str
    url: str
    trust_tier: str
    is_structural: bool
    mapping: FieldMapping | None = None
    summary_only: bool = False  # the feed carries only a summary: always download the article (ING-04)


# FUE-01 to FUE-05 are structural (no switch off, D-041); FUE-06 to FUE-11 are optional.
# The endpoints of ransomware.live, URLhaus, ThreatFox and EPSS are marked for verification in docs/03;
# F2 only reads the RSS news feeds, the data feeds are read by their own phases.
DEFAULT_SOURCES: tuple[SourceDefinition, ...] = (
    SourceDefinition("nvd", "NVD", "api", "https://services.nvd.nist.gov/rest/json/cves/2.0", "N1", True),
    SourceDefinition("cve_org", "CVE.org", "api", "https://github.com/CVEProject/cvelistV5", "N1", True),
    SourceDefinition(
        "kev",
        "CISA KEV",
        "json",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "N1",
        True,
    ),
    SourceDefinition(
        "epss", "EPSS", "csv", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz", "N1", True
    ),
    SourceDefinition("osv", "OSV", "api", "https://api.osv.dev/v1/query", "N1", True),
    SourceDefinition(
        "thn", "The Hacker News", "rss", "https://feeds.feedburner.com/TheHackersNews", "N3", False, summary_only=True
    ),
    SourceDefinition("tenable", "Tenable Blog", "rss", "https://www.tenable.com/blog/feed", "N2", False),
    SourceDefinition(
        "bleepingcomputer", "BleepingComputer", "rss", "https://www.bleepingcomputer.com/feed/", "N3", False
    ),
    SourceDefinition(
        "ransomware_live", "ransomware.live", "api", "https://api.ransomware.live/v2/recentvictims", "N3", False
    ),
    SourceDefinition("urlhaus", "URLhaus", "json", "https://urlhaus.abuse.ch/downloads/json_recent/", "N3", False),
    SourceDefinition("threatfox", "ThreatFox", "json", "https://threatfox.abuse.ch/export/json/recent/", "N3", False),
)


def sync_default_sources(session: Session, now: datetime) -> list[str]:
    """Insert the default sources that are missing; rows already there (and any admin edit) stay untouched."""
    existing = set(session.scalars(select(m.Source.code)))
    added: list[str] = []
    for definition in DEFAULT_SOURCES:
        if definition.code in existing:
            continue
        session.add(
            m.Source(
                id=new_id(),
                code=definition.code,
                name=definition.name,
                kind=definition.kind,
                url=definition.url,
                trust_tier=definition.trust_tier,
                is_structural=definition.is_structural,
                is_custom=False,
                enabled=True,
                created_at=now,
            )
        )
        added.append(definition.code)
    session.flush()
    return added


def mapping_for(code: str) -> FieldMapping | None:
    """Field mapping of a default JSON or CSV source; custom feeds use the default mapping."""
    for definition in DEFAULT_SOURCES:
        if definition.code == code:
            return definition.mapping
    return None


def is_summary_only(code: str) -> bool:
    return any(definition.summary_only for definition in DEFAULT_SOURCES if definition.code == code)
