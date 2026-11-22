"""CVE.org (cvelistV5, CVE JSON 5) reader and loader: the CNA's own `affected[]` data (ESC-09, certainty 0.9).

Records are fetched one CVE at a time from the repository's raw files (`cves/<year>/<n>xxx/CVE-<year>-<n>.json`)
or read from a local clone. ⚠️ The path layout and field names follow the CVE JSON 5 schema and the repository's
public structure; they were not re-read from the official page in this session. A CVE that CVE.org does not
have (404) is a normal "not found", not an error. Rejected CVEs are skipped.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from sqlalchemy.orm import Session

from core.vulndata.http import JsonSource, SourceRefusedError
from core.vulndata.records import (
    CNA_AFFECTED,
    CVE_ID,
    CWE_ID,
    CveRecord,
    RangeRecord,
    ReferenceRecord,
    WorkaroundRecord,
    parse_score,
    parse_timestamp,
)
from core.vulndata.store import store_cve

RAW_URL: Final = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
CVSS_KEYS: Final = (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"))
TAGS: Final = {"patch": "Patch", "vendor-advisory": "Vendor Advisory", "exploit": "Exploit"}
UNKNOWN_NAMES: Final = frozenset({"", "n/a", "unspecified", "unknown", "*"})
START_OF_TIME: Final = frozenset({"0", "0.0", "0.0.0", "unspecified", "*", ""})
NOT_COMPARABLE: Final = frozenset({"git"})  # commit hashes cannot be compared with a release version
NOT_FOUND: Final = 404


def raw_path(cve_id: str) -> str:
    """Relative path of a CVE's file in cvelistV5, e.g. `2024/1xxx/CVE-2024-1234.json`."""
    _, year, number = cve_id.split("-")
    return f"{year}/{int(number) // 1000}xxx/{cve_id}.json"


def _english(items: list[dict[str, Any]]) -> str | None:
    for item in items:
        if str(item.get("lang", "")).lower().startswith("en") and isinstance(item.get("value"), str):
            return str(item["value"])
    return None


def _ranges(affected: list[dict[str, Any]]) -> list[RangeRecord]:
    ranges: list[RangeRecord] = []
    for entry in affected:
        vendor, product = str(entry.get("vendor", "")).strip(), str(entry.get("product", "")).strip()
        if vendor.lower() in UNKNOWN_NAMES or product.lower() in UNKNOWN_NAMES:
            continue
        versions = [v for v in entry.get("versions") or [] if v.get("versionType") not in NOT_COMPARABLE]
        found = [
            r for item in versions if item.get("status") == "affected" for r in _version_ranges(vendor, product, item)
        ]
        if not found and entry.get("defaultStatus") == "affected":
            found = _default_affected(vendor, product, versions)
        ranges.extend(found)
    return list(dict.fromkeys(ranges))


def _default_affected(vendor: str, product: str, versions: list[dict[str, Any]]) -> list[RangeRecord]:
    """`defaultStatus: affected`: everything is affected except the listed unaffected versions.

    A single unaffected version is read as "fixed from there on"; with several, the exclusions cannot be
    expressed as one range and the product is left without a range rather than invented (pendientes-f12).
    """
    unaffected = [v for v in versions if v.get("status") == "unaffected" and str(v.get("version", "")).strip()]
    if not unaffected:
        return [RangeRecord(CNA_AFFECTED, vendor, product)]
    if len(unaffected) == 1 and unaffected[0].get("lessThan") is None and unaffected[0].get("lessThanOrEqual") is None:
        return [RangeRecord(CNA_AFFECTED, vendor, product, None, None, str(unaffected[0]["version"]).strip(), False)]
    return []


def _version_ranges(vendor: str, product: str, item: dict[str, Any]) -> list[RangeRecord]:
    version = str(item.get("version", "")).strip()
    start: str | None = None if version.lower() in START_OF_TIME else version
    below, up_to = item.get("lessThan"), item.get("lessThanOrEqual")
    changes = [c for c in item.get("changes") or [] if isinstance(c, dict) and c.get("at")]
    if not changes:
        if below is None and up_to is None:
            if start is None:
                return []  # "unspecified" without bounds says nothing usable
            return [RangeRecord(CNA_AFFECTED, vendor, product, start, True, start, True)]
        end, end_inclusive = (str(below), False) if below is not None else (str(up_to), True)
        return [RangeRecord(CNA_AFFECTED, vendor, product, start, None if start is None else True, end, end_inclusive)]
    # `changes` flip the status at given versions: affected from the entry's version until the first flip, and so on
    ranges: list[RangeRecord] = []
    affected = True
    for change in changes:
        at, status = str(change["at"]), change.get("status")
        if affected and status in {"unaffected", "unknown"}:
            ranges.append(RangeRecord(CNA_AFFECTED, vendor, product, start, None if start is None else True, at, False))
            affected = False
        elif not affected and status == "affected":
            start, affected = at, True
    if affected:
        tail_end: str | None = str(below) if below is not None else (str(up_to) if up_to is not None else None)
        tail_inclusive = None if tail_end is None else below is None
        ranges.append(
            RangeRecord(CNA_AFFECTED, vendor, product, start, None if start is None else True, tail_end, tail_inclusive)
        )
    return ranges


def parse_cve5(document: dict[str, Any]) -> CveRecord | None:
    """A CVE JSON 5 document; None when it is rejected or has no valid id."""
    meta = document.get("cveMetadata") or {}
    cve_id = meta.get("cveId")
    if not isinstance(cve_id, str) or not CVE_ID.match(cve_id) or meta.get("state") != "PUBLISHED":
        return None
    cna = (document.get("containers") or {}).get("cna") or {}
    record = CveRecord(
        cve_id=cve_id,
        origin="cna",
        description=_english(cna.get("descriptions") or []),
        published_at=parse_timestamp(meta.get("datePublished")),
        last_modified_at=parse_timestamp(meta.get("dateUpdated")),
    )
    for key, version in CVSS_KEYS:
        data = next((m[key] for m in cna.get("metrics") or [] if isinstance(m.get(key), dict)), None)
        if data and data.get("vectorString") and (score := parse_score(data.get("baseScore"))) is not None:
            record.cvss_version, record.cvss_vector, record.cvss_score = version, str(data["vectorString"]), score
            record.cvss_source = "cna"
            break
    for problem in cna.get("problemTypes") or []:
        for description in problem.get("descriptions") or []:
            cwe = description.get("cweId")
            if isinstance(cwe, str) and CWE_ID.match(cwe):
                record.cwes.append(cwe)
    for ref in cna.get("references") or []:
        if isinstance(ref.get("url"), str):
            tags = tuple(dict.fromkeys(TAGS[t] for t in ref.get("tags") or [] if t in TAGS))
            record.references.append(ReferenceRecord(ref["url"], tags))
    record.ranges = _ranges(cna.get("affected") or [])
    for key in ("workarounds", "solutions"):  # both are mitigation text the CNA publishes (ESC-14)
        for entry in cna.get(key) or []:
            if text := _english([entry]):
                record.workarounds.append(WorkaroundRecord(text, "cna"))
    return record


@dataclass
class CveOrgClient:
    source: JsonSource
    base_url: str = RAW_URL

    def fetch(self, cve_id: str) -> dict[str, Any] | None:
        """The CVE's document, or None when CVE.org has no such file."""
        if not CVE_ID.match(cve_id):
            raise ValueError("not a CVE id")
        try:
            body = self.source.get(f"{self.base_url}/{raw_path(cve_id)}")
        except SourceRefusedError as refused:
            if refused.status == NOT_FOUND:
                return None
            raise
        return body if isinstance(body, dict) else None


@dataclass
class LoadResult:
    stored: int = 0
    missing: int = 0
    skipped: int = 0


def load_cve_org(
    session: Session, client: CveOrgClient, cve_ids: Iterable[str], *, now: datetime | None = None
) -> LoadResult:
    """Fetch and store the given CVEs. A CVE has to exist in `cve` only through this call, so it is created."""
    result = LoadResult()
    for cve_id in cve_ids:
        document = client.fetch(cve_id)
        if document is None:
            result.missing += 1
            continue
        record = parse_cve5(document)
        if record is None or record.cve_id != cve_id:
            result.skipped += 1
            continue
        store_cve(session, record, now=now)
        result.stored += 1
    return result


def clone_files(root: Path) -> Iterator[Path]:
    """Every CVE file of a local clone of cvelistV5 (`git pull` keeps it current, FUE-02)."""
    yield from sorted((root / "cves").glob("*/*/CVE-*.json"))


def load_cve_files(session: Session, paths: Iterable[Path], *, now: datetime | None = None) -> LoadResult:
    """Store CVE JSON 5 files from a local clone of cvelistV5."""
    result = LoadResult()
    for path in paths:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            result.skipped += 1
            continue
        record = parse_cve5(document) if isinstance(document, dict) else None
        if record is None:
            result.skipped += 1
            continue
        store_cve(session, record, now=now)
        result.stored += 1
    return result
