"""CVE.org (cvelistV5, CVE JSON 5) reader and loader: the CNA's own `affected[]` data (ESC-09, certainty 0.9).

Records are fetched one CVE at a time from the repository's raw files (`cves/<year>/<n>xxx/CVE-<year>-<n>.json`)
or read from a local clone. ⚠️ The path layout and field names follow the CVE JSON 5 schema and the repository's
public structure; they were not re-read from the official page in this session. A CVE that CVE.org does not
have (404) is a normal "not found", not an error. Rejected CVEs are skipped.

How `affected[].versions[]` becomes ranges (F15.9, read from the records of the inventory's CNAs on 27 Nov 2026):
  - `defaultStatus: unaffected` (or none): each `affected` entry is a range (`version` up to `lessThan` or
    `lessThanOrEqual`, or `changes`); GitHub's CNA writes the range in `version` itself (`>= 16.0.0, < 16.4.5`);
  - `defaultStatus: affected`: everything is affected except the `unaffected` entries, so the ranges are the gaps
    between them. The kernel CNA lists one fixed line per stable branch (`6.1.192 <= v <= 6.1.*`), which leaves
    `(6.1.*, 6.6.162)` and so on; a wildcard bound stands for its whole line (`core.scan.versions.bound_order`).
    Exclusions that overlap or touch are one (their union: the kernel lists fixed lines inside `[0, introduction)`),
    and a bare unaffected version is only that version;
  - a lone `*` bound is an open side, a wildcard line in `lessThan` is the whole line too; `git` versions cannot be
    compared with a release and are skipped;
  - nothing is guessed (ESC-13): an exclusion that cannot be read gives no range for that entry, and a version text
    the comparator cannot read is stored as it is, so the scan counts it as a comparison error.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from sqlalchemy.orm import Session

from core.scan.versions import Version, bound_order, compare_versions, line_edge_order, parse_version, wildcard_line
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
NO_VENDOR: Final = frozenset(
    {"", "*"}
)  # a vendor `n/a` is kept: the PostgreSQL CNA writes it and the mapping matches it
START_OF_TIME: Final = frozenset({"0", "0.0", "0.0.0", "unspecified", "*", ""})
OPEN_END: Final = "*"  # `lessThanOrEqual: "*"`: no upper bound
NO_VERSION: Final = frozenset({"", "unspecified", "unknown", "n/a", "*"})  # a bare item with these states nothing
UNREADABLE: Final = "unreadable"  # the status of an exclusion that names no version
NOT_COMPARABLE: Final = frozenset({"git"})  # commit hashes cannot be compared with a release version
NOT_FOUND: Final = 404
# One constraint of GitHub's CNA range text (`>= 13.4.0`, `< 15.5.24`), comma-separated in `version`
_CONSTRAINT: Final = re.compile(r"\s*(>=|<=|>|<|=)\s*v?([0-9][0-9A-Za-z.\-+_~]*)\s*")
_OPERATORS: Final = ("<", ">", "=")

log = logging.getLogger(__name__)

Bound = tuple[str | None, bool | None]  # (version, inclusive); (None, None) is an open side
Segment = tuple[Bound, Bound, str]  # start, end and the status the CNA gives the versions between them


def raw_path(cve_id: str) -> str:
    """Relative path of a CVE's file in cvelistV5, e.g. `2024/1xxx/CVE-2024-1234.json`."""
    _, year, number = cve_id.split("-")
    return f"{year}/{int(number) // 1000}xxx/{cve_id}.json"


def _english(items: list[dict[str, Any]]) -> str | None:
    for item in items:
        if str(item.get("lang", "")).lower().startswith("en") and isinstance(item.get("value"), str):
            return str(item["value"])
    return None


def _ranges(affected: list[Any], cve_id: str = "") -> list[RangeRecord]:
    return _read_affected(affected, cve_id)[0]


def _read_affected(affected: list[Any], cve_id: str = "") -> tuple[list[RangeRecord], int]:
    """The ranges of `affected[]` and how many product entries give only git commits (they cannot be compared with
    an installed release: they are counted, never turned into a range)."""
    ranges: list[RangeRecord] = []
    git_only = 0
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        vendor, product = str(entry.get("vendor", "")).strip(), str(entry.get("product", "")).strip()
        if vendor in NO_VENDOR or product.lower() in UNKNOWN_NAMES:
            continue
        items = [v for v in entry.get("versions") or [] if isinstance(v, dict)]
        versions = [v for v in items if v.get("versionType") not in NOT_COMPARABLE]
        if items and not versions:
            git_only += 1
            continue
        found = _entry_ranges(vendor, product, versions, default_affected=entry.get("defaultStatus") == "affected")
        if found is None:
            log.warning("CVE.org %s: the versions of %s:%s cannot be read; no range", cve_id, vendor, product)
            found = []
        ranges.extend(found)
    return list(dict.fromkeys(ranges)), git_only


def _entry_ranges(
    vendor: str, product: str, versions: list[dict[str, Any]], *, default_affected: bool
) -> list[RangeRecord] | None:
    """The affected ranges of one `affected[]` entry; None when a version it needs cannot be read.

    Each `versions[]` item becomes segments with a status (`_segments`). With `defaultStatus: affected` the ranges are
    the gaps between the unaffected segments (`_gaps`); otherwise they are the affected segments. `unknown` segments
    state nothing either way, so the default applies to them."""
    segments: list[Segment] = []
    for item in versions:
        found = _segments(item)
        if found is None:
            return None
        segments.extend(found)
    if not default_affected:
        segments = [segment for segment in segments if segment[2] != UNREADABLE]
        return [
            RangeRecord(CNA_AFFECTED, vendor, product, *start, *end)
            for start, end, status in segments
            if status == "affected"
        ]
    gaps = _complement(segments)
    return None if gaps is None else [RangeRecord(CNA_AFFECTED, vendor, product, *start, *end) for start, end in gaps]


def _complement(segments: list[Segment]) -> list[tuple[Bound, Bound]] | None:
    """`defaultStatus: affected`: the versions no unaffected segment covers; None when an exclusion cannot be read."""
    unaffected = [(start, end) for start, end, status in segments if status == "unaffected"]
    if any(status == UNREADABLE for _, _, status in segments) or not all(_readable(*u) for u in unaffected):
        return None
    return _gaps(unaffected) if unaffected else [((None, None), (None, None))]


def _readable(start: Bound, end: Bound) -> bool:
    """Both bounds of an exclusion can be placed by the comparator (a complement is never computed blind)."""
    start_ok = start[0] is None or compare_versions(start[0], start[0]) is not None
    return start_ok and (end[0] is None or bound_order("0", end[0]) is not None)


def _segments(item: dict[str, Any]) -> list[Segment] | None:
    """The version ranges one `versions[]` item states, each with its status (CVE JSON 5): an exact version (also
    `0.0.0`), `version` up to `lessThan`/`lessThanOrEqual`, GitHub's constraint text, and `changes`, applied in version
    order, that flip the status along the range. [] when it states nothing usable; None when a `changes` version
    cannot be ordered."""
    status = str(item.get("status", ""))
    version = str(item.get("version", "")).strip()
    below, up_to = item.get("lessThan"), item.get("lessThanOrEqual")
    changes = [c for c in item.get("changes") or [] if isinstance(c, dict) and c.get("at")]
    if any(operator in version for operator in _OPERATORS):
        parsed = _constraints(version)
        # text that is not a constraint set is kept as it is: the scan counts it as a comparison error (ESC-13)
        return [((version, True), (version, True), status)] if parsed is None else [(*parsed, status)]
    if below is None and up_to is None and not changes:
        if version.lower() in NO_VERSION:
            # an exclusion that names no version cannot be placed: with `defaultStatus: affected` the entry gets no
            # range (nothing is guessed); an affected item that names none simply states nothing
            return [((None, None), (None, None), UNREADABLE)] if status == "unaffected" else []
        return [((version, True), (version, True), status)]
    start: Bound = (None, None) if version.lower() in START_OF_TIME else (version, True)
    end = _upper(below, up_to) if below is not None or up_to is not None else (None, None)
    ordered = _ordered_changes(changes)
    if ordered is None:
        return None
    segments: list[Segment] = []
    for at, new_status in (change for change in ordered if _within(change[0], start, end)):
        if new_status == status:
            continue  # no flip: the segment goes on
        if start[0] is not None and compare_versions(at, start[0]) == 0:
            status = new_status  # a change at an inclusive start applies from the start: no empty segment
            continue
        segments.append((start, (at, False), status))
        start, status = (at, True), new_status
    segments.append((start, end, status))
    return segments


def _within(at: str, start: Bound, end: Bound) -> bool:
    """A change applies inside its entry's own interval only (CVE JSON 5): after the start, before the end."""
    order = None if start[0] is None else compare_versions(at, start[0])
    after_start = start[0] is None or order is None or order > 0 or (order == 0 and bool(start[1]))
    if end[0] is None:
        return after_start
    position = bound_order(at, end[0])
    return after_start and position is not None and (position < 0 or (position == 0 and bool(end[1])))


def _ordered_changes(changes: list[dict[str, Any]]) -> list[tuple[str, str]] | None:
    """`changes` in version order (CVE JSON 5 applies them that way); None when a version cannot be ordered."""
    found = [(str(c["at"]).strip(), str(c.get("status", ""))) for c in changes]
    if any(parse_version(at) is None for at, _ in found):
        return None
    return sorted(found, key=lambda change: parse_version(change[0]) or Version((), 0, 0, 0))


def _upper(below: Any, up_to: Any) -> Bound:
    """The upper bound of `lessThan` or `lessThanOrEqual`: a lone `*` is an open end, and a wildcard line is the whole
    line either way (`lessThan: "2.*"` is beyond every 2.x, as CVE JSON 5 defines it)."""
    raw, inclusive = (str(below).strip(), False) if below is not None else (str(up_to).strip(), True)
    if raw == OPEN_END:
        return (None, None)
    return (raw, True) if wildcard_line(raw) is not None else (raw, inclusive)


def _gaps(intervals: list[tuple[Bound, Bound]]) -> list[tuple[Bound, Bound]] | None:
    """The versions no interval covers, as (start, end) pairs; None when two bounds cannot be ordered.

    Overlapping intervals are merged: the kernel CNA lists a fixed line inside the range before the introduction
    (`[0, 4.6)` and `[3.2.81, 3.2.*]`), and the unaffected versions are simply the union of what it says."""

    def start_key(interval: tuple[Bound, Bound]) -> tuple[int, Version | None]:
        start = interval[0][0]
        return (0, None) if start is None else (1, parse_version(start))  # every start was checked readable

    ordered = sorted(intervals, key=start_key)
    gaps: list[tuple[Bound, Bound]] = []
    (first_start, first_inclusive), end = ordered[0]
    if first_start is not None:
        gaps.append(((None, None), (first_start, not first_inclusive)))
    for (start, start_inclusive), next_end in ordered[1:]:
        if end[0] is None:
            break  # covered to the end: nothing after can be affected
        order = -1 if start is None else bound_order(start, end[0])
        if order is None:
            return None
        if order < 0 or (order == 0 and (end[1] or start_inclusive)):
            merged = _later_end(end, next_end)  # overlapping or touching: one exclusion
            if merged is None:
                return None
            end = merged
            continue
        if order > 0:
            gaps.append(((end[0], not end[1]), (start, not start_inclusive)))
        else:
            gaps.append(((start, True), (start, True)))  # both exclusive at the same version: only it is left
        end = next_end
    if end[0] is not None:
        gaps.append(((end[0], not end[1]), (None, None)))
    return gaps


def _later_end(left: Bound, right: Bound) -> Bound | None:
    """The later of two upper bounds (an open end is the latest); None when they cannot be ordered. A wildcard line
    included (`<= 6.1.*`) ends after every version of the line; excluded, before its first."""
    if left[0] is None or right[0] is None:
        return (None, None)
    order = _end_order(left, right)
    if order is None:
        return None
    return left if order >= 0 else right


def _end_order(left: Bound, right: Bound) -> int | None:
    """-1, 0 or 1 comparing two upper bounds that are not open."""
    left_text, right_text = str(left[0]), str(right[0])
    left_line, right_line = wildcard_line(left_text), wildcard_line(right_text)
    if left_line is None and right_line is None:
        order = compare_versions(left_text, right_text)
        return None if order is None else order or (bool(left[1]) - bool(right[1]))
    if left_line is not None and right_line is not None:
        return line_edge_order(left_line, bool(left[1]), right_line, bool(right[1]))  # an inclusive end is after
    if left_line is None:
        flipped = _end_order(right, left)
        return None if flipped is None else -flipped
    position = bound_order(right_text, left_text)  # the plain end against the line
    if position is None:
        return None
    if left[1]:  # `<= X.Y.*`: after every version of the line
        return 1 if position <= 0 else -1
    return 1 if position < 0 else -1  # `< X.Y.*`: before the first version of the line


def _constraints(text: str) -> tuple[Bound, Bound] | None:
    """GitHub's `>= 13.4.0, < 15.5.24` (every constraint holds); None when the text is not that shape."""
    start: Bound = (None, None)
    end: Bound = (None, None)
    for part in text.split(","):
        match = _CONSTRAINT.fullmatch(part)
        if match is None:
            return None
        operator, version = match.groups()
        if operator == "=":
            if start[0] is not None or end[0] is not None:
                return None
            start = end = (version, True)
        elif operator.startswith(">"):
            if start[0] is not None:
                return None
            start = (version, operator == ">=")
        else:
            if end[0] is not None:
                return None
            end = (version, operator == "<=")
    return (start, end) if start[0] is not None or end[0] is not None else None


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
    record.ranges, record.uncomparable = _read_affected(cna.get("affected") or [], cve_id)
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
