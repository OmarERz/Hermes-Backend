"""Review package (schemas/review_package.schema.json): validation, element index and the judge's compact view.

The package is an internal contract built by correlation (F4.1). `from_content` takes a private JSON snapshot
(Decimal values become JSON numbers, later changes by the producer do not leak in), validates it, cleans its free
texts (SEG-01) and derives both the element index and the compact view from that one cleaned snapshot, so what the
judge reads is exactly what quotes are checked against. The judge sees the compact view as delimited data (SEG-02)
and reads full elements with `read_element`. Every element carries its source level (L6):

- the CVE element (NVD/CNA data plus KEV and EPSS) is N1, except what the CVE analyst wrote (docs/05): a CVSS
  score and vector it estimated (`cvss_source = inferred`) and its `conditions` and `components`, which are N4;
- a news element has the level of its source;
- a CI element is N1 for its structured iTop fields and N4 for its free-text description.

A quote takes the level of the part it comes from: N1 only if it lies entirely in the official part.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import date, datetime
from decimal import Decimal
from enum import StrEnum
from functools import cache
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator

from core.ingestion.cleaning import clean_html, clean_plain
from core.llm.tools import default_schemas_dir

PACKAGE_SCHEMA_FILE = "review_package.schema.json"
VIEW_OPEN = "<paquete>"
VIEW_CLOSE = "</paquete>"
MAX_VIEW_DESCRIPTION_CHARS = 600  # the compact view trims long texts; read_element returns them whole


class PackageError(ValueError):
    """The package does not satisfy its schema or its cross-field invariants. Carries paths, not values."""


class SourceLevel(StrEnum):
    """Source confidence levels of docs/09 §2 (L6). N1 is the most trusted."""

    N1 = "N1"
    N2 = "N2"
    N3 = "N3"
    N4 = "N4"

    @property
    def rank(self) -> int:
        return int(self.value[1])


class ElementKind(StrEnum):
    CVE = "cve"
    NEWS = "news"
    CI = "ci"


@dataclass(frozen=True)
class NewsInfo:
    story_id: str
    source: str
    published: date | None
    domains: frozenset[str]
    suspicious: bool


@dataclass(frozen=True)
class Element:
    """One citable element of the package."""

    element_id: str
    kind: ElementKind
    text: str
    source_level: SourceLevel
    official_text: str = ""  # CVE and CI: the N1 part (official data, structured iTop fields)
    free_text: str = ""  # CI only: the iTop description (N4)
    ci_id: str | None = None
    news: NewsInfo | None = None
    suspicious: bool = False  # SEG-03: flagged news, or injection markers found while cleaning (forces L10)

    def contains(self, quote: str) -> bool:
        """L5: the quote appears verbatim in the element once whitespace is normalized."""
        needle = normalize_text(quote)
        return bool(needle) and needle in normalize_text(self.text)

    def quote_level(self, quote: str) -> SourceLevel:
        """Level of the part the quote comes from: news keep their source level; for CVE and CI elements a quote
        outside the official part (iTop description, inferred CVSS) is N4."""
        if self.kind is ElementKind.NEWS:
            return self.source_level
        needle = normalize_text(quote)
        return SourceLevel.N1 if needle and needle in normalize_text(self.official_text) else SourceLevel.N4

    def quote_in_free_text(self, quote: str) -> bool:
        needle = normalize_text(quote)
        return bool(needle) and needle in normalize_text(self.free_text)


def normalize_text(text: str) -> str:
    """Collapsed whitespace only (VAL-03 'textual after normalizing spaces'); characters and case are preserved.
    Unicode normalization happens once, when the package is cleaned, so quotes match the text the judge saw."""
    return " ".join(text.split())


@cache
def _validator(schemas_dir: Path) -> Draft202012Validator:
    schema = json.loads((schemas_dir / PACKAGE_SCHEMA_FILE).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


@dataclass(frozen=True)
class GroupCi:
    element_id: str
    ci_id: str
    name: str
    exposed: bool
    base_score: int
    floor_applicable: bool


@dataclass(frozen=True)
class ReviewPackage:
    """A validated package plus its element index."""

    content: Mapping[str, Any]
    elements: Mapping[str, Element]

    @classmethod
    def from_content(cls, content: Mapping[str, Any], schemas_dir: Path | None = None) -> ReviewPackage:
        snapshot = _snapshot(content)
        validator = _validator(schemas_dir or default_schemas_dir())
        errors = sorted(validator.iter_errors(snapshot), key=lambda e: list(e.path))
        if errors:
            paths = [f"{'.'.join(str(p) for p in e.path) or '<root>'}: {e.validator}" for e in errors]
            raise PackageError("review package rejected: " + "; ".join(paths))
        flagged = _clean(snapshot)
        package = cls(content=_freeze(snapshot), elements=_index(snapshot, flagged))
        package._check_invariants()
        return package

    # --- accessors -------------------------------------------------------------------------------------------
    @property
    def package_id(self) -> str:
        return str(self.content["package_id"])

    @property
    def kind(self) -> str:
        return str(self.content["type"])

    @property
    def fingerprint(self) -> str:
        return str(self.content["fingerprint"])

    @property
    def group_cve(self) -> str | None:
        group = self.content["group"]
        return str(group["cve"]) if group else None

    @property
    def cis(self) -> tuple[GroupCi, ...]:
        group = self.content["group"]
        if not group:
            return ()
        return tuple(
            GroupCi(
                element_id=str(ci["element_id"]),
                ci_id=str(ci["ci_id"]),
                name=str(ci["name"]),
                exposed=bool(ci["exposed"]),
                base_score=int(ci["base"]["score"]),
                floor_applicable=bool(ci["base"]["floor_applicable"]),
            )
            for ci in group["cis"]
        )

    @property
    def ci_ids(self) -> frozenset[str]:
        return frozenset(ci.ci_id for ci in self.cis)

    @property
    def base_score(self) -> int:
        return int(self.content["base"]["score"])

    @property
    def kev(self) -> Mapping[str, Any]:
        kev: Mapping[str, Any] = self.content["kev"]
        return kev

    @property
    def cve_data(self) -> Mapping[str, Any] | None:
        data: Mapping[str, Any] | None = self.content["cve_data"]
        return data

    @property
    def is_critical(self) -> bool:
        """KEV, R1 or an exposed CI: uses the critical budget reserve (docs/09 §4)."""
        return bool(
            self.kev["listed"] or "R1" in self.content["base"]["relevance"] or any(ci.exposed for ci in self.cis)
        )

    @property
    def news_elements(self) -> tuple[Element, ...]:
        return tuple(e for e in self.elements.values() if e.kind is ElementKind.NEWS)

    def _check_invariants(self) -> None:
        if self.kind == "finding" and (self.content["group"] is None or self.content["cve_data"] is None):
            raise PackageError("review package rejected: a finding package needs group and cve_data")
        ci_ids = [ci.ci_id for ci in self.cis]
        if len(ci_ids) != len(set(ci_ids)):
            raise PackageError("review package rejected: group.cis has repeated ci_id")

    # --- the judge's view ------------------------------------------------------------------------------------
    def compact_view(self) -> str:
        """Delimited JSON data for the user message (SEG-02). Long texts are trimmed; `<` is escaped so the
        content cannot close the delimiter."""
        content = self.content
        flagged = frozenset(e.element_id for e in self.elements.values() if e.suspicious)
        view: dict[str, Any] = {
            "package_id": content["package_id"],
            "type": content["type"],
            "group": _group_view(content["group"], flagged),
            "cve": _cve_view(content["cve_data"], flagged),
            "kev": content["kev"],
            "epss": content["epss"],
            "base": {
                k: content["base"][k] for k in ("S", "P", "T", "A", "D", "score", "floor_applicable", "relevance")
            },
            "news": [
                {
                    "element_id": n["element_id"],
                    "title": n["title"],
                    "source": n["source"],
                    "source_level": n["source_level"],
                    "date": n["date"],
                    "summary": _trim(n["summary"]),
                    "event_types": n["event_types"],
                    "exploitation_level": n["exploitation_level"],
                    "match": n["match"],
                    "suspicious": n["suspicious"],
                }
                for n in content["news"]
            ],
            "tickets": content["tickets"],
        }
        body = json.dumps(_thaw(view), ensure_ascii=False, sort_keys=True).replace("<", "\\u003c")
        return f"{VIEW_OPEN}\n{body}\n{VIEW_CLOSE}"


def _trim(text: str | None) -> str | None:
    if text is None or len(text) <= MAX_VIEW_DESCRIPTION_CHARS:
        return text
    return text[:MAX_VIEW_DESCRIPTION_CHARS] + "…"


def _group_view(group: Mapping[str, Any] | None, flagged: frozenset[str]) -> dict[str, Any] | None:
    if group is None:
        return None
    return {
        "cve": group["cve"],
        "product": group["product"],
        "cpe": group["cpe"],
        "cis": [
            {
                "element_id": ci["element_id"],
                "ci_id": ci["ci_id"],
                "name": ci["name"],
                "service": ci["service"],
                "criticality": ci["criticality"],
                "exposed": ci["exposed"],
                "confidentiality": ci["confidentiality"],
                "personal_data": ci["personal_data"],
                "status": ci["status"],
                "description": _trim(ci["description"]),
                "base_score": ci["base"]["score"],
                "floor_applicable": ci["base"]["floor_applicable"],
                "suspicious": ci["element_id"] in flagged,
            }
            for ci in group["cis"]
        ],
    }


def _cve_view(cve: Mapping[str, Any] | None, flagged: frozenset[str]) -> dict[str, Any] | None:
    if cve is None:
        return None
    return {
        "element_id": cve["element_id"],
        "description": _trim(cve["description"]),
        "cvss": cve["cvss"],
        "vector": cve["vector"],
        "cvss_source": cve["cvss_source"],
        "fixed_version": cve["fixed_version"],
        "reference_tags": sorted({str(t) for ref in cve["references"] for t in _tags(ref)}),
        "suspicious": cve["element_id"] in flagged,
    }


def _tags(reference: Mapping[str, Any]) -> Sequence[Any]:
    tags = reference.get("tags", [])
    return tags if isinstance(tags, list | tuple) else []


def _freeze(node: Any) -> Any:
    """Read-only view of the snapshot: the index and the view can never drift apart through a caller."""
    if isinstance(node, dict):
        return MappingProxyType({key: _freeze(value) for key, value in node.items()})
    if isinstance(node, list):
        return tuple(_freeze(value) for value in node)
    return node


def _thaw(node: Any) -> Any:
    if isinstance(node, Mapping):
        return {key: _thaw(value) for key, value in node.items()}
    if isinstance(node, list | tuple):
        return [_thaw(value) for value in node]
    return node


# --- snapshot and cleaning ------------------------------------------------------------------------------------
def _json_number(value: Any) -> Any:
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("non-finite decimal")
        return int(value) if value == value.to_integral_value() else float(value)
    raise TypeError(f"not JSON serializable: {type(value).__name__}")


def _snapshot(content: Mapping[str, Any]) -> dict[str, Any]:
    """A private deep copy in plain JSON types (the engine builds packages with Decimal factors, EVA-10)."""
    try:
        snapshot: dict[str, Any] = json.loads(json.dumps(content, default=_json_number, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise PackageError(f"review package rejected: not JSON ({type(exc).__name__})") from None
    return snapshot


# Identifiers, codes, dates and URLs are kept byte for byte: they are matched against the inventory and the DB.
_VERBATIM_KEYS = frozenset(
    {
        "package_id", "fingerprint", "group_id", "element_id", "ci_id", "story_id", "itop_id", "cve", "cpe",
        "vector", "cvss_source", "cwe", "date", "urls", "url", "source_level", "type", "relevance",
        "confidentiality", "fixed_version", "affected_ranges",
    }
)  # fmt: skip


def _clean(content: dict[str, Any]) -> frozenset[str]:
    """SEG-01 on every free text, in place (the CI description as HTML). Returns the element IDs whose text
    carried injection markers; a flagged news item also gets `suspicious = true` in the snapshot (SEG-03)."""
    flagged: set[str] = set()
    cve = content["cve_data"]
    kev_dirty = _clean_tree(content["kev"])  # KEV text is part of the CVE element
    if cve is not None and (_clean_tree(cve) or kev_dirty):
        flagged.add(cve["element_id"])
    for news in content["news"]:
        if _clean_tree(news):
            flagged.add(news["element_id"])
            news["suspicious"] = True
    for ci in content["group"]["cis"] if content["group"] else []:
        description = ci.pop("description")
        dirty = _clean_tree(ci)
        if description is not None:
            cleaned = clean_html(description)
            description, dirty = cleaned.text, dirty or cleaned.is_suspicious
        ci["description"] = description
        if dirty:
            flagged.add(ci["element_id"])
    # context shown to the judge; IOC values and extra URLs stay verbatim (hashes would look like base64 blocks)
    for key in ("group", "tickets", "profile_summary", "base"):
        if content.get(key) is not None:
            _clean_tree(content[key], skip=("cis",))
    return frozenset(flagged)


def _clean_tree(node: Any, skip: tuple[str, ...] = ()) -> bool:
    """Clean every string under `node` except verbatim keys; True if any carried injection markers."""
    dirty = False
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _VERBATIM_KEYS or key in skip:
                continue
            if isinstance(value, str):
                cleaned = clean_plain(value)
                node[key], dirty = cleaned.text, dirty or cleaned.is_suspicious
            else:
                dirty = _clean_tree(value) or dirty
    elif isinstance(node, list):
        for index, value in enumerate(node):
            if isinstance(value, str):
                cleaned = clean_plain(value)
                node[index], dirty = cleaned.text, dirty or cleaned.is_suspicious
            else:
                dirty = _clean_tree(value) or dirty
    return dirty


# --- element index ---------------------------------------------------------------------------------------------
def _index(content: Mapping[str, Any], flagged: frozenset[str]) -> dict[str, Element]:
    elements: list[Element] = []
    if content["cve_data"] is not None:
        elements.append(_cve_element(content["cve_data"], content["kev"], content["epss"]))
    for news in content["news"]:
        elements.append(_news_element(news))
    if content["group"] is not None:
        elements.extend(_ci_element(ci) for ci in content["group"]["cis"])
    elements = [replace(e, suspicious=e.element_id in flagged or bool(e.news and e.news.suspicious)) for e in elements]
    index: dict[str, Element] = {}
    for element in elements:
        if element.element_id in index:
            raise PackageError("review package rejected: repeated element_id")
        index[element.element_id] = element
    return index


def _line(key: str, value: Any) -> str:
    rendered = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
    return f"{key}: {rendered}"


def _cve_element(cve: Mapping[str, Any], kev: Mapping[str, Any], epss: Mapping[str, Any] | None) -> Element:
    inferred = cve["cvss_source"] == "inferred"  # estimated by the CVE analyst (docs/05): not an official fact
    lines = [
        (True, _line("description", cve["description"])),
        (not inferred, _line("cvss", cve["cvss"])),
        (not inferred, _line("vector", cve["vector"])),
        (True, _line("cvss_source", cve["cvss_source"])),
        (True, _line("cwe", cve["cwe"])),
        (True, _line("affected_ranges", cve["affected_ranges"])),
        (True, _line("fixed_version", cve["fixed_version"])),
        (True, _line("references", cve["references"])),
        (False, _line("conditions", cve["conditions"])),  # CVE analyst output (docs/05 ANA)
        (False, _line("components", cve["components"])),
        (True, _line("kev_listed", kev["listed"])),
        (True, _line("kev_date", kev["date"])),
        (True, _line("kev_required_action", kev["required_action"])),
        (True, _line("kev_known_ransomware", kev["known_ransomware"])),
        (True, _line("epss", epss)),
    ]
    return Element(
        element_id=str(cve["element_id"]),
        kind=ElementKind.CVE,
        text="\n".join(line for _official, line in lines),
        source_level=SourceLevel.N1,
        official_text="\n".join(line for official, line in lines if official),
    )


def _news_element(news: Mapping[str, Any]) -> Element:
    lines = [
        _line("title", news["title"]),
        _line("source", news["source"]),
        _line("date", news["date"]),
        _line("urls", news["urls"]),
        _line("summary", news["summary"]),
        _line("event_types", news["event_types"]),
        _line("exploitation_level", news["exploitation_level"]),
    ]
    info = NewsInfo(
        story_id=str(news["story_id"]),
        source=str(news["source"]),
        published=_parse_date(str(news["date"])),
        domains=frozenset(d for d in (_domain(u) for u in news["urls"]) if d),
        suspicious=bool(news["suspicious"]),
    )
    return Element(
        element_id=str(news["element_id"]),
        kind=ElementKind.NEWS,
        text="\n".join(lines),
        source_level=SourceLevel(news["source_level"]),
        news=info,
    )


def _ci_element(ci: Mapping[str, Any]) -> Element:
    structured = "\n".join(
        _line(key, ci[key])
        for key in ("ci_id", "name", "service", "criticality", "exposed", "confidentiality", "personal_data")
    )
    structured += "\n" + "\n".join(_line(key, ci[key]) for key in ("custodian", "status"))
    free_text = ci["description"] or ""
    return Element(
        element_id=str(ci["element_id"]),
        kind=ElementKind.CI,
        text=f"{structured}\n{_line('description', free_text)}",
        source_level=SourceLevel.N1,
        official_text=structured,
        free_text=free_text,
        ci_id=str(ci["ci_id"]),
    )


def _parse_date(value: str) -> date | None:
    try:
        return datetime.fromisoformat(value).date()
    except ValueError:
        try:
            return date.fromisoformat(value[:10])
        except ValueError:
            return None


def _domain(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:  # e.g. an invalid bracketed host: keep the rest of the evidence
        return None
    if not host:
        return None
    host = host.lower()
    return host.removeprefix("www.")
