"""Layer VAL-03: content rules for the analysts' outputs (docs/09 §1).

Every rule returns violations with its id; nothing is repaired (VAL-05). The checks that need data outside the
output (does the CVE exist, what is the article text) take it as arguments, so the layer is pure and testable.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable, Iterable
from typing import Any

from core.validation.violations import Violation

CVE_FORMAT = re.compile(r"^CVE-\d{4}-\d{4,7}$")
CPE_PAIR = re.compile(r"^[a-z0-9._\-~%]+:[a-z0-9._\-~%]+$")
CVSS_31 = re.compile(r"^CVSS:3\.1/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]$")
CVSS_40 = re.compile(
    r"^CVSS:4\.0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[HLN]/VI:[HLN]/VA:[HLN]/SC:[HLN]/SI:[HLN]/SA:[HLN]$"
)
_SPACES = re.compile(r"\s+")

CveExists = Callable[[str], bool]


def normalize_text(value: str) -> str:
    """Unicode NFKC, runs of whitespace collapsed to one space, trimmed (the normalization of VAL-03)."""
    return _SPACES.sub(" ", unicodedata.normalize("NFKC", value)).strip()


def quote_in_text(quote: str, text: str) -> bool:
    """True when `quote` is non-empty and appears verbatim in `text` once spaces are normalized."""
    needle = normalize_text(quote)
    return bool(needle) and needle in normalize_text(text)


def check_quote(quote: object, text: str, path: str) -> list[Violation]:
    if not isinstance(quote, str) or not normalize_text(quote):
        return [Violation("VAL-03.quote", path, "The claim has no quote", "missing")]
    if not quote_in_text(quote, text):
        return [Violation("VAL-03.quote", path, "The quote does not appear verbatim in the text", "not_verbatim")]
    return []


def check_cve(value: object, path: str, cve_exists: CveExists) -> list[Violation]:
    if not isinstance(value, str) or not CVE_FORMAT.fullmatch(value):
        return [Violation("VAL-03.cve_format", path, "Not a valid CVE identifier")]
    if not cve_exists(value):
        return [Violation("VAL-03.cve_exists", path, "The CVE does not exist in NVD or CVE.org")]
    return []


def check_cvss_vector(vector: object, path: str) -> list[Violation]:
    """An empty vector means "not inferred". Otherwise it must be a CVSS 3.1 or 4.0 base vector (the score is
    computable from base metrics alone; optional metrics are not accepted)."""
    if vector == "":
        return []
    if isinstance(vector, str) and (CVSS_31.fullmatch(vector) or CVSS_40.fullmatch(vector)):
        return []
    return [Violation("VAL-03.cvss_syntax", path, "Not a valid CVSS 3.1 or 4.0 vector")]


def _each(items: object, path: str) -> Iterable[tuple[str, dict[str, Any]]]:
    if isinstance(items, list):
        for index, item in enumerate(items):
            if isinstance(item, dict):
                yield f"{path}[{index}]", item


_DASHES = {ord(c): "-" for c in "\u2010\u2011\u2012\u2013\u2014\u2212"}


def _mentions_cve(text: str, cve: str) -> bool:
    """The identifier appears in the text as a whole (CVE-2026-1111 is not inside CVE-2026-11112)."""
    plain = normalize_text(text).translate(_DASHES).upper()
    return re.search(rf"(?<![0-9]){re.escape(cve.upper())}(?![0-9])", plain) is not None


def check_news_analysis(
    output: dict[str, Any], article_text: str, expected_news_id: str, cve_exists: CveExists
) -> list[Violation]:
    """VAL-03 for `submit_news_analysis`: the story id, CVEs, quotes of every claim and CPE candidates."""
    violations: list[Violation] = []
    if output.get("news_id") != expected_news_id:
        violations.append(Violation("VAL-03.news_id", "news_id", "The output is about another story"))
    for path, item in _each(output.get("cves"), "cves"):
        found = check_cve(item.get("cve"), f"{path}.cve", cve_exists)
        violations += found
        if not found and not _mentions_cve(article_text, str(item["cve"])):
            violations.append(Violation("VAL-03.cve_in_text", f"{path}.cve", "The CVE does not appear in the article"))
        violations += check_quote(item.get("quote"), article_text, f"{path}.quote")
    for path, item in _each(output.get("products"), "products"):
        cpe = item.get("candidate_cpe")
        if cpe and not (isinstance(cpe, str) and CPE_PAIR.fullmatch(cpe)):
            violations.append(Violation("VAL-03.cpe_format", f"{path}.candidate_cpe", "Expected vendor:product"))
        violations += check_quote(item.get("quote"), article_text, f"{path}.quote")
    for section in ("actors", "victims", "conditions"):
        for path, item in _each(output.get(section), section):
            violations += check_quote(item.get("quote"), article_text, f"{path}.quote")
    return violations


def check_cve_analysis(
    output: dict[str, Any], expected_cve: str, source_text: str, cve_exists: CveExists
) -> list[Violation]:
    """VAL-03 for `submit_cve_analysis`: the CVE asked for, the vector syntax and the quotes."""
    violations: list[Violation] = []
    if output.get("cve") != expected_cve:
        violations.append(Violation("VAL-03.cve_id", "cve", "The output is about another CVE"))
    violations += check_cve(output.get("cve"), "cve", cve_exists)
    violations += check_cvss_vector(output.get("inferred_cvss_vector", ""), "inferred_cvss_vector")
    for section in ("conditions", "components"):
        for path, item in _each(output.get(section), section):
            violations += check_quote(item.get("quote"), source_text, f"{path}.quote")
    return violations
