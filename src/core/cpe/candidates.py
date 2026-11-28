"""Candidate search for the CPE mapping (ESC-06): NVD's CPE dictionary plus what we already hold.

`GET https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=...` answers `products[].cpe.cpeName`
(`cpe:2.3:<part>:<vendor>:<product>:...`, part `a`, `o` or `h`), `deprecated` and `titles`. ⚠️ Endpoint and fields
follow NVD's published API and could not be re-read from its JavaScript documentation here. The local candidates come
from the affected ranges already loaded (`cve_affected_range`), so the search still works offline and without a key.
The query is data: it is only ever sent as a URL parameter or a bound SQL value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Final

from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.cpe.fields import CPE_PARTS, DEFAULT_PART, split_cpe_fields, unescape_cpe
from core.db import models as m
from core.vulndata.http import JsonSource, SourceRefusedError, SourceUnavailableError
from core.vulndata.records import NVD_CPE

CPE_URL: Final = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
TOKEN: Final = re.compile(r"[a-z0-9]+")
MAX_QUERY: Final = 100
FIRST_PRINTABLE: Final = 32
LIMIT: Final = 20
PAGE_SIZE: Final = 500
MAX_PAGES: Final = 4  # versions each take a dictionary record, so one page may hold a single product
CPE_FIELDS: Final = 6


@dataclass(frozen=True)
class Candidate:
    vendor: str
    product: str
    source: str  # nvd_dictionary | local
    score: float  # 0-1 similarity to the query
    title: str | None = None
    cve_count: int | None = None
    part: str = DEFAULT_PART  # the dictionary's own part; a local pair takes the part of a mapping that has it


def clean_query(raw: str) -> str:
    query = " ".join(raw.split())
    if not query or len(query) > MAX_QUERY or any(ord(ch) < FIRST_PRINTABLE for ch in query):
        raise ValueError("the search text must be 1 to 100 printable characters")
    return query


def similarity(query: str, vendor: str, product: str) -> float:
    wanted = set(TOKEN.findall(query.lower()))
    have = set(TOKEN.findall(f"{vendor} {product}".lower().replace("_", " ")))
    if not wanted or not have:
        return 0.0
    return len(wanted & have) / len(wanted | have)


def cpe_uri(vendor: str, product: str, part: str | None = DEFAULT_PART) -> str:
    """The CPE 2.3 name of a vendor and product with every version wildcarded, as the front shows it. The part is the
    one the mapping stores (`o` for an operating system such as the Linux kernel, D-107); `a` when there is none."""

    def escape(field: str) -> str:
        return re.sub(r"([^A-Za-z0-9_.\-])", r"\\\1", field)

    kind = part if part in CPE_PARTS else DEFAULT_PART
    return f"cpe:2.3:{kind}:{escape(vendor)}:{escape(product)}:*:*:*:*:*:*:*:*"


def parse_cpe_parts(name: str) -> tuple[str, str, str] | None:
    """(part, vendor, product) of a CPE 2.3 name whose part is `a`, `o` or `h` and that names a vendor and product."""
    parts = split_cpe_fields(name)
    if len(parts) < CPE_FIELDS or parts[:2] != ["cpe", "2.3"] or parts[2] not in CPE_PARTS:
        return None
    vendor, product = (unescape_cpe(p) for p in parts[3:5])
    return (parts[2], vendor, product) if vendor not in {"", "*", "-"} and product not in {"", "*", "-"} else None


def parse_cpe_name(name: str) -> tuple[str, str] | None:
    """(vendor, product) of a CPE 2.3 name, as `parse_cpe_parts` reads it."""
    parsed = parse_cpe_parts(name)
    return None if parsed is None else (parsed[1], parsed[2])


@dataclass
class CpeDictionaryClient:
    source: JsonSource
    api_key: SecretStr | None = None
    url: str = CPE_URL

    @staticmethod
    def _collect(item: Any, query: str, found: dict[tuple[str, str], Candidate]) -> None:
        cpe = item.get("cpe") if isinstance(item, dict) else None
        if not isinstance(cpe, dict) or cpe.get("deprecated") or not isinstance(cpe.get("cpeName"), str):
            return
        parsed = parse_cpe_parts(cpe["cpeName"])
        if parsed is None or parsed[1:] in found:
            return
        part, *pair = parsed
        titles = [t.get("title") for t in cpe.get("titles") or [] if isinstance(t, dict) and t.get("lang") == "en"]
        title = titles[0] if titles else None
        found[(pair[0], pair[1])] = Candidate(
            pair[0], pair[1], "nvd_dictionary", similarity(query, *pair), title, part=part
        )

    def search(self, keyword: str) -> list[Candidate]:
        query = clean_query(keyword)
        headers = {"apiKey": self.api_key.get_secret_value()} if self.api_key else None
        found: dict[tuple[str, str], Candidate] = {}
        start = 0
        for _ in range(MAX_PAGES):
            params: dict[str, str | int] = {"keywordSearch": query, "resultsPerPage": PAGE_SIZE, "startIndex": start}
            body = self.source.get(self.url, params=params, headers=headers)
            if not isinstance(body, dict) or not isinstance(body.get("products"), list):
                raise SourceUnavailableError("incomplete NVD CPE answer")
            products: list[Any] = body["products"]
            for item in products:
                self._collect(item, query, found)
            start += len(products)
            if not products or start >= int(body.get("totalResults") or 0) or len(found) >= LIMIT:
                break
        return list(found.values())


def local_candidates(session: Session, keyword: str, limit: int = LIMIT) -> list[Candidate]:
    """Vendor and product pairs already seen in NVD ranges whose name shares a word with the query."""
    query = clean_query(keyword)
    words = TOKEN.findall(query.lower())
    if not words:
        return []
    rows = session.execute(
        select(m.CveAffectedRange.vendor, m.CveAffectedRange.product, func.count(m.CveAffectedRange.cve_id.distinct()))
        .where(m.CveAffectedRange.source == NVD_CPE)
        .where(
            func.lower(m.CveAffectedRange.vendor + " " + m.CveAffectedRange.product).op("~")(
                "(" + "|".join(re.escape(w) for w in words) + ")"
            )
        )
        .group_by(m.CveAffectedRange.vendor, m.CveAffectedRange.product)
    )
    counted = list(rows)
    parts = _mapped_parts(session, {(v, p) for v, p, _ in counted})
    found = [
        Candidate(v, p, "local", similarity(query, v, p), None, n, parts.get((v, p), DEFAULT_PART))
        for v, p, n in counted
    ]
    return sorted(found, key=lambda c: (-c.score, c.vendor, c.product))[:limit]


def _mapped_parts(session: Session, pairs: set[tuple[str, str]]) -> dict[tuple[str, str], str]:
    """The CPE part a mapping already stores for each NVD pair (ranges do not keep it); the lowest when two differ."""
    if not pairs:
        return {}
    rows = session.execute(
        select(m.CpeMapping.nvd_vendor, m.CpeMapping.nvd_product, func.min(m.CpeMapping.nvd_part))
        .where(m.CpeMapping.nvd_vendor.in_({v for v, _ in pairs}), m.CpeMapping.nvd_part.is_not(None))
        .group_by(m.CpeMapping.nvd_vendor, m.CpeMapping.nvd_product)
    )
    return {(str(v), str(p)): str(part) for v, p, part in rows if (v, p) in pairs and part}


def merge_candidates(local: list[Candidate], remote: list[Candidate], limit: int = LIMIT) -> list[Candidate]:
    """Local and dictionary candidates merged by (vendor, product), best match first (the CVE count is kept)."""
    merged = {(c.vendor, c.product): c for c in local}
    for item in remote:
        known = merged.get((item.vendor, item.product))
        merged[(item.vendor, item.product)] = (
            item
            if known is None
            else Candidate(
                item.vendor, item.product, "nvd_dictionary", item.score, item.title, known.cve_count, item.part
            )
        )
    return sorted(merged.values(), key=lambda c: (-c.score, c.vendor, c.product))[:limit]


def search_dictionary(dictionary: CpeDictionaryClient | None, keyword: str) -> list[Candidate]:
    """The dictionary's candidates; an outage or a refusal (a 403 for a bad key) gives none instead of failing."""
    if dictionary is None:
        return []
    try:
        return dictionary.search(keyword)
    except (SourceUnavailableError, SourceRefusedError):
        return []


def find_candidates(
    session: Session, keyword: str, dictionary: CpeDictionaryClient | None = None, limit: int = LIMIT
) -> list[Candidate]:
    """Local and dictionary candidates merged, best match first.

    A dictionary outage does not hide the local candidates: the analyst still gets what we know.
    """
    return merge_candidates(local_candidates(session, keyword, limit), search_dictionary(dictionary, keyword), limit)
