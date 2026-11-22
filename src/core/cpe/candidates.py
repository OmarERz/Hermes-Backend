"""Candidate search for the CPE mapping (ESC-06): NVD's CPE dictionary plus what we already hold.

`GET https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=...` answers `products[].cpe.cpeName`
(`cpe:2.3:a:<vendor>:<product>:...`), `deprecated` and `titles`. ⚠️ Endpoint and fields follow NVD's published
API and could not be re-read from its JavaScript documentation here. The local candidates come from the affected
ranges already loaded (`cve_affected_range`), so the search still works offline and without a key.
The query is data: it is only ever sent as a URL parameter or a bound SQL value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Final

from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.db import models as m
from core.vulndata.http import JsonSource, SourceRefusedError, SourceUnavailableError
from core.vulndata.records import NVD_CPE

CPE_URL: Final = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
CPE_SPLIT: Final = re.compile(r"(?<!\\):")
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


def cpe_uri(vendor: str, product: str) -> str:
    """The CPE 2.3 name of a vendor and product with every version wildcarded, as the front shows it."""

    def escape(part: str) -> str:
        return re.sub(r"([^A-Za-z0-9_.\-])", r"\\\1", part)

    return f"cpe:2.3:a:{escape(vendor)}:{escape(product)}:*:*:*:*:*:*:*:*"


def parse_cpe_name(name: str) -> tuple[str, str] | None:
    parts = CPE_SPLIT.split(name)
    if len(parts) < CPE_FIELDS or parts[:2] != ["cpe", "2.3"] or parts[2] not in {"a", "o"}:
        return None
    vendor, product = (re.sub(r"\\(.)", r"\1", p) for p in parts[3:5])
    return (vendor, product) if vendor not in {"", "*", "-"} and product not in {"", "*", "-"} else None


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
        pair = parse_cpe_name(cpe["cpeName"])
        if pair is None or pair in found:
            return
        titles = [t.get("title") for t in cpe.get("titles") or [] if isinstance(t, dict) and t.get("lang") == "en"]
        found[pair] = Candidate(*pair, "nvd_dictionary", similarity(query, *pair), titles[0] if titles else None)

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
    found = [Candidate(v, p, "local", similarity(query, v, p), None, n) for v, p, n in rows]
    return sorted(found, key=lambda c: (-c.score, c.vendor, c.product))[:limit]


def find_candidates(
    session: Session, keyword: str, dictionary: CpeDictionaryClient | None = None, limit: int = LIMIT
) -> list[Candidate]:
    """Local and dictionary candidates merged by (vendor, product), best match first.

    A dictionary outage does not hide the local candidates: the analyst still gets what we know.
    """
    merged = {(c.vendor, c.product): c for c in local_candidates(session, keyword, limit)}
    if dictionary is not None:
        try:
            remote = dictionary.search(keyword)
        except (SourceUnavailableError, SourceRefusedError):  # a 403 or an outage must not hide local candidates
            remote = []
        for item in remote:
            known = merged.get((item.vendor, item.product))
            merged[(item.vendor, item.product)] = (
                item
                if known is None
                else Candidate(item.vendor, item.product, "nvd_dictionary", item.score, item.title, known.cve_count)
            )
    return sorted(merged.values(), key=lambda c: (-c.score, c.vendor, c.product))[:limit]
