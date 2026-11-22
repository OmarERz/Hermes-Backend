"""Dynamic keyword filter (ING-06, D-018): only stories that mention something of the company reach the analyst.

The term list is rebuilt on each run from: iTop products and their CPE names, the CVEs of active findings, sector
terms (English and Spanish) for the company's sectors, and the names and aliases of peer companies. A story is
`relevant` when any article of it contains a term as a whole word or phrase; otherwise `filtered`. The filter may
let irrelevant stories through (tolerated leak, D-018); the analyst and the correlation decide the rest.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass
from functools import cached_property

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from core.db import models as m
from core.ingestion.entities import extract_cves

log = logging.getLogger("ingestion")

MIN_TERM_CHARS = 2  # keeps exact short names such as "Go" or "3M"
_TRAILING_VERSION = re.compile(r"[\s_-]+v?\d[\w.\-]*$")
_SEPARATORS = re.compile(r"[\s_]+")

# Sector terms in English and Spanish, by `sector.code` (seeded catalog).
SECTOR_TERMS: dict[str, tuple[str, ...]] = {
    "transportation": (
        "transportation",
        "logistics",
        "airline",
        "aviation",
        "railway",
        "ride-hailing",
        "rideshare",
        "transporte",
        "logística",
        "aerolínea",
        "aviación",
        "ferrocarril",
        "movilidad",
    ),
    "fintech": (
        "fintech",
        "banking",
        "financial services",
        "payments",
        "payment processor",
        "insurance",
        "banca",
        "servicios financieros",
        "pagos",
        "seguros",
        "financiera",
    ),
    "retail": (
        "retail",
        "retailer",
        "e-commerce",
        "ecommerce",
        "point of sale",
        "comercio",
        "minorista",
        "comercio electrónico",
        "punto de venta",
    ),
    "healthcare": (
        "healthcare",
        "hospital",
        "medical",
        "pharmaceutical",
        "clinic",
        "salud",
        "clínica",
        "médico",
        "farmacéutica",
    ),
    "government": (
        "government",
        "federal agency",
        "public sector",
        "municipal",
        "ministry",
        "gobierno",
        "sector público",
        "dependencia",
        "ministerio",
    ),
}


def _normalize(value: str) -> str:
    return _SEPARATORS.sub(" ", unicodedata.normalize("NFKC", value)).strip().casefold()


def name_variants(name: str) -> set[str]:
    """A product or company name as written and without trailing version tokens ("OpenSSL 3.0" gives "openssl")."""
    full = _normalize(name)
    variants = {full}
    stripped = full
    while True:
        shorter = _TRAILING_VERSION.sub("", stripped)
        if shorter == stripped:
            break
        stripped = shorter
    variants.add(stripped)
    return {v for v in variants if len(v) >= MIN_TERM_CHARS}


@dataclass(frozen=True)
class KeywordSet:
    terms: frozenset[str]
    cves: frozenset[str]

    def matches(self, text_value: str) -> bool:
        """True when the text names a CVE of an active finding or contains any term as a whole word or phrase."""
        if self.cves and self.cves & extract_cves(text_value):
            return True
        if not self.terms:
            return False
        return self._pattern.search(_normalize(text_value)) is not None

    @cached_property
    def _pattern(self) -> re.Pattern[str]:
        alternation = "|".join(re.escape(t) for t in sorted(self.terms, key=len, reverse=True))
        return re.compile(rf"(?<![\w])(?:{alternation})(?![\w])")


def build_keywords(session: Session) -> KeywordSet:
    terms: set[str] = set()
    for (name,) in session.execute(select(m.SoftwareProduct.itop_name)):
        terms |= name_variants(name)
    mapping_columns = (
        m.CpeMapping.nvd_vendor,
        m.CpeMapping.nvd_product,
        m.CpeMapping.cna_vendor,
        m.CpeMapping.cna_product,
    )
    for row in session.execute(select(*mapping_columns)):
        for value in row:
            if value:
                terms |= name_variants(value)
    for code, name in session.execute(
        select(m.Sector.code, m.Sector.name).join(m.ProfileSector, m.ProfileSector.sector_code == m.Sector.code)
    ):
        terms |= name_variants(name)
        for term in SECTOR_TERMS.get(code, ()):
            terms |= name_variants(term)
    for (name,) in session.execute(select(m.PeerCompany.name)):
        terms |= name_variants(name)
    for (alias,) in session.execute(select(m.PeerCompanyAlias.alias)):
        terms |= name_variants(alias)
    cves = frozenset(
        cve_id
        for (cve_id,) in session.execute(
            text(
                "SELECT g.cve_id FROM finding_group g JOIN finding_group_status s ON s.finding_group_id = g.id "
                "WHERE s.status = 'active'"
            )
        )
    )
    return KeywordSet(terms=frozenset(terms), cves=cves)


@dataclass(frozen=True)
class FilterResult:
    relevant: int
    filtered: int


def filter_pending_stories(session: Session, keywords: KeywordSet | None = None) -> FilterResult:
    """Decide every story still `pending`; commits."""
    keywords = keywords or build_keywords(session)
    stories = list(session.scalars(select(m.Story).where(m.Story.relevance_status == "pending")))
    relevant = 0
    for story in stories:
        articles = session.execute(
            select(m.RawArticle.title, m.RawArticle.clean_text).where(m.RawArticle.story_id == story.id)
        )
        passes = any(keywords.matches(f"{title}\n{body or ''}") for title, body in articles)
        story.relevance_status = "relevant" if passes else "filtered"
        relevant += passes
    session.commit()
    log.info("keyword filter: %d relevant, %d filtered", relevant, len(stories) - relevant)
    return FilterResult(relevant=relevant, filtered=len(stories) - relevant)
