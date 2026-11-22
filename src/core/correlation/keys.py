"""Match keys (COR-01, COR-02) and relevance rules R1 to R4 (docs/06 §2) as pure functions.

A key never compares a single word: a product needs its vendor and its product name, both, and equal after
normalization ("Apache" alone crosses with nothing). Strengths come from `correlation_match_type`, not from code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal

KEY_ORDER = ("cve_exact", "product_version", "product", "os", "vector")  # strongest first
PRODUCT_KEYS = frozenset({"product_version", "product", "os"})
EXPLOITED_LEVELS = frozenset({"limited", "active", "mass"})  # R1: the news reports exploitation
SECURITY_EVENT_TYPES = frozenset({"active_exploitation", "organization_attack", "actor_campaign", "new_vulnerability"})
RELEVANCE_ORDER = ("R1", "R2", "R3", "R4")

_SEPARATORS = re.compile(r"[\s_\-.]+")


@dataclass(frozen=True)
class MatchType:
    code: str
    strength: Decimal
    priority: int  # 1 is the strongest


def normalize_name(value: str | None) -> str:
    """Case, separators and surrounding spaces folded; nothing else (no stemming, no partial words)."""
    return _SEPARATORS.sub(" ", (value or "").casefold()).strip()


def same_product(news_vendor: str | None, news_product: str | None, vendor: str | None, product: str | None) -> bool:
    """COR-02: vendor and product must both be present and both equal; one word alone never crosses."""
    pairs = (normalize_name(news_vendor), normalize_name(news_product), normalize_name(vendor), normalize_name(product))
    if not all(pairs):
        return False
    return pairs[0] == pairs[2] and pairs[1] == pairs[3]


def os_matches(news_product: str | None, news_version: str | None, asset_os: str | None) -> bool:
    """The news names an OS family and a version, and the CI's OS text contains both as whole words."""
    family, version, installed = normalize_name(news_product), normalize_name(news_version), normalize_name(asset_os)
    if not (family and version and installed):
        return False
    return f" {family} {version} " in f" {installed} "


def vector_matches(vector_code: str | None, present_products: set[str]) -> bool:
    """R3: the attack vector is a product present in iTop (compared whole, normalized)."""
    code = normalize_name(vector_code)
    return bool(code) and code in {normalize_name(p) for p in present_products}


def best_match(candidates: set[str], types: dict[str, MatchType]) -> MatchType | None:
    """The strongest of the keys that matched (lowest priority number)."""
    found = [types[code] for code in candidates if code in types]
    return min(found, key=lambda t: t.priority) if found else None


def keep_strongest(matches: list[tuple[MatchType, str]], limit: int) -> tuple[list[tuple[MatchType, str]], int]:
    """COR-03: at most `limit` group matches per news item, the strongest first; returns the kept ones and the cut."""
    ordered = sorted(matches, key=lambda item: (item[0].priority, -item[0].strength, item[1]))
    return ordered[:limit], max(0, len(ordered) - limit)


def is_r1(match_code: str, cve_exploitation_level: str | None) -> bool:
    """R1: exploitation (limited, active or mass) of a CVE that is in an active group."""
    return match_code == "cve_exact" and cve_exploitation_level in EXPLOITED_LEVELS


def is_r2(match_code: str) -> bool:
    return match_code in PRODUCT_KEYS


def is_r3(peer_victim: bool, sector_matches_profile: bool, vector_is_present_product: bool) -> bool:
    return peer_victim or sector_matches_profile or vector_is_present_product


def is_r4(actor_history_in_profile_scope: bool) -> bool:
    return actor_history_in_profile_scope


def highest_relevance(relevances: set[str]) -> str | None:
    for code in RELEVANCE_ORDER:
        if code in relevances:
            return code
    return None
