"""Match keys and relevance rules, pure."""

from __future__ import annotations

from decimal import Decimal

import pytest

from core.correlation.keys import (
    KEY_ORDER,
    MatchType,
    best_match,
    highest_relevance,
    is_r1,
    is_r2,
    is_r3,
    is_r4,
    keep_strongest,
    normalize_name,
    os_matches,
    same_product,
    vector_matches,
)

TYPES = {
    code: MatchType(code, Decimal(strength), priority)
    for priority, (code, strength) in enumerate(
        [("cve_exact", "1.0"), ("product_version", "0.9"), ("product", "0.6"), ("os", "0.6"), ("vector", "0.6")], 1
    )
}


def test_names_are_folded_but_never_cut() -> None:
    assert normalize_name("  HTTP_Server-2.4 ") == "http server 2 4"
    assert normalize_name(None) == ""
    assert KEY_ORDER == ("cve_exact", "product_version", "product", "os", "vector")


@pytest.mark.parametrize(
    ("news_vendor", "news_product", "vendor", "product", "expected"),
    [
        ("Apache", "HTTP Server", "apache", "http_server", True),
        ("Apache", None, "apache", "http_server", False),  # a single word never crosses (COR-02)
        (None, "http_server", "apache", "http_server", False),
        ("", "", "", "", False),
        ("Apache", "Tomcat", "apache", "http_server", False),
        ("Apache", "HTTP Server", "nginx", "http_server", False),
        ("Apache", "HTTP", "apache", "http_server", False),  # no partial product names
    ],
)
def test_product_needs_vendor_and_product(
    news_vendor: str | None, news_product: str | None, vendor: str, product: str, expected: bool
) -> None:
    assert same_product(news_vendor, news_product, vendor, product) is expected


@pytest.mark.parametrize(
    ("family", "version", "asset_os", "expected"),
    [
        ("Ubuntu", "22.04", "Ubuntu 22.04 LTS", True),
        ("Ubuntu", "22.04", "Ubuntu 20.04", False),
        ("Ubuntu", None, "Ubuntu 22.04", False),
        ("Windows", "10", "Windows 10 Pro", True),
        ("Windows", "1", "Windows 10 Pro", False),  # whole words only
        ("Ubuntu", "22.04", None, False),
    ],
)
def test_os_needs_family_and_version(family: str, version: str | None, asset_os: str | None, expected: bool) -> None:
    assert os_matches(family, version, asset_os) is expected


def test_vector_is_a_whole_product_present_in_itop() -> None:
    present = {"OpenSSL", "Apache HTTP Server"}
    assert vector_matches("openssl", present)
    assert vector_matches("apache_http_server", present)
    assert not vector_matches("apache", present)
    assert not vector_matches("", present)
    assert not vector_matches(None, present)


def test_the_strongest_key_wins() -> None:
    assert best_match({"product", "cve_exact", "os"}, TYPES) == TYPES["cve_exact"]
    assert best_match({"os", "product"}, TYPES) == TYPES["product"]
    assert best_match({"unknown"}, TYPES) is None
    assert best_match(set(), TYPES) is None


def test_the_match_cap_keeps_the_strongest_and_reports_the_cut() -> None:
    matches = [
        (TYPES["product"], "g3"),
        (TYPES["cve_exact"], "g2"),
        (TYPES["vector"], "g1"),
        (TYPES["cve_exact"], "g0"),
    ]
    kept, cut = keep_strongest(matches, 2)
    assert [(m.code, g) for m, g in kept] == [("cve_exact", "g0"), ("cve_exact", "g2")]
    assert cut == 2
    assert keep_strongest(matches, 10)[1] == 0


def test_relevance_rules() -> None:
    assert is_r1("cve_exact", "active")
    assert is_r1("cve_exact", "limited")
    assert is_r1("cve_exact", "mass")
    assert not is_r1("cve_exact", "denied")
    assert not is_r1("cve_exact", "attempted")
    assert not is_r1("cve_exact", None)
    assert not is_r1("product", "active")
    assert is_r2("product_version") and is_r2("product") and is_r2("os")
    assert not is_r2("cve_exact") and not is_r2("vector")
    assert is_r3(True, False, False) and is_r3(False, True, False) and is_r3(False, False, True)
    assert not is_r3(False, False, False)
    assert is_r4(True) and not is_r4(False)
    assert highest_relevance({"R3", "R2"}) == "R2"
    assert highest_relevance({"R4"}) == "R4"
    assert highest_relevance(set()) is None
