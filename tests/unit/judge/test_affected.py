"""Affected ranges of the group's product in a review package (D-101, docs/07 §13 JUE-MIT-10)."""

from __future__ import annotations

from typing import Any

import pytest

from core.judge.affected import AffectedRange, product_key, product_ranges
from core.judge.package import ReviewPackage
from harness.judge import dismissal_package, finding_package

pytestmark = pytest.mark.unit


def package(cpe: str | None, ranges: list[str]) -> ReviewPackage:
    content: dict[str, Any] = finding_package()
    content["group"]["cpe"] = cpe
    content["cve_data"]["affected_ranges"] = ranges
    return ReviewPackage.from_content(content)


@pytest.mark.parametrize(
    ("cpe", "key"),
    [
        ("openssl:openssl", "openssl:openssl"),  # how correlation writes it: the first pair of the CPE mapping
        ("OpenSSL:OpenSSL", "openssl:openssl"),
        ("apache:http_server", "apache:http server"),
        ("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", "openssl:openssl"),  # a CPE 2.3 name
        ("cpe:2.3:a:example:http\\:server:*:*:*:*:*:*:*:*", "example:http:server"),  # an escaped colon
        (None, None),
        ("", None),
        ("openssl", None),
        (":openssl", None),
        ("openssl:", None),
        ("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*", None),  # any vendor names no product
        ("cpe:2.3:a:openssl", None),
    ],
)
def test_product_key_needs_a_vendor_and_a_product(cpe: str | None, key: str | None) -> None:
    assert product_key(cpe) == key


def test_only_ranges_of_the_group_product_count() -> None:
    ranges = [
        "openssl:openssl [3.0.0,3.0.18)",
        "OpenSSL:OpenSSL [3.2.0,3.2.6)",  # a CNA range under the same names
        "openssl:openssl (,1.0.2zm]",
        "openssl:openssl_fips [3.0.0,3.0.9)",  # another product that starts the same
        "nodejs:node.js [18.0.0,18.20.5)",
        "openssl:openssl (,)",
    ]
    found = product_ranges(package("openssl:openssl", ranges))
    assert found == (
        AffectedRange("openssl:openssl [3.0.0,3.0.18)", "3.0.0", True, "3.0.18", False),
        AffectedRange("OpenSSL:OpenSSL [3.2.0,3.2.6)", "3.2.0", True, "3.2.6", False),
        AffectedRange("openssl:openssl (,1.0.2zm]", None, False, "1.0.2zm", True),
        AffectedRange("openssl:openssl (,)", None, False, None, False),
    )


@pytest.mark.parametrize(
    "text",
    [
        "< 2.4.60",  # not how correlation renders a range: it names no product
        "openssl:openssl 3.0.0-3.0.23",  # no interval
        "openssl [3.0.0,3.0.23)",  # no vendor
    ],
)
def test_a_string_that_names_no_product_of_the_group_is_left_out(text: str) -> None:
    assert product_ranges(package("openssl:openssl", [text])) == ()


@pytest.mark.parametrize(
    "text",
    ["openssl:openssl [3.0.0,3.0.23", "openssl:openssl [3.0.0;3.0.23)", "openssl:openssl [3.0.0,3.0.23,3.1.0)"],
)
def test_a_range_of_the_product_that_cannot_be_read_is_kept_as_unreadable(text: str) -> None:
    (unreadable,) = product_ranges(package("openssl:openssl", [text]))
    assert unreadable == AffectedRange(text, None, False, None, False, readable=False)
    assert unreadable.contains("3.0.23") is None  # nothing is known to be outside it


def test_spaces_around_a_bound_are_dropped() -> None:
    # A CNA `lessThan` keeps its spaces (cvelist.py) and correlation renders them as they are.
    (spaced,) = product_ranges(package("openssl:openssl", ["openssl:openssl [ 3.0.0 ,3.0.23 )"]))
    assert (spaced.start, spaced.end) == ("3.0.0", "3.0.23")
    assert spaced.contains("3.0.22") is True


def test_a_product_name_with_brackets_is_read_whole() -> None:
    ranges = ["acme:server (enterprise) [1.0,2.0)", "acme:server [1.0,1.5)"]
    assert product_ranges(package("acme:server (enterprise)", ranges)) == (
        AffectedRange("acme:server (enterprise) [1.0,2.0)", "1.0", True, "2.0", False),
    )


def test_no_group_or_no_cpe_means_no_ranges() -> None:
    assert product_ranges(package(None, ["openssl:openssl [3.0.0,3.0.23)"])) == ()
    assert product_ranges(ReviewPackage.from_content(dismissal_package())) == ()  # no group, no CVE data


@pytest.mark.parametrize(
    ("version", "inside"),
    [
        ("2.9.9", False),
        ("3.0.0", True),  # inclusive start
        ("3.0.22", True),
        ("3.0.23", False),  # exclusive end: the fixed version
        ("3.0.23-rc1", True),  # a pre-release of the fixed version is still before it
        ("v3.0.23", False),
        ("3.0.23-fips", None),  # a label off the scale next to the bound: never guessed (ESC-13)
        ("1.1.1w", False),  # a letter release below the range: its release decides
        ("latest", None),
    ],
)
def test_contains_compares_both_bounds(version: str, inside: bool | None) -> None:
    assert AffectedRange("p:p [3.0.0,3.0.23)", "3.0.0", True, "3.0.23", False).contains(version) is inside


def test_one_bound_that_leaves_the_version_out_decides() -> None:
    letters = AffectedRange("openssl:openssl [1.1.1,1.1.1zd)", "1.1.1", True, "1.1.1zd", False)
    assert letters.contains("3.0.18") is False  # above the end whatever "zd" means
    assert letters.contains("1.0.2") is False  # below the start
    assert letters.contains("1.1.1zd") is False  # the end itself, excluded
    assert letters.contains("1.1.1w") is None  # same release, letters off the scale
    inclusive_end = AffectedRange("p:p [3.0.0,3.0.22]", "3.0.0", True, "3.0.22", True)
    assert inclusive_end.contains("3.0.22") is True
    assert inclusive_end.contains("3.0.23") is False
    exclusive_start = AffectedRange("p:p (2.0,)", "2.0", False, None, False)
    assert exclusive_start.contains("2.0.0") is False
    assert exclusive_start.contains("2.0.1") is True
    assert AffectedRange("p:p (,)", None, False, None, False).contains("99") is True  # every version
