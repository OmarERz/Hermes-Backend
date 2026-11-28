"""Version comparison (ESC-13) and range membership."""

from __future__ import annotations

import pytest

from core.scan.versions import bound_order, compare_versions, in_range, known_order, parse_version, release_of


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1.2.10", "1.2.9", 1),
        ("1.2.9", "1.2.10", -1),
        ("1.0", "1.0.0", 0),
        ("v2.0", "2.0.0", 0),
        ("2.0.0-rc1", "2.0.0", -1),
        ("2.0.0-rc2", "2.0.0-rc10", -1),
        ("2.0.0-beta1", "2.0.0-rc1", -1),
        ("2.0.0-alpha", "2.0.0-beta", -1),
        ("2.0.0-p1", "2.0.0", 1),
        ("2.0.0.post2", "2.0.0.post10", -1),
        ("3.0.2", "3.0.2", 0),
        ("1.24.0", "1.25.3", -1),
        ("10", "9.9.9", 1),
        ("1.0.0.1", "1.0.0", 1),
    ],
)
def test_compare(left: str, right: str, expected: int) -> None:
    assert compare_versions(left, right) == expected


@pytest.mark.parametrize(
    "raw", ["", "unknown", "latest", "1.2.x-weird.label.9", "1.2.3 beta", "a.b.c", "1.0-foo", "x" * 101]
)
def test_incomparable_versions_return_none(raw: str) -> None:
    assert parse_version(raw) is None
    assert compare_versions(raw, "1.0") is None
    assert compare_versions("1.0", raw) is None


def test_range_membership() -> None:
    # 1.20.0 <= v < 1.25.3
    assert in_range("1.24.0", "1.20.0", True, "1.25.3", False) is True
    assert in_range("1.25.3", "1.20.0", True, "1.25.3", False) is False
    assert in_range("1.20.0", "1.20.0", True, "1.25.3", False) is True
    assert in_range("1.20.0", "1.20.0", False, "1.25.3", False) is False
    assert in_range("1.19.9", "1.20.0", True, "1.25.3", False) is False
    assert in_range("1.25.3", None, None, "1.25.3", True) is True
    assert in_range("9.9", None, None, None, None) is True  # a range with no bounds covers every version
    assert in_range("1.18.0", "1.18.0", True, "1.18.0", True) is True


def test_range_with_an_incomparable_version_is_unknown() -> None:
    assert in_range("weird", "1.0", True, None, None) is None
    assert in_range("1.0", None, None, "latest", False) is None


@pytest.mark.parametrize(
    ("raw", "release"),
    [
        ("3.0.18", (3, 0, 18)),
        ("1.1.1zd", (1, 1, 1)),  # an OpenSSL letter release the scale cannot place
        ("V1.0.2ZM", (1, 0, 2)),
        ("1.1.0zd", (1, 1)),  # trailing zeros do not count, as in parse_version
        ("2.0.0-rc1", (2,)),
        ("1.2x", None),  # a wildcard names a line, not one version
        ("1.2.x", None),
        ("3.0.23-fips", None),  # an unknown label after a separator stays unknown
        ("3.0.22fips", None),  # a word glued to the numbers is no OpenSSL letter release
        ("1.1.1zzz", None),
        ("3.0.11-1~deb12u2", None),
        ("latest", None),
        ("1" + "a" * 100, None),  # too long, as in parse_version
    ],
)
def test_release_of_reads_numbers_before_an_unknown_letter_suffix(raw: str, release: tuple[int, ...] | None) -> None:
    assert release_of(raw) == release


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("3.0.18", "1.1.1zd", 1),  # the release decides, whatever "zd" means
        ("1.1.1zd", "3.0.18", -1),
        ("1.0.2zm", "1.1.1", -1),
        ("1.1.1w", "1.1.1w", 0),  # the same text is the same version
        ("v1.1.1W", "1.1.1w", 0),
        ("3.0.23-fips", "3.0.23-FIPS", 0),
        ("1.1.1w", "1.1.1zd", None),  # same release, letters off the scale: unknown
        ("1.1.1", "1.1.1w", None),
        ("1.1.1-rc1", "1.1.1w", None),
        ("3.0.23-fips", "3.0.0", None),  # not a letter release: never guessed
        ("3.0.22fips", "3.0.21", None),
        ("1.2.x", "1.3.0", None),
        ("3.0.18", "latest", None),
        ("2.0.0-rc1", "2.0.0", -1),  # readable versions keep the comparator's order
    ],
)
def test_known_order_decides_only_what_the_scale_decides(left: str, right: str, expected: int | None) -> None:
    assert known_order(left, right) == expected


# --- F15.9: CVE JSON 5 wildcard bounds ('6.1.*' names the whole 6.1 line) -----------------------------------------
@pytest.mark.parametrize(
    ("version", "bound", "expected"),
    [
        ("6.1.0", "6.1.*", 0),
        ("6.1.192", "6.1.*", 0),
        ("6.1", "6.1.*", 0),
        ("6.2", "6.1.*", 1),
        ("6.2-rc1", "6.1.*", 1),
        ("6.0.99", "6.1.*", -1),
        ("5.10.274", "5.10.*", 0),
        ("6", "6.0.*", 0),  # trailing zeros: 6 is 6.0
        ("7.0.1", "6.*", 1),
        ("2.4.58", "2.4.x", 0),
        ("6.1.0", "6.1.0", 0),  # a plain bound is the comparator's own order
        ("6.1.0", "6.1.1", -1),
        ("latest", "6.1.*", None),
        ("6.1.0", "*", None),  # a lone '*' is no bound: the parser turns it into an open side
    ],
)
def test_bound_order_reads_wildcard_lines(version: str, bound: str, expected: int | None) -> None:
    assert bound_order(version, bound) == expected


def test_wildcard_bounds_in_ranges() -> None:
    """The kernel CNA writes fixed lines as `6.1.192 <= v <= 6.1.*` and the affected gap after one as `(6.1.*, ...)`."""
    assert in_range("6.1.200", "6.1.192", True, "6.1.*", True) is True
    assert in_range("6.2.0", "6.1.192", True, "6.1.*", True) is False
    assert in_range("6.1.0", "6.1.*", False, "6.6.162", False) is False  # inside the 6.1 line, not after it
    assert in_range("6.2.0", "6.1.*", False, "6.6.162", False) is True
    assert in_range("6.6.162", "6.1.*", False, "6.6.162", False) is False
    assert in_range("6.1.0", "5.15.*", False, "6.1.192", False) is True
    assert in_range("6.1.0", "6.1.*", True, None, None) is True
    assert in_range("6.1.0", "x.*", True, None, None) is None  # an unreadable bound is never guessed
