"""Version comparison (ESC-13) and range membership."""

from __future__ import annotations

import pytest

from core.scan.versions import compare_versions, in_range, parse_version


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
