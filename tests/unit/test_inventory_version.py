"""Version normalization (ESC-08)."""

from __future__ import annotations

import pytest

from core.inventory.version import NormalizedVersion, normalize_version


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("7.2.4-1ubuntu0.2", ("7.2.4", "7.2.4-1ubuntu0.2")),
        ("1.24.0", ("1.24.0", None)),
        ("  15.4 ", ("15.4", None)),
        ("1:2.3.4-1", ("2.3.4", "1:2.3.4-1")),
        ("1:2.3.4", ("2.3.4", "1:2.3.4")),
        ("3.0.2-0ubuntu1.12", ("3.0.2", "3.0.2-0ubuntu1.12")),
        ("2.4.57-2.el9", ("2.4.57", "2.4.57-2.el9")),
        ("2.0.0-rc1", ("2.0.0-rc1", None)),  # a pre-release is not a distribution revision
        ("1.2.3+dfsg-1", ("1.2.3+dfsg", "1.2.3+dfsg-1")),
        ("v1.2", ("v1.2", None)),
    ],
)
def test_normalize(raw: str, expected: tuple[str, str | None]) -> None:
    assert normalize_version(raw) == NormalizedVersion(*expected)


@pytest.mark.parametrize("raw", ["", "   "])
def test_blank_has_no_version(raw: str) -> None:
    assert normalize_version(raw) is None
