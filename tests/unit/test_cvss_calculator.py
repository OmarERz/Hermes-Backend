"""CVSS 3.1 base scores against values published by FIRST/NVD."""

from __future__ import annotations

from decimal import Decimal

import pytest

from core.scoring.cvss import base_score, parse_cvss31, roundup


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "9.8"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "7.5"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "6.1"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "10.0"),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "7.8"),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", "1.6"),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", "9.9"),
        ("CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L", "5.0"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "0.0"),
        ("CVSS:3.1/S:U/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H", "9.8"),  # the order of the metrics does not matter
    ],
)
def test_published_scores(vector: str, score: str) -> None:
    assert base_score(vector) == Decimal(score)


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
        "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Z/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:",
    ],
)
def test_anything_that_is_not_a_base_31_vector_has_no_score(vector: str) -> None:
    assert parse_cvss31(vector) is None
    assert base_score(vector) is None


def test_roundup_follows_the_specification() -> None:
    assert roundup(Decimal("4.02")) == Decimal("4.1")
    assert roundup(Decimal("4.00")) == Decimal("4.0")
    assert roundup(Decimal("4.000001")) == Decimal("4.0")  # the specification's float-noise guard
    assert roundup(Decimal("0.1")) == Decimal("0.1")
    assert roundup(Decimal("9.91")) == Decimal("10.0")
