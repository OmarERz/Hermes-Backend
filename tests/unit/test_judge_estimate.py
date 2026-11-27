"""FRO-04: rescaling stored judge points to another sensitivity profile (docs/07 §12, ROUND_HALF_UP)."""

from __future__ import annotations

import pytest

from core.configuration.judge_estimate import _profile_of, rescale
from core.judge.catalog import ProfileName, SensitivityProfile

MINIMAL, NORMAL, BROAD = (SensitivityProfile.named(p.value) for p in ProfileName)


@pytest.mark.parametrize(
    ("points", "applied_with", "proposed", "expected"),
    [
        (8, NORMAL, BROAD, 12),
        (8, NORMAL, MINIMAL, 4),
        (7, NORMAL, MINIMAL, 4),  # 3.5 rounds half away from zero
        (-7, NORMAL, MINIMAL, -4),
        (4, MINIMAL, BROAD, 12),
        (12, BROAD, NORMAL, 8),
        (5, NORMAL, NORMAL, 5),
    ],
)
def test_rescale(points: int, applied_with: SensitivityProfile, proposed: SensitivityProfile, expected: int) -> None:
    assert rescale(points, applied_with, proposed) == expected


@pytest.mark.parametrize(
    ("parameters", "expected"),
    [({"profile": "broad"}, BROAD), ({}, NORMAL), (None, NORMAL), ({"profile": "wild"}, NORMAL), ("x", NORMAL)],
)
def test_profile_of_a_review(parameters: object, expected: SensitivityProfile) -> None:
    assert _profile_of(parameters) == expected
