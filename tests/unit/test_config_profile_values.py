"""The values each sensitivity profile sets, as GET /api/config/schema publishes them (docs/07 §12, F18.6)."""

from __future__ import annotations

import pytest

from core.configuration.service import option_values_of, profile_values
from core.judge.catalog import PROFILES

pytestmark = pytest.mark.unit


def test_each_profile_publishes_the_values_the_judge_applies() -> None:
    assert profile_values("minimal") == {
        "judge.range_multiplier": "0.5",
        "judge.allow_lowering": "false",
        "dead_zone": "6",
        "mode2.min_confidence": "0.8",
    }
    assert profile_values("normal") == {
        "judge.range_multiplier": "1",
        "judge.allow_lowering": "true",
        "dead_zone": "4",
        "mode2.min_confidence": "0.6",
    }
    assert profile_values("broad")["judge.range_multiplier"] == "1.5"
    for name, profile in PROFILES.items():  # read from the judge's own table, so they never diverge
        assert int(profile_values(name)["dead_zone"]) == profile.dead_zone


def test_only_the_sensitivity_profile_has_option_values_and_unknown_options_have_none() -> None:
    assert option_values_of("notifications.consumer", ["log", "slack"]) == {}
    values = option_values_of("sensitivity_profile", ["broad", "huge", "normal"])
    assert sorted(values) == ["broad", "normal"]  # an option the judge does not know has nothing to show
