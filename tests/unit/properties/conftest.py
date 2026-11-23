"""Hypothesis profile of the property tests (F12.4): deterministic, bounded and free of wall-clock deadlines."""

from __future__ import annotations

from hypothesis import HealthCheck, settings

settings.register_profile(
    "hermes",
    max_examples=150,
    deadline=None,  # CI machines vary; the bound is the number of examples, not the time of each
    derandomize=True,  # the same examples on every run: a failure reproduces anywhere
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("hermes")
