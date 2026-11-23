"""Factory dedup thresholds (docs/02 §4, 23 nov 2026): calibrated for multilingual-e5-small, where two distinct
security stories reached 0.86 and the same story 0.88 to 0.94. A fresh database gets these; an existing one keeps the
values it stored (the bootstrap seeds only a database without a formula)."""

from __future__ import annotations

from decimal import Decimal

import pytest

from core.db.seeds import SETTINGS

pytestmark = pytest.mark.unit


def test_the_factory_dedup_thresholds() -> None:
    defaults = {key: Decimal(str(default)) for key, _g, _t, default, *_ in SETTINGS if key.startswith("dedup.")}
    assert defaults["dedup.similarity"] == Decimal("0.90")
    assert defaults["dedup.gray_zone"] == Decimal("0.84")
    assert Decimal("0.86") < defaults["dedup.similarity"]  # the measured distinct-story pair stays apart
    assert defaults["dedup.gray_zone"] < defaults["dedup.similarity"]
