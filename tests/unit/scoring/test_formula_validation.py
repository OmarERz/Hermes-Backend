"""FRO-05 validation of a formula version: ranges, rank-based monotonicity, decay and urgency bands."""

from __future__ import annotations

from decimal import Decimal

import pytest

from core.scoring.engine import Formula, FormulaError, default_formula

F = default_formula()
D = Decimal


def levels_with(factor: str, values: dict[str, Decimal]) -> dict[str, dict[str, Decimal]]:
    return {k: dict(v) for k, v in F.levels.items()} | {factor: values}


def test_key_order_never_hides_inverted_levels() -> None:
    """PoC 0.9 listed before KEV 0.8 is still rejected: monotonicity follows the rank, not the dict order."""
    inverted = {"public_poc": D("0.9"), "kev_or_exploited": D("0.8"), "epss_p90": D("0.5"), "other": D("0.2")}
    with pytest.raises(FormulaError, match="monotonic"):
        Formula(weights=F.weights, levels=levels_with("P", inverted))


def test_reordered_valid_levels_are_accepted() -> None:
    reordered = {"other": D("0.2"), "epss_p90": D("0.5"), "public_poc": D("0.75"), "kev_or_exploited": D("1.0")}
    assert Formula(weights=F.weights, levels=levels_with("P", reordered)).level("P", "other") == D("0.2")


def test_missing_or_extra_level_codes_are_rejected() -> None:
    with pytest.raises(FormulaError, match="exactly"):
        Formula(weights=F.weights, levels=levels_with("A", {"critical_exposed": D("1.0")}))
    with pytest.raises(FormulaError, match="exactly"):
        Formula(weights=F.weights, levels=levels_with("X", {"a": D("1")}))


def test_each_weight_stays_between_zero_and_one() -> None:
    weights = {"S": D("1.2"), "P": D("-0.2"), "T": D("0"), "A": D("0"), "D": D("0")}
    with pytest.raises(FormulaError, match="between 0 and 1"):
        Formula(weights=weights, levels=F.levels)


@pytest.mark.parametrize("floor", [79, 101])
def test_floor_range(floor: int) -> None:
    with pytest.raises(FormulaError, match="80 and 100"):
        Formula(weights=F.weights, levels=F.levels, kev_exposed_floor=floor)


@pytest.mark.parametrize("value", ["0.4", "1.1"])
def test_s_without_cvss_range(value: str) -> None:
    with pytest.raises(FormulaError, match=r"0\.5 and 1\.0"):
        Formula(weights=F.weights, levels=F.levels, s_without_cvss=D(value))


def test_dead_zone_range() -> None:
    with pytest.raises(FormulaError, match="dead zone"):
        Formula(weights=F.weights, levels=F.levels, dead_zone=11)


def test_decay_must_decrease_and_end_open() -> None:
    with pytest.raises(FormulaError, match="decrease"):
        Formula(weights=F.weights, levels=F.levels, decay=((7, D("0.5")), (None, D("0.9"))))
    with pytest.raises(FormulaError, match="open step"):
        Formula(weights=F.weights, levels=F.levels, decay=((7, D("1.0")), (30, D("0.5"))))


def test_urgency_bands_must_be_ordered() -> None:
    with pytest.raises(FormulaError, match="ordered"):
        Formula(weights=F.weights, levels=F.levels, urgency_bands={1: 50, 2: 75, 3: 20, 4: 0})


@pytest.mark.parametrize(
    "bands",
    [{1: 90, 2: 75, 3: 50, 5: 0}, {1: 90, 2: 75, 3: 50}, {1: 101, 2: 75, 3: 50, 4: 0}, {1: 90, 2: 75, 3: 50, 4: 10}],
)
def test_urgency_band_codes_and_thresholds(bands: dict[int, int]) -> None:
    with pytest.raises(FormulaError):
        Formula(weights=F.weights, levels=F.levels, urgency_bands=bands)


def test_every_factor_needs_its_levels() -> None:
    levels = {k: dict(v) for k, v in F.levels.items() if k != "P"}
    with pytest.raises(FormulaError, match="cover exactly the factors"):
        Formula(weights=F.weights, levels=levels)


@pytest.mark.parametrize(
    "decay",
    [((30, D("1.0")), (7, D("0.6")), (None, D("0.3"))), ((7, D("1.0")), (7, D("0.6")), (None, D("0.3")))],
)
def test_decay_limits_strictly_increase(decay: tuple[tuple[int | None, Decimal], ...]) -> None:
    with pytest.raises(FormulaError, match="strictly increasing"):
        Formula(weights=F.weights, levels=F.levels, decay=decay)
