"""Properties of the engine over generated inputs (EVA-10, docs/14): bounded, monotonic, exact breakdown."""

from __future__ import annotations

from decimal import Decimal

from hypothesis import given
from hypothesis import strategies as st

from core.scoring.engine import Factors, base_score, default_formula, delta_breakdown, final_score

F = default_formula()
unit = st.decimals(min_value=0, max_value=1, places=4, allow_nan=False, allow_infinity=False)
factors = st.builds(Factors, unit, unit, unit, unit, unit)
adjustment = st.one_of(st.none(), st.integers(min_value=-40, max_value=40))


@given(factors, adjustment, st.integers(min_value=-20, max_value=20), st.booleans())
def test_scores_stay_between_0_and_100(f: Factors, judge: int | None, ci: int, floor: bool) -> None:
    base = base_score(F, f)
    assert 0 <= base <= 100
    assert 0 <= final_score(F, base, judge_adjustment=judge, ci_adjustment=ci, floor=floor).final <= 100


@given(factors, st.sampled_from(["s", "p", "t", "a", "d"]), unit)
def test_base_is_monotonic_in_every_factor(f: Factors, name: str, delta: Decimal) -> None:
    raised = getattr(f, name) + delta
    bigger = Factors(**{**f.__dict__, name: min(raised, Decimal(1))})
    assert base_score(F, bigger) >= base_score(F, f)


@given(factors, adjustment, st.booleans())
def test_breakdown_reconstructs_the_final(f: Factors, judge: int | None, floor: bool) -> None:
    base = base_score(F, f)
    result = final_score(F, base, judge_adjustment=judge, floor=floor)
    assert delta_breakdown(F, f, result, base).total() == Decimal(result.final)
