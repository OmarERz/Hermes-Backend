"""Numbers read from headers, keys and JSON strings: ASCII digits only, never a crash (F12.5)."""

from __future__ import annotations

import re

from hypothesis import given
from hypothesis import strategies as st

from core.configuration.errors import ValidationFailedError
from core.configuration.formula_store import apply_changes
from core.scoring.engine import default_formula
from core.textnum import ascii_int, retry_after_seconds

OTHER = "\u0660\u0661\u0662\u0663\u0664\u0966\u0967\u0968\u0e50\u0e51\uff10\uff11\uff12\uff13\u00b2\u00b3\u2460"
other_digits = st.text(alphabet=OTHER, min_size=1, max_size=7)
ascii_digits = st.text(alphabet="0123456789", min_size=4, max_size=7)
mixed = st.tuples(ascii_digits, st.integers(min_value=0, max_value=3), st.sampled_from(OTHER)).map(
    lambda t: t[0][: t[1]] + t[2] + t[0][t[1] :]  # a number with one foreign digit somewhere inside it
)


@given(st.text(max_size=12))
def test_ascii_int_agrees_with_a_plain_ascii_digit_check(text: str) -> None:
    expected = int(text) if text and re.fullmatch(r"[0-9]+", text) else None
    assert ascii_int(text) == expected


@given(other_digits)
def test_ascii_int_never_raises_on_digits_that_int_rejects(text: str) -> None:
    assert ascii_int(text) is None
    assert ascii_int(text + "1") is None


@given(st.text(max_size=12))
def test_retry_after_is_a_finite_non_negative_number_or_nothing(raw: str) -> None:
    seconds = retry_after_seconds(raw, maximum=300.0)
    assert seconds is None or 0.0 <= seconds <= 300.0


@given(
    st.sampled_from(["nan", "NaN", "inf", "-inf", "infinity", "1e9", "-5", "\u0663", "\u00b2", "1,5", ".5", "5.", ""])
)
def test_hostile_retry_after_values_are_ignored(raw: str) -> None:
    assert retry_after_seconds(raw, maximum=300.0) is None


@given(st.integers(min_value=0, max_value=10**6), st.integers(min_value=0, max_value=999))
def test_a_valid_retry_after_is_kept_and_capped(whole: int, fraction: int) -> None:
    assert retry_after_seconds(str(whole), maximum=300.0) == min(float(whole), 300.0)
    assert retry_after_seconds(f"{whole}.{fraction}") == float(f"{whole}.{fraction}")


@given(other_digits, st.sampled_from(["bands", "decay"]))
def test_a_formula_key_with_other_digits_is_an_unknown_parameter_not_a_crash(bad: str, family: str) -> None:
    key = f"bands.{bad}" if family == "bands" else f"decay.{bad}.multiplier"
    try:
        apply_changes(default_formula(), {key: "50"})
    except ValidationFailedError as error:
        assert any(problem.issue == "unknown_parameter" for problem in error.problems)
    else:
        raise AssertionError("the key must be refused")
