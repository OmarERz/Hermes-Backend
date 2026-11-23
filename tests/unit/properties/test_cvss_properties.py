"""Properties of the CVSS 3.1 calculator against the invariants of the specification (ANA-13)."""

from __future__ import annotations

import random
from decimal import Decimal

from hypothesis import assume, given
from hypothesis import strategies as st

from core.scoring.cvss import _METRICS, base_score, parse_cvss31, roundup

# Values of every metric from the lowest to the highest effect on the score.
ORDER = {
    "AV": "PLAN",  # physical < local < adjacent < network
    "AC": "HL",  # the attack is easier at L
    "PR": "HLN",
    "UI": "RN",
    "C": "NLH",
    "I": "NLH",
    "A": "NLH",
}
metric_values = {
    "AV": "NALP",
    "AC": "LH",
    "PR": "NLH",
    "UI": "NR",
    "S": "UC",
    "C": "HLN",
    "I": "HLN",
    "A": "HLN",
}
vectors = st.fixed_dictionaries({key: st.sampled_from(values) for key, values in metric_values.items()})
TENTH = Decimal("0.1")


def render(metrics: dict[str, str]) -> str:
    return "CVSS:3.1/" + "/".join(f"{key}:{metrics[key]}" for key in _METRICS)


def score(metrics: dict[str, str]) -> Decimal:
    value = base_score(render(metrics))
    assert value is not None
    return value


@given(vectors)
def test_the_score_is_between_0_and_10_with_one_decimal(metrics: dict[str, str]) -> None:
    value = score(metrics)
    assert Decimal(0) <= value <= Decimal(10)
    assert value == value.quantize(TENTH)


@given(vectors)
def test_the_vector_round_trips_through_the_parser(metrics: dict[str, str]) -> None:
    assert parse_cvss31(render(metrics)) == metrics


@given(vectors, st.randoms(use_true_random=False))
def test_the_order_of_the_metrics_does_not_matter(metrics: dict[str, str], rnd: random.Random) -> None:
    keys = list(_METRICS)
    rnd.shuffle(keys)
    shuffled = "CVSS:3.1/" + "/".join(f"{k}:{metrics[k]}" for k in keys)
    assert base_score(shuffled) == score(metrics)


@given(vectors, st.sampled_from(sorted(ORDER)))
def test_a_worse_metric_never_lowers_the_score(metrics: dict[str, str], name: str) -> None:
    ranking = ORDER[name]
    position = ranking.index(metrics[name])
    assume(position + 1 < len(ranking))
    assert score({**metrics, name: ranking[position + 1]}) >= score(metrics)


@given(vectors)
def test_no_impact_means_a_zero_score_and_only_then(metrics: dict[str, str]) -> None:
    no_impact = all(metrics[k] == "N" for k in "CIA")
    assert (score(metrics) == Decimal("0.0")) is no_impact


@given(vectors)
def test_the_worst_vector_scores_ten_and_nothing_beats_it(metrics: dict[str, str]) -> None:
    worst = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"}
    assert score(worst) == Decimal("10.0")
    assert score(metrics) <= Decimal("10.0")


@given(st.decimals(min_value=0, max_value=11, places=6, allow_nan=False, allow_infinity=False))
def test_roundup_is_the_smallest_tenth_not_below_the_value(value: Decimal) -> None:
    rounded = roundup(value)
    assert rounded == rounded.quantize(TENTH)
    assert rounded >= value - Decimal("0.00001")
    assert rounded - value < Decimal("0.10001")


@given(st.text(max_size=80))
def test_arbitrary_text_is_never_scored_by_accident(text: str) -> None:
    value = base_score(text)
    assert value is None or (parse_cvss31(text) is not None and Decimal(0) <= value <= Decimal(10))
