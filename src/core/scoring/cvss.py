"""CVSS 3.1 base score from a vector, computed by code (ANA-13): the model never gives the number.

Only CVSS 3.1 base vectors are scored. A CVSS 4.0 vector or anything malformed returns None, which the scoring
engine treats as "no estimate" (S falls back to the conservative default, marked unrated).
"""

from __future__ import annotations

from decimal import ROUND_FLOOR, ROUND_HALF_UP, Decimal

_AV = {"N": Decimal("0.85"), "A": Decimal("0.62"), "L": Decimal("0.55"), "P": Decimal("0.2")}
_AC = {"L": Decimal("0.77"), "H": Decimal("0.44")}
_PR_UNCHANGED = {"N": Decimal("0.85"), "L": Decimal("0.62"), "H": Decimal("0.27")}
_PR_CHANGED = {"N": Decimal("0.85"), "L": Decimal("0.68"), "H": Decimal("0.5")}
_UI = {"N": Decimal("0.85"), "R": Decimal("0.62")}
_CIA = {"H": Decimal("0.56"), "L": Decimal("0.22"), "N": Decimal(0)}
_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_TEN = Decimal(10)
_ONE_DECIMAL = Decimal("0.1")


def parse_cvss31(vector: str) -> dict[str, str] | None:
    """The eight base metrics of a CVSS 3.1 vector in any order, each once with a valid value; else None."""
    parts = vector.split("/")
    if parts[0] != "CVSS:3.1":
        return None
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, _, value = part.partition(":")
        if key in metrics or key not in _METRICS or not value:
            return None
        metrics[key] = value
    if set(metrics) != set(_METRICS):
        return None
    tables = {"AV": _AV, "AC": _AC, "UI": _UI, "C": _CIA, "I": _CIA, "A": _CIA, "PR": _PR_UNCHANGED}
    if any(metrics[k] not in table for k, table in tables.items()) or metrics["S"] not in ("U", "C"):
        return None
    return metrics


def roundup(value: Decimal) -> Decimal:
    """CVSS 3.1 Roundup (appendix A): the smallest number with one decimal that is >= value, immune to float noise."""
    scaled = int((value * 100000).to_integral_value(rounding=ROUND_HALF_UP))
    if scaled % 10000 == 0:
        return (Decimal(scaled) / 100000).quantize(_ONE_DECIMAL)
    return ((Decimal(scaled) / 10000).to_integral_value(rounding=ROUND_FLOOR) / 10 + Decimal("0.1")).quantize(
        _ONE_DECIMAL
    )


def base_score(vector: str) -> Decimal | None:
    """The CVSS 3.1 base score (0.0 to 10.0) of a base vector, or None when it is not a valid 3.1 base vector."""
    metrics = parse_cvss31(vector)
    if metrics is None:
        return None
    changed = metrics["S"] == "C"
    iss = Decimal(1) - (Decimal(1) - _CIA[metrics["C"]]) * (Decimal(1) - _CIA[metrics["I"]]) * (
        Decimal(1) - _CIA[metrics["A"]]
    )
    if changed:
        impact = Decimal("7.52") * (iss - Decimal("0.029")) - Decimal("3.25") * (iss - Decimal("0.02")) ** 15
    else:
        impact = Decimal("6.42") * iss
    pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[metrics["PR"]]
    exploitability = Decimal("8.22") * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]
    if impact <= 0:
        return Decimal("0.0")
    total = impact + exploitability
    return roundup(min(total * (Decimal("1.08") if changed else 1), _TEN))
