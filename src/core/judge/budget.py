"""Judge budget (L12, docs/09 §4): per-review token caps by complexity, daily gate and cost at today's price.

The daily budget and the critical reserve live in the shared budget policy (F3.1); the judge depends only on the
`DailyBudget` protocol so that policy plugs in without changes here. Budget is checked between turns, never in
the middle of a response, and a review that runs out closes as `partial_review` with what was accepted.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Protocol

from core.judge.catalog import TokenCaps
from core.judge.package import ReviewPackage
from core.llm import Usage

COMPLEX_NEWS = 3
COMPLEX_CIS = 10
COMPLEX_DESCRIPTION_CHARS = 2000
MILLION = Decimal(1_000_000)
COST_QUANTUM = Decimal("0.000001")  # llm_review.cost_usd is numeric(10,6)


class DailyBudget(Protocol):
    def allows(self, *, critical: bool) -> bool:
        """Whether the day's budget (with the 20% critical reserve, P-015) still allows a judge turn."""
        ...


class UnlimitedDailyBudget:
    """Placeholder until the shared daily budget policy is wired in (TODO(P-015): USD 5 a day, 20% critical)."""

    def allows(self, *, critical: bool) -> bool:
        return True


@dataclass(frozen=True)
class ModelPrice:
    """USD per million tokens (setting `model_prices`, MET-17)."""

    input: Decimal
    cached_input: Decimal
    output: Decimal

    def cost(self, usage: Usage) -> Decimal:
        uncached = max(usage.input - usage.cached_input, 0)
        total = (
            Decimal(uncached) * self.input
            + Decimal(usage.cached_input) * self.cached_input
            + Decimal(usage.output + usage.reasoning) * self.output
        ) / MILLION
        return total.quantize(COST_QUANTUM)


FREE = ModelPrice(Decimal(0), Decimal(0), Decimal(0))


def complexity(package: ReviewPackage) -> str:
    """'normal' or 'complex', estimated before starting (docs/09 §4.2)."""
    cve = package.cve_data
    long_advisory = cve is not None and len(str(cve["description"])) > COMPLEX_DESCRIPTION_CHARS
    many = len(package.news_elements) >= COMPLEX_NEWS or len(package.cis) >= COMPLEX_CIS
    return "complex" if long_advisory or many else "normal"


def token_cap(package: ReviewPackage, caps: TokenCaps) -> int:
    """Token cap of one review: by complexity; KEV, R1 or an exposed CI may use up to 2x the normal cap (§4.5)."""
    cap = caps.complex if complexity(package) == "complex" else caps.normal
    return max(cap, caps.normal * caps.critical_multiplier) if package.is_critical else cap
