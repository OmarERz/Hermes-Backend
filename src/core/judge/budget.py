"""Judge budget (L12, docs/09 §4): per-review token caps by complexity, daily gate and cost at today's price.

The daily budget and the critical reserve live in the shared budget policy (F3.1, `core.validation.budget`); the
judge depends on the `DailyBudget` protocol and `LedgerDailyBudget` adapts that policy to it. Budget is checked
between turns, never in the middle of a response, and a review that runs out closes as `partial_review` with what
was accepted.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import Protocol

from core.judge.catalog import TokenCaps
from core.judge.package import ReviewPackage
from core.llm import Usage
from core.validation.budget import BudgetConfig, can_start

COMPLEX_NEWS = 3
COMPLEX_CIS = 10
COMPLEX_DESCRIPTION_CHARS = 2000
MILLION = Decimal(1_000_000)
COST_QUANTUM = Decimal("0.000001")  # llm_review.cost_usd is numeric(10,6)


class DailyBudget(Protocol):
    def allows(self, *, critical: bool, pending_usd: Decimal = Decimal(0)) -> bool:
        """Whether the day's budget (with the 20% critical reserve, P-015) still allows a judge turn, counting
        `pending_usd`: what the review in progress already spent and is not yet stored in `llm_review`."""
        ...


class UnlimitedDailyBudget:
    """No daily limit: for tests and tools only; production wires `LedgerDailyBudget`."""

    def allows(self, *, critical: bool, pending_usd: Decimal = Decimal(0)) -> bool:
        return True


@dataclass(frozen=True)
class OffsetDailyBudget:
    """A daily budget that also counts what the day's reading does not include: reviews that ran but are not stored
    yet (the first of a double review, docs/07 §6), and reviews the same caller stored after the day's spending was
    read (an evaluation that judges a changed package again, F12.2 #105)."""

    inner: DailyBudget
    already_usd: Decimal

    def allows(self, *, critical: bool, pending_usd: Decimal = Decimal(0)) -> bool:
        return self.inner.allows(critical=critical, pending_usd=pending_usd + self.already_usd)


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
# TODO(P-015): conservative provisional price (USD per million tokens) used while `model_prices` has no entry for
# the model, so the daily budget still advances; deliberately above the published DeepSeek prices ⚠️ (verify).
FALLBACK_PRICE = ModelPrice(input=Decimal(2), cached_input=Decimal("0.5"), output=Decimal(8))


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


# TODO(P-015): one judge turn is estimated at this size until the test bench measures it (docs/09 §4.1).
TURN_ESTIMATE = Usage(input=12_000, cached_input=0, output=1_500, reasoning=0)


class LedgerDailyBudget:
    """`DailyBudget` over the shared daily policy (F3.1): what the day already spent, read through `spent` (the
    `llm_usage_daily` view), plus the estimated cost of the next turn must fit the day's limit; only critical
    packages (KEV, R1, exposed CI) may use the reserve (docs/09 §4, P-015)."""

    def __init__(self, spent: Callable[[], Decimal], config: BudgetConfig, turn_estimate_usd: Decimal) -> None:
        self._spent = spent
        self._config = config
        self._estimate = turn_estimate_usd

    def allows(self, *, critical: bool, pending_usd: Decimal = Decimal(0)) -> bool:
        return can_start(self._config, self._spent() + pending_usd, self._estimate, critical)
