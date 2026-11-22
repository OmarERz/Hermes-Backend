"""Daily LLM budget (docs/09 §4, L12).

- A daily limit (`daily_budget_usd`) with a reserve (`critical_reserve`) that only critical packages (KEV, R1,
  exposed CI) may use; they may also use up to 2x the normal token cap.
- Work is never cut in the middle of an answer: the budget is checked between turns, before starting one.
- When a piece cannot run, it falls back (analyst: unanalyzed in the queue; CVE analyst: unrated; judge: base only).
- With little budget left, critical work goes first.

Money is `Decimal`. Token caps are provisional until the bench measures them (cap = 1.5 x p99, `TODO(P-015)`).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import text
from sqlalchemy.orm import Session

NORMAL = "normal"
COMPLEX = "complex"

# What to do when a piece cannot run: the state it is left in (docs/09 §4).
FALLBACKS = {"news_analyst": "unanalyzed", "cve_analyst": "unrated", "judge": "no_judge_review"}

# TODO(P-015): provisional, generous caps in output tokens per answer, replaced by 1.5 x p99 from the bench.
DEFAULT_TOKEN_CAPS = {
    ("news_analyst", NORMAL): 4_000,
    ("news_analyst", COMPLEX): 12_000,
    ("cve_analyst", NORMAL): 3_000,
    ("cve_analyst", COMPLEX): 9_000,
    ("judge", NORMAL): 6_000,
    ("judge", COMPLEX): 18_000,
}


@dataclass(frozen=True)
class BudgetConfig:
    daily_usd: Decimal = Decimal(5)
    critical_reserve: Decimal = Decimal("0.20")
    critical_multiplier: int = 2
    warning_ratio: Decimal = Decimal("0.80")
    token_caps: dict[tuple[str, str], int] = field(default_factory=lambda: dict(DEFAULT_TOKEN_CAPS))
    complex_news: int = 5  # linked news items
    complex_advisory_chars: int = 20_000
    complex_assets: int = 10
    complex_second_review: Decimal = Decimal("0.5")  # probability of a double review


def classify(
    config: BudgetConfig, linked_news: int, advisory_chars: int, assets: int, second_review_probability: Decimal
) -> str:
    """`complex` when any size signal passes its threshold, else `normal` (estimated before the work starts)."""
    heavy = (
        linked_news > config.complex_news
        or advisory_chars > config.complex_advisory_chars
        or assets > config.complex_assets
        or second_review_probability >= config.complex_second_review
    )
    return COMPLEX if heavy else NORMAL


def token_cap(config: BudgetConfig, piece: str, complexity: str, critical: bool) -> int:
    cap = config.token_caps[(piece, complexity)]
    return cap * config.critical_multiplier if critical else cap


def limit_usd(config: BudgetConfig, critical: bool) -> Decimal:
    """What may be spent in the day: everything for critical work, the day minus the reserve for the rest."""
    return config.daily_usd if critical else config.daily_usd * (Decimal(1) - config.critical_reserve)


def can_start(config: BudgetConfig, spent_usd: Decimal, estimated_usd: Decimal, critical: bool) -> bool:
    """True when the next piece of work (or turn) fits in what is left of the budget."""
    return spent_usd + estimated_usd <= limit_usd(config, critical)


def warning(config: BudgetConfig, spent_usd: Decimal) -> bool:
    """True from 80% of the daily budget: the administrator is warned (docs/15 F-19)."""
    return spent_usd >= config.daily_usd * config.warning_ratio


def next_turn(config: BudgetConfig, spent_usd: Decimal, estimated_usd: Decimal, critical: bool) -> str:
    """Between turns: `continue`, or `partial_review` to close the review with the reasons already accepted."""
    return "continue" if can_start(config, spent_usd, estimated_usd, critical) else "partial_review"


@dataclass(frozen=True)
class WorkItem:
    key: str
    critical: bool
    created_at: datetime


def prioritize(items: Sequence[WorkItem]) -> list[WorkItem]:
    """Critical first, then oldest first."""
    return sorted(items, key=lambda item: (not item.critical, item.created_at, item.key))


def spent_on(session: Session, day: date) -> Decimal:
    """Cost in USD of the day's reviews, from the `llm_usage_daily` view (UTC days)."""
    value = session.execute(
        text("SELECT coalesce(sum(cost_usd), 0) FROM llm_usage_daily WHERE usage_date = :day"), {"day": day}
    ).scalar_one()
    return Decimal(value)
