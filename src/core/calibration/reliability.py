"""Source reliability from resolved claims and the level changes it suggests (docs/09 §2, L6).

score = (confirmed + 2) / (confirmed + refuted + 4) over the claims resolved in the window; a level change is
suggested only with enough resolved claims (default 20) and crossing the raise (0.85) or lower (0.5) threshold. One
level at a time; N1 is reserved for the official sources, so a source is never proposed to N1 and structural sources
are never touched.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Final

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.calibration.settings import CalibrationSettings
from core.db import models as m

TIERS: Final = ("N1", "N2", "N3", "N4")
TWO: Final = Decimal(2)
FOUR: Final = Decimal(4)


@dataclass(frozen=True)
class SourceScore:
    code: str
    name: str
    tier: str
    confirmed: int
    refuted: int

    @property
    def resolved(self) -> int:
        return self.confirmed + self.refuted

    @property
    def score(self) -> Decimal:
        return (Decimal(self.confirmed) + TWO) / (Decimal(self.resolved) + FOUR)


@dataclass(frozen=True)
class TierSuggestion:
    source: SourceScore
    proposed_tier: str


def source_scores(session: Session, now: datetime, window_days: int) -> list[SourceScore]:
    since = now - timedelta(days=window_days)
    rows = session.execute(
        select(
            m.Source.code,
            m.Source.name,
            m.Source.trust_tier,
            func.count().filter(m.Claim.status == "confirmed"),
            func.count().filter(m.Claim.status == "refuted"),
        )
        .join(m.Claim, m.Claim.source_id == m.Source.id)
        .where(m.Source.is_structural.is_(False), m.Claim.resolved_at >= since, m.Claim.status != "pending")
        .group_by(m.Source.code, m.Source.name, m.Source.trust_tier)
        .order_by(m.Source.code)
    )
    return [SourceScore(code, name, tier, int(c), int(r)) for code, name, tier, c, r in rows]


def suggest_tiers(scores: list[SourceScore], settings: CalibrationSettings) -> list[TierSuggestion]:
    suggestions: list[TierSuggestion] = []
    for item in scores:
        if item.resolved < settings.min_resolved or item.tier not in TIERS:
            continue
        position = TIERS.index(item.tier)
        if item.score >= settings.raise_at and position > 1:  # up to N2 at most: N1 is for official sources
            suggestions.append(TierSuggestion(item, TIERS[position - 1]))
        elif item.score <= settings.lower_at and 0 < position < len(TIERS) - 1:
            suggestions.append(TierSuggestion(item, TIERS[position + 1]))
    return suggestions
