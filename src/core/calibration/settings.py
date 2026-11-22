"""The calibration parameters of docs/11 (read from `setting_current`)."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from sqlalchemy.orm import Session

from core.ingestion.settings import get_decimal, get_int


@dataclass(frozen=True)
class CalibrationSettings:
    weekly_limit: Decimal  # largest relative change of a parameter per week (+/-)
    cooldown_weeks: int  # the same parameter does not change more than once in this time
    block_weeks: int  # a reverted change stays blocked this long
    window_days: int  # reliability window
    min_resolved: int  # resolved claims needed before a source level is proposed
    raise_at: Decimal
    lower_at: Decimal


def load_settings(session: Session) -> CalibrationSettings:
    return CalibrationSettings(
        weekly_limit=get_decimal(session, "mode4.weekly_limit"),
        cooldown_weeks=get_int(session, "mode4.cooldown_weeks"),
        block_weeks=get_int(session, "mode4.block_weeks"),
        window_days=get_int(session, "reliability.window_days"),
        min_resolved=get_int(session, "reliability.min_resolved"),
        raise_at=get_decimal(session, "reliability.raise"),
        lower_at=get_decimal(session, "reliability.lower"),
    )
