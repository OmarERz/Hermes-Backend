"""Read the editable parameters of docs/11 from the `setting_current` view."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


def get_setting(session: Session, key: str) -> Any:
    """Current value of a parameter; raises `KeyError` for a key that is not defined."""
    row = session.execute(text("SELECT value FROM setting_current WHERE setting_key = :key"), {"key": key}).first()
    if row is None:
        raise KeyError(key)
    return row[0]


def get_int(session: Session, key: str) -> int:
    return int(get_setting(session, key))


def get_decimal(session: Session, key: str) -> Decimal:
    return Decimal(str(get_setting(session, key)))
