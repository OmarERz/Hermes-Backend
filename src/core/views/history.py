"""Score history of one finding (EVA-05): its CI's score in every assessment of its group, oldest first."""

from __future__ import annotations

import uuid

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.mitigation.history import HistoryPoint, score_history

_FINDING = text(
    "SELECT f.finding_group_id, i.asset_id FROM finding f "
    "JOIN installed_software i ON i.id = f.installed_software_id WHERE f.id = :finding_id"
)


def finding_history(session: Session, finding_id: uuid.UUID) -> list[HistoryPoint] | None:
    """None if the finding does not exist; a decommissioned CI keeps its history."""
    found = session.execute(_FINDING, {"finding_id": finding_id}).one_or_none()
    if found is None:
        return None
    return score_history(session, finding_group_id=found.finding_group_id, asset_id=found.asset_id)
