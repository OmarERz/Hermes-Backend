"""FIRST EPSS client and loader (ESC-09, EVA scoring input).

`GET https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B` answers `{"status": "OK", "data": [{"cve", "epss",
"percentile", "date"}]}` with the numbers as strings (verified against the live API on 22 Nov 2026). Requests are
batched so the URL stays short. Only CVEs already in `cve` are stored: a score for a CVE we do not track is of
no use. One row per CVE and day (`epss_score` is a daily series).
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db import models as m
from core.vulndata.http import JsonSource, SourceUnavailableError
from core.vulndata.records import CVE_ID

EPSS_URL: Final = "https://api.first.org/data/v1/epss"
BATCH_SIZE: Final = 100
FIVE_PLACES: Final = Decimal("0.00001")


@dataclass
class EpssResult:
    stored: int = 0
    skipped: int = 0


def _batches(ids: Sequence[str]) -> Iterator[Sequence[str]]:
    for start in range(0, len(ids), BATCH_SIZE):
        yield ids[start : start + BATCH_SIZE]


def _unit(raw: object) -> Decimal | None:
    try:
        value = Decimal(str(raw))
    except ArithmeticError:
        return None
    return value.quantize(FIVE_PLACES) if value.is_finite() and Decimal(0) <= value <= Decimal(1) else None


def fetch_scores(source: JsonSource, cve_ids: Sequence[str], url: str = EPSS_URL) -> list[dict[str, Any]]:
    """The `data` rows for the CVEs, one request per batch of 100."""
    rows: list[dict[str, Any]] = []
    for batch in _batches([c for c in cve_ids if CVE_ID.match(c)]):
        body = source.get(url, params={"cve": ",".join(batch), "limit": BATCH_SIZE})
        if not isinstance(body, dict) or not isinstance(body.get("data"), list):
            raise SourceUnavailableError("incomplete EPSS answer")
        rows.extend(r for r in body["data"] if isinstance(r, dict))
    return rows


def load_epss(session: Session, rows: list[dict[str, Any]]) -> EpssResult:
    """Upsert score rows for the CVEs we hold. The caller owns the transaction."""
    result = EpssResult()
    known = set(session.scalars(select(m.Cve.id)))
    for raw in rows:
        cve_id, epss, percentile = raw.get("cve"), _unit(raw.get("epss")), _unit(raw.get("percentile"))
        try:
            day = date.fromisoformat(str(raw.get("date")))
        except ValueError:
            day = None
        if cve_id not in known or epss is None or percentile is None or day is None:
            result.skipped += 1
            continue
        row = session.get(m.EpssScore, (cve_id, day))
        if row is None:
            row = m.EpssScore(cve_id=cve_id, score_date=day)
            session.add(row)
        row.epss, row.percentile = epss, percentile
        result.stored += 1
    session.flush()
    return result


def refresh_epss(session: Session, source: JsonSource, cve_ids: Sequence[str] | None = None) -> EpssResult:
    """Fetch and store the latest scores for `cve_ids` (default: every CVE we hold)."""
    ids = list(cve_ids) if cve_ids is not None else sorted(session.scalars(select(m.Cve.id)))
    return load_epss(session, fetch_scores(source, ids))
