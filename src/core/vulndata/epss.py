"""FIRST EPSS loaders (ESC-09, EVA scoring input).

Bulk refresh reads the daily full CSV `epss_scores-current.csv.gz` (FUE-04): the API is only for spot queries.
⚠️ The CSV address and its first line (`#model_version:...,score_date:<ISO date>`) follow FIRST's data page and
could not be re-read in this session; the address is a parameter.

`GET https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B` answers `{"status": "OK", "data": [{"cve", "epss",
"percentile", "date"}]}` with the numbers as strings (verified against the live API on 22 Nov 2026). Requests are
batched so the URL stays short. Only CVEs already in `cve` are stored: a score for a CVE we do not track is of
no use. One row per CVE and day (`epss_score` is a daily series).
"""

from __future__ import annotations

import zlib
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
EPSS_DAILY_URL: Final = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
MAX_CSV_BYTES: Final = 256 * 1024 * 1024
GZIP_MAGIC: Final = b"\x1f\x8b"
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


def parse_daily_csv(data: bytes) -> list[dict[str, Any]]:
    """Rows of the daily file as the API shape (`cve`, `epss`, `percentile`, `date`); gzip is detected and bounded."""
    if data.startswith(GZIP_MAGIC):
        inflater = zlib.decompressobj(wbits=31)
        data = inflater.decompress(data, MAX_CSV_BYTES)
        if inflater.unconsumed_tail:
            raise SourceUnavailableError("EPSS file too large")
    lines = data.decode("utf-8", errors="replace").splitlines()
    day = ""
    if lines and lines[0].startswith("#"):
        marker = next((p for p in lines[0].lstrip("#").split(",") if p.startswith("score_date:")), "")
        day = marker.removeprefix("score_date:")[:10]
        lines = lines[1:]
    if not day or not lines or lines[0].strip() != "cve,epss,percentile":
        raise SourceUnavailableError("unexpected EPSS file layout")
    rows: list[dict[str, Any]] = []
    for line in lines[1:]:
        cve, _, rest = line.partition(",")
        epss, _, percentile = rest.partition(",")
        rows.append({"cve": cve, "epss": epss, "percentile": percentile, "date": day})
    return rows


def fetch_daily(source: JsonSource, url: str = EPSS_DAILY_URL) -> list[dict[str, Any]]:
    return parse_daily_csv(source.get_bytes(url))


def load_epss(session: Session, rows: list[dict[str, Any]], known: set[str] | None = None) -> EpssResult:
    """Upsert score rows for the CVEs we hold (`known`, read here when not given). The caller owns the transaction."""
    result = EpssResult()
    known = set(session.scalars(select(m.Cve.id))) if known is None else known
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
    """Store the latest scores: the daily file for every CVE we hold (default), or API spot queries for `cve_ids`."""
    rows = fetch_scores(source, list(cve_ids)) if cve_ids is not None else fetch_daily(source)
    return load_epss(session, rows)
