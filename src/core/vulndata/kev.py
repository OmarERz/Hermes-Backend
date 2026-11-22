"""CISA Known Exploited Vulnerabilities catalogue loader (ESC-09).

One JSON document with every entry (`vulnerabilities[]`: `cveID`, `dateAdded`, `dueDate`, `requiredAction`,
`knownRansomwareCampaignUse` as `Known` or `Unknown`), verified against the published feed on 22 Nov 2026.
An entry for a CVE we do not hold yet creates the minimal `cve` row (`fetched_at` NULL) the model allows.
KEV never withdraws entries, so a CVE missing from a later download keeps its row.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db import models as m
from core.vulndata.http import JsonSource, SourceUnavailableError
from core.vulndata.records import CVE_ID

KEV_URL: Final = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass
class KevEntry:
    cve_id: str
    date_added: date
    due_date: date | None
    required_action: str
    known_ransomware_use: bool | None


@dataclass
class KevResult:
    stored: int = 0
    skipped: int = 0


def _date(raw: object) -> date | None:
    try:
        return date.fromisoformat(str(raw)[:10])
    except ValueError:
        return None


def parse_entry(raw: dict[str, Any]) -> KevEntry | None:
    cve_id = raw.get("cveID")
    added = _date(raw.get("dateAdded"))
    action = str(raw.get("requiredAction") or "").strip()
    if not isinstance(cve_id, str) or not CVE_ID.match(cve_id) or added is None or not action:
        return None
    ransomware = {"known": True, "unknown": False}.get(str(raw.get("knownRansomwareCampaignUse", "")).lower())
    return KevEntry(cve_id, added, _date(raw.get("dueDate")), action, ransomware)


def fetch_catalogue(source: JsonSource, url: str = KEV_URL) -> list[dict[str, Any]]:
    body = source.get(url)
    if not isinstance(body, dict) or not isinstance(body.get("vulnerabilities"), list):
        raise SourceUnavailableError("incomplete KEV answer")
    return [e for e in body["vulnerabilities"] if isinstance(e, dict)]


def load_kev(session: Session, entries: list[dict[str, Any]]) -> KevResult:
    """Upsert the entries. The caller owns the transaction."""
    result = KevResult()
    known_cves = set(session.scalars(select(m.Cve.id)))
    existing = {k.cve_id: k for k in session.scalars(select(m.KevEntry))}
    for raw in entries:
        entry = parse_entry(raw)
        if entry is None:
            result.skipped += 1
            continue
        if entry.cve_id not in known_cves:
            session.add(m.Cve(id=entry.cve_id))
            known_cves.add(entry.cve_id)
            session.flush()
        row = existing.get(entry.cve_id)
        if row is None:
            row = m.KevEntry(cve_id=entry.cve_id)
            session.add(row)
            existing[entry.cve_id] = row
        row.date_added, row.due_date = entry.date_added, entry.due_date
        row.required_action, row.known_ransomware_use = entry.required_action, entry.known_ransomware_use
        result.stored += 1
    session.flush()
    return result
