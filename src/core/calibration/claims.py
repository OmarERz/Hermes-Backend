"""Resolve source claims from data we already hold (docs/09 §2, L6). No LLM and no token cost.

| Claim type | Confirmed when | Refuted when |
|---|---|---|
| `active_exploitation` | the CVE enters CISA KEV within 90 days of the claim | never (not confirmed is not refuted) |
| `public_poc` | a reference tagged `Exploit` exists | never automatically |
| `requires_authentication` | the CVSS vector has `PR:L` or `PR:H` | the vector has `PR:N` |
| `used_in_assessment` | the latest human feedback on the CVE's assessments is "relevant" | it is "false positive" |

Feedback rows are read from `feedback` directly; whoever writes them (the FeedbackService) is not needed here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Final

from sqlalchemy import text
from sqlalchemy.orm import Session

KEV_DAYS: Final = 90

_CONFIRM_KEV = text(
    "UPDATE claim c SET status = 'confirmed', resolved_at = :now FROM kev_entry k "
    "WHERE c.status = 'pending' AND c.claim_type = 'active_exploitation' AND k.cve_id = c.cve_id "
    "AND k.date_added <= (c.claimed_at::date + :days)"
)
_CONFIRM_POC = text(
    "UPDATE claim c SET status = 'confirmed', resolved_at = :now "
    "WHERE c.status = 'pending' AND c.claim_type = 'public_poc' AND EXISTS ("
    "SELECT 1 FROM cve_reference r JOIN cve_reference_tag t ON t.reference_id = r.id "
    "WHERE r.cve_id = c.cve_id AND t.tag = 'Exploit')"
)
_AUTH = text(
    "UPDATE claim c SET status = CASE WHEN v.cvss_vector ~ '/PR:[LH]' THEN 'confirmed' ELSE 'refuted' END, "
    "resolved_at = :now FROM cve v WHERE c.status = 'pending' AND c.claim_type = 'requires_authentication' "
    "AND v.id = c.cve_id AND v.cvss_vector ~ '/PR:[LHN]'"
)
_FEEDBACK = text(
    "WITH latest AS (SELECT DISTINCT ON (g.cve_id) g.cve_id, f.verdict FROM feedback f "
    "JOIN assessment a ON a.id = f.assessment_id JOIN finding_group g ON g.id = a.finding_group_id "
    "WHERE f.superseded_at IS NULL AND f.verdict IN ('relevant', 'false_positive') "
    "ORDER BY g.cve_id, f.created_at DESC, f.id DESC) "
    "UPDATE claim c SET status = CASE l.verdict WHEN 'relevant' THEN 'confirmed' ELSE 'refuted' END, "
    "resolved_at = :now FROM latest l "
    "WHERE c.status = 'pending' AND c.claim_type = 'used_in_assessment' AND l.cve_id = c.cve_id"
)


@dataclass(frozen=True)
class Resolved:
    confirmed: int
    refuted: int


def resolve_claims(session: Session, now: datetime) -> Resolved:
    """Resolve every pending claim the data can decide; returns how many became confirmed and refuted."""
    before = _counts(session)
    session.execute(_CONFIRM_KEV, {"now": now, "days": KEV_DAYS})
    session.execute(_CONFIRM_POC, {"now": now})
    session.execute(_AUTH, {"now": now})
    session.execute(_FEEDBACK, {"now": now})
    after = _counts(session)
    return Resolved(after[0] - before[0], after[1] - before[1])


def _counts(session: Session) -> tuple[int, int]:
    row = session.execute(
        text(
            "SELECT count(*) FILTER (WHERE status = 'confirmed'), count(*) FILTER (WHERE status = 'refuted') FROM claim"
        )
    ).one()
    return int(row[0]), int(row[1])
