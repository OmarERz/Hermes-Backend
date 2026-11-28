"""Shared pieces of the read models: the scored-finding CTE, status and classification order, links and dates.

A *scored finding* is one CI of one vulnerability group (CVE + product) on a live asset (not decommissioned,
ARQ-03) that has at least one score. Its score is the CI's row in the most recent assessment of the group that
scored it (D-035, EVA-06); a CI with two instances of the product is one scored finding whose status is the most
pressing of its instances. Findings the engine has not scored yet are not shown.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Final
from urllib.parse import quote

from sqlalchemy import text
from sqlalchemy.orm import Session

# Most pressing first: a group or CI shows the status of its most pressing finding.
STATUS_ORDER: Final = ("reopened", "new", "persistent", "no_data", "fixed")
# Most restrictive first (FRO-13). Unclassified sits above public: it is scored like classified (D-034).
CLASSIFICATION_ORDER: Final = ("highly_classified", "classified", "unclassified", "public")
LEVELS: Final = ("critical", "high", "medium", "low")
_ITOP_CI_PAGE: Final = "/pages/UI.php?operation=details&class="

# One row per scored finding, with what every view needs of its group, CI, owner and custodian.
# `:group_id` and `:asset_id` narrow the rows when given.
_SCORED: Final = text(
    """
WITH pair AS (
  SELECT f.finding_group_id AS group_id, i.asset_id,
         (array_agg(f.id ORDER BY array_position(
             ARRAY['reopened','new','persistent','no_data','fixed']::text[], fc.status), f.id))[1] AS finding_id,
         (ARRAY['reopened','new','persistent','no_data','fixed']::text[])[min(array_position(
             ARRAY['reopened','new','persistent','no_data','fixed']::text[], fc.status))] AS status,
         max(fc.status_changed_at) AS last_seen
    FROM finding f
    JOIN finding_current fc ON fc.finding_id = f.id
    JOIN installed_software i ON i.id = f.installed_software_id
    JOIN asset live ON live.id = i.asset_id AND live.decommissioned_at IS NULL
   WHERE (CAST(:group_id AS uuid) IS NULL OR f.finding_group_id = CAST(:group_id AS uuid))
     AND (CAST(:asset_id AS uuid) IS NULL OR i.asset_id = CAST(:asset_id AS uuid))
   GROUP BY f.finding_group_id, i.asset_id
), latest AS (
  SELECT DISTINCT ON (a.finding_group_id, s.asset_id)
         a.finding_group_id AS group_id, s.asset_id, s.assessment_id, s.final, s.base, s.ci_adjustment,
         a.judge_adjustment, s.snap_confidentiality, a.raw_cvss_score
    FROM asset_score s
    JOIN assessment a ON a.id = s.assessment_id
    JOIN pair p ON p.group_id = a.finding_group_id AND p.asset_id = s.asset_id
   ORDER BY a.finding_group_id, s.asset_id, a.assessed_at DESC, a.id DESC
)
SELECT p.group_id, p.asset_id, p.finding_id, p.status, p.last_seen,
       l.assessment_id, l.final, l.base, l.ci_adjustment, l.judge_adjustment, d.level, l.snap_confidentiality,
       l.raw_cvss_score AS cvss,
       g.cve_id AS cve, sp.itop_name AS product, c.description,
       EXISTS (SELECT 1 FROM kev_entry k WHERE k.cve_id = g.cve_id) AS in_kev,
       ast.itop_ci_id AS ci_id, ast.itop_class, ast.name AS asset_name, ast.criticality,
       (ast.exposed IS TRUE) AS exposed, ast.confidentiality AS classification,
       pe.name AS owner, t.name AS custodian,
       ARRAY(SELECT COALESCE(tk.itop_ref, tk.itop_ticket_id) FROM ticket tk
              WHERE tk.finding_group_id = p.group_id AND COALESCE(tk.itop_ref, tk.itop_ticket_id) IS NOT NULL
              ORDER BY 1) AS tickets
  FROM pair p
  JOIN latest l ON l.group_id = p.group_id AND l.asset_id = p.asset_id
  JOIN asset_score_detail d ON d.assessment_id = l.assessment_id AND d.asset_id = l.asset_id
  JOIN finding_group g ON g.id = p.group_id
  JOIN software_product sp ON sp.id = g.software_product_id
  LEFT JOIN cve c ON c.id = g.cve_id
  JOIN asset ast ON ast.id = p.asset_id
  LEFT JOIN team t ON t.id = ast.custodian_team_id
  LEFT JOIN person pe ON pe.id = ast.owner_person_id
"""
)


@dataclass(frozen=True)
class ScoredFinding:
    group_id: uuid.UUID
    asset_id: uuid.UUID
    finding_id: uuid.UUID
    status: str
    last_seen: datetime
    assessment_id: uuid.UUID
    final: int
    base: int
    ci_adjustment: int
    judge_adjustment: int
    level: str
    snap_confidentiality: str
    cvss: Decimal | None  # the CVSS the assessment used (NVD, else the CNA's: D-104); None = unrated (docs/06 §S)
    cve: str
    product: str
    description: str | None
    in_kev: bool
    ci_id: str
    itop_class: str
    asset_name: str
    criticality: str
    exposed: bool
    classification: str
    owner: str | None
    custodian: str | None
    tickets: list[str]

    @property
    def is_current(self) -> bool:
        return self.status != "fixed"


def scored_findings(
    session: Session, *, group_id: uuid.UUID | None = None, asset_id: uuid.UUID | None = None
) -> list[ScoredFinding]:
    rows = session.execute(_SCORED, {"group_id": group_id, "asset_id": asset_id}).mappings().all()
    return [ScoredFinding(**{**row, "tickets": list(row["tickets"])}) for row in rows]


def speaking(rows: Sequence[ScoredFinding]) -> list[ScoredFinding]:
    """The rows that speak for a group or a CI: the current ones, or every one when none is current."""
    return [r for r in rows if r.is_current] or list(rows)


def iso(value: datetime) -> str:
    """ISO 8601 in UTC with a `Z` suffix (API-02)."""
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_uuid(raw: str) -> uuid.UUID | None:
    """The UUID in a path parameter, or None when it is not one (the route answers 404, not 422)."""
    try:
        return uuid.UUID(raw)
    except ValueError:
        return None


def ci_url(itop_base_url: str | None, itop_class: str, itop_ci_id: str) -> str:
    """Link to the CI in iTop's console, or "" while iTop's URL is not configured."""
    if not itop_base_url:
        return ""
    return f"{itop_base_url.rstrip('/')}{_ITOP_CI_PAGE}{quote(itop_class, safe='')}&id={quote(itop_ci_id, safe='')}"


def most_pressing(statuses: Sequence[str]) -> str:
    return min(statuses, key=STATUS_ORDER.index)


def most_restrictive(classifications: Sequence[str]) -> str:
    return min(classifications, key=CLASSIFICATION_ORDER.index)
