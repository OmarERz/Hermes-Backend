"""Load what a ticket shows (TIC-08) and its score history (D-006) from the database.

The ticket score is the highest final among the ticket's current CIs in one assessment (D-035, EVA-07): it is read
from `asset_score`, written by the scoring engine, so this module never recomputes a score.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any, Final

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.db import models as m
from core.mitigation.builder import Mitigation, build_mitigation
from core.tickets.content import CiLine, NewsLine, ReasonLine, TicketContext

MAX_NEWS: Final = 20
HISTORY_DEPTH: Final = 30

_CIS: Final = text(
    """
    SELECT a.id AS asset_id, a.itop_ci_id, a.name, a.criticality, a.exposed, a.confidentiality, a.personal_data,
           p.name AS owner_name, p.itop_person_id AS owner_itop_id, p.email AS owner_email,
           fc.status, s.final, s.base, s.ci_adjustment, s.factor_a, s.factor_d,
           EXISTS (SELECT 1 FROM suppression x WHERE x.finding_id = fc.finding_id AND x.lifted_at IS NULL
                     AND x.suppressed_version = fc.observed_version) AS suppressed
      FROM ticket_finding tf
      JOIN finding_current fc ON fc.finding_id = tf.finding_id
      JOIN installed_software i ON i.id = fc.installed_software_id
      JOIN asset a ON a.id = i.asset_id
      LEFT JOIN person p ON p.id = a.owner_person_id
      LEFT JOIN asset_score s ON s.assessment_id = :assessment_id AND s.asset_id = a.id
     WHERE tf.ticket_id = :ticket_id AND tf.removed_at IS NULL
     ORDER BY a.name, a.id
    """
)
_GROUP: Final = text(
    """
    SELECT g.cve_id, sp.itop_name AS product, c.cvss_score,
           EXISTS (SELECT 1 FROM kev_entry k WHERE k.cve_id = g.cve_id) AS in_kev
      FROM finding_group g
      JOIN software_product sp ON sp.id = g.software_product_id
      JOIN cve c ON c.id = g.cve_id
     WHERE g.id = :group_id
    """
)
_REASONS: Final = text(
    """
    SELECT r.reason_code, r.points FROM judge_reason r
     WHERE r.llm_review_id = :review_id AND r.status = 'accepted' ORDER BY r.seq
    """
)
_DRAFT: Final = text(
    """SELECT d.action FROM mitigation_draft_step d WHERE d.llm_review_id = :review_id ORDER BY d.step_order"""
)
_NEWS: Final = text(
    """
    SELECT DISTINCT ON (ra.canonical_url) ra.title, ra.canonical_url, ra.published_at, src.name AS source
      FROM correlation co
      JOIN raw_article ra ON ra.story_id = co.story_id
      JOIN source_fetch sf ON sf.id = ra.source_fetch_id
      JOIN source src ON src.id = sf.source_id
     WHERE co.finding_group_id = :group_id
     ORDER BY ra.canonical_url, ra.published_at
    """
)
_HISTORY: Final = text(
    """
    SELECT a.assessed_at, max(s.final) AS score
      FROM assessment a
      JOIN asset_score s ON s.assessment_id = a.id
     WHERE a.finding_group_id = :group_id AND s.asset_id = ANY(:asset_ids)
     GROUP BY a.id, a.assessed_at
     ORDER BY a.assessed_at DESC, a.id DESC
     LIMIT :depth
    """
)

CURRENT_STATUSES: Final = frozenset({"new", "persistent", "reopened", "no_data"})


def _merge_by_asset(rows: Sequence[Any]) -> list[Any]:
    """One line per CI: a CI with two instances of the product is fixed only when both are."""
    merged: dict[uuid.UUID, Any] = {}
    for row in rows:
        kept = merged.get(row.asset_id)
        if kept is None or (kept.status == "fixed" and row.status != "fixed"):
            merged[row.asset_id] = row
    return list(merged.values())


def mitigation_text(mitigation: Mitigation | None) -> str | None:
    """Mitigation from the data (D-017, built by `core.mitigation`) as plain lines for the ticket and the event."""
    if mitigation is None:
        return None
    lines = [*mitigation.correction, *mitigation.temporal, *mitigation.detection, *mitigation.verification]
    references = [*mitigation.patch_references, *mitigation.advisory_references]
    if references:
        lines.append("Referencias: " + ", ".join(references))
    return "\n".join(lines) or None


def load_context(session: Session, ticket: m.Ticket, assessment: m.Assessment | None) -> TicketContext:
    """Everything the ticket and its events show, for the ticket's current links and one assessment."""
    group = session.execute(_GROUP, {"group_id": ticket.finding_group_id}).one()
    team = session.get_one(m.Team, ticket.custodian_team_id)
    assessment_id = assessment.id if assessment is not None else None
    rows = _merge_by_asset(session.execute(_CIS, {"ticket_id": ticket.id, "assessment_id": assessment_id}).all())
    cis = [
        CiLine(
            itop_ci_id=row.itop_ci_id,
            name=row.name,
            score=row.final,
            criticality=row.criticality,
            exposed=row.exposed,
            confidentiality=row.confidentiality,
            personal_data=row.personal_data,
            owner_name=row.owner_name,
            owner_itop_id=row.owner_itop_id,
            owner_email=row.owner_email,
            fixed=row.status not in CURRENT_STATUSES,
        )
        for row in rows
    ]
    # A false positive (ARQ-06) never drives the ticket score: its CI is listed but does not count.
    scored = [row for row in rows if row.status in CURRENT_STATUSES and row.final is not None and not row.suppressed]
    driver = max(sorted(scored, key=lambda r: r.name), key=lambda r: r.final) if scored else None
    review_id = assessment.llm_review_id if assessment is not None else None
    reasons = session.execute(_REASONS, {"review_id": review_id}).all() if review_id else []
    draft = session.scalars(_DRAFT, {"review_id": review_id}).all() if review_id else []
    news = session.execute(_NEWS, {"group_id": ticket.finding_group_id}).all()
    factors: dict[str, str] = {}
    if assessment is not None:
        factors = {"S": str(assessment.factor_s), "P": str(assessment.factor_p), "T": str(assessment.factor_t)}
        if driver is not None:
            factors |= {"A": str(driver.factor_a), "D": str(driver.factor_d)}
    return TicketContext(
        cve=group.cve_id,
        product=group.product,
        custodian=team.name,
        custodian_itop_id=team.itop_team_id,
        cis=cis,
        score=driver.final if driver is not None else None,
        driving_ci=driver.name if driver is not None else None,
        base=driver.base if driver is not None else None,
        judge_adjustment=(assessment.judge_adjustment + driver.ci_adjustment)
        if assessment is not None and driver is not None
        else 0,
        factors=factors,
        reasons=[ReasonLine(r.reason_code, r.points) for r in reasons],
        mitigation=mitigation_text(build_mitigation(session, ticket.finding_group_id)),
        mitigation_draft=list(draft) or None,
        news=[
            NewsLine(n.title, n.canonical_url, n.source, n.published_at.date().isoformat())
            for n in sorted(news, key=lambda n: n.published_at, reverse=True)[:MAX_NEWS]
        ],
        cvss=float(group.cvss_score) if group.cvss_score is not None else None,
        in_kev=bool(group.in_kev),
    )


def score_history(session: Session, ticket: m.Ticket, asset_ids: Sequence[uuid.UUID]) -> list[tuple[datetime, int]]:
    """The ticket score of each recent assessment of its group over `asset_ids` (its current CIs), oldest first."""
    if not asset_ids:
        return []
    rows = session.execute(
        _HISTORY, {"group_id": ticket.finding_group_id, "asset_ids": list(asset_ids), "depth": HISTORY_DEPTH}
    ).all()
    return [(row.assessed_at, int(row.score)) for row in reversed(rows)]


def linked_asset_ids(session: Session, ticket_id: uuid.UUID, *, current_only: bool = True) -> list[uuid.UUID]:
    """Assets of the ticket's linked findings; only the current ones (not fixed, not a false positive) unless
    `current_only` is False."""
    rows = session.execute(
        text(
            """
            SELECT DISTINCT i.asset_id
              FROM ticket_finding tf
              JOIN finding_current fc ON fc.finding_id = tf.finding_id
              JOIN installed_software i ON i.id = fc.installed_software_id
             WHERE tf.ticket_id = :ticket_id AND tf.removed_at IS NULL
               AND (NOT :current_only OR (fc.status <> 'fixed' AND NOT EXISTS (
                     SELECT 1 FROM suppression x WHERE x.finding_id = fc.finding_id AND x.lifted_at IS NULL
                       AND x.suppressed_version = fc.observed_version)))
            """
        ),
        {"ticket_id": ticket_id, "current_only": current_only},
    ).all()
    return [row.asset_id for row in rows]
