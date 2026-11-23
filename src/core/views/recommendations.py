"""Recommendation history with feedback (D-040, D-044, FRO-12 to FRO-15): one recommendation per assessment.

The score shown is the assessment's highest final (EVA-07, "impulsada por …"); the affected CI shown is the most
restrictive one at evaluation time (FRO-13), with its classification, owner and custodian of that moment.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.mitigation.builder import build_mitigation
from core.mitigation.justification import JudgeReason, JustificationInput, build_justification
from core.notifications.events import ticket_url
from core.tickets.context import mitigation_text
from core.views.common import CLASSIFICATION_ORDER, ci_url

TimeKey = tuple[datetime, uuid.UUID]  # (assessed_at, id) of the last row of a page, newest first
MAX_FEEDBACK: Final = 500

# One row per CI score of each assessment in the page; `:after_at`/`:after_id` resume after the last row seen.
_PAGE: Final = text(
    """
    WITH page AS (
      SELECT a.id, a.assessed_at
        FROM assessment a
       WHERE EXISTS (SELECT 1 FROM asset_score s WHERE s.assessment_id = a.id)
         AND (CAST(:assessment_id AS uuid) IS NULL OR a.id = CAST(:assessment_id AS uuid))
         AND (CAST(:group_id AS uuid) IS NULL OR a.finding_group_id = CAST(:group_id AS uuid))
         AND (CAST(:ci_id AS text) IS NULL OR EXISTS (
               SELECT 1 FROM asset_score s JOIN asset x ON x.id = s.asset_id
                WHERE s.assessment_id = a.id AND x.itop_ci_id = CAST(:ci_id AS text)))
         AND (CAST(:after_at AS timestamptz) IS NULL OR (a.assessed_at, a.id)
               < (CAST(:after_at AS timestamptz), CAST(:after_id AS uuid)))
       ORDER BY a.assessed_at DESC, a.id DESC
       LIMIT :limit
    )
    SELECT a.id AS assessment_id, a.assessed_at, a.finding_group_id, a.alert_id, a.llm_review_id,
           a.judge_adjustment, a.raw_cvss_score, a.raw_in_kev, g.cve_id AS cve, sp.itop_name AS product,
           (a.llm_review_id IS NULL OR r.status = 'no_judge_review') AS no_judge_review,
           r.mitigation_status,
           s.asset_id, s.base, s.ci_adjustment, s.final, d.level, d.floor_applied,
           s.snap_criticality, s.snap_exposed, s.snap_confidentiality, s.snap_personal_data,
           ast.itop_ci_id AS ci_id, ast.itop_class, ast.name AS asset_name, ast.confidentiality AS classification,
           (ast.decommissioned_at IS NOT NULL) AS retired,
           s.snap_custodian_team_id, own.name AS owner, team.name AS custodian,
           (SELECT count(*) FROM feedback fb WHERE fb.assessment_id = a.id AND fb.superseded_at IS NULL)
             AS feedback_count,
           (SELECT max(ps.final) FROM asset_score ps WHERE ps.assessment_id = (
               SELECT pa.id FROM assessment pa
                WHERE ((a.finding_group_id IS NOT NULL AND pa.finding_group_id = a.finding_group_id)
                    OR (a.alert_id IS NOT NULL AND pa.alert_id = a.alert_id))
                  AND (pa.assessed_at, pa.id) < (a.assessed_at, a.id)
                  AND EXISTS (SELECT 1 FROM asset_score x WHERE x.assessment_id = pa.id)
                ORDER BY pa.assessed_at DESC, pa.id DESC LIMIT 1)) AS previous_final,
           (SELECT fc.status FROM finding f
              JOIN finding_current fc ON fc.finding_id = f.id
              JOIN installed_software i ON i.id = f.installed_software_id
             WHERE f.finding_group_id = a.finding_group_id AND i.asset_id = s.asset_id
             ORDER BY array_position(ARRAY['reopened','new','persistent','no_data','fixed']::text[], fc.status)
             LIMIT 1) AS finding_status
      FROM page
      JOIN assessment a ON a.id = page.id
      LEFT JOIN finding_group g ON g.id = a.finding_group_id
      LEFT JOIN software_product sp ON sp.id = g.software_product_id
      LEFT JOIN llm_review r ON r.id = a.llm_review_id
      JOIN asset_score s ON s.assessment_id = a.id
      JOIN asset_score_detail d ON d.assessment_id = s.assessment_id AND d.asset_id = s.asset_id
      JOIN asset ast ON ast.id = s.asset_id
      LEFT JOIN person own ON own.id = s.snap_owner_person_id
      LEFT JOIN team ON team.id = s.snap_custodian_team_id
     ORDER BY a.assessed_at DESC, a.id DESC
    """
)
_REASONS: Final = text(
    """
    SELECT jr.llm_review_id, t.description, jr.points
      FROM judge_reason jr JOIN judge_reason_type t ON t.code = jr.reason_code
     WHERE jr.llm_review_id = ANY(CAST(:reviews AS uuid[])) AND jr.status = 'accepted'
     ORDER BY jr.llm_review_id, jr.seq
    """
)
_DRAFT: Final = text(
    """
    SELECT llm_review_id, "action" FROM mitigation_draft_step
     WHERE llm_review_id = ANY(CAST(:reviews AS uuid[])) ORDER BY llm_review_id, step_order
    """
)
_TICKETS: Final = text(
    """
    SELECT finding_group_id, custodian_team_id, itop_ticket_id FROM ticket
     WHERE finding_group_id = ANY(CAST(:groups AS uuid[])) AND itop_ticket_id IS NOT NULL
     ORDER BY created_at, id
    """
)
_FEEDBACK: Final = text(
    """
    SELECT COALESCE(u.display_name, split_part(u.email::text, '@', 1)) AS "user", fb.channel, fb.verdict,
           fb.proposed_level, fb.proposed_score, fb.comment, fb.created_at, (fb.superseded_at IS NULL) AS active
      FROM feedback fb JOIN app_user u ON u.id = fb.app_user_id
     WHERE fb.assessment_id = :assessment_id
     ORDER BY fb.created_at DESC, fb.id DESC
     LIMIT :limit
    """
)
_NEWER_FINAL: Final = text(
    """
    SELECT (SELECT max(s.final) FROM asset_score s WHERE s.assessment_id = a.id) AS this_final,
           (SELECT max(s.final) FROM asset_score s WHERE s.assessment_id = (
               SELECT n.id FROM assessment n
                WHERE ((a.finding_group_id IS NOT NULL AND n.finding_group_id = a.finding_group_id)
                    OR (a.alert_id IS NOT NULL AND n.alert_id = a.alert_id))
                  AND (n.assessed_at, n.id) > (a.assessed_at, a.id)
                  AND EXISTS (SELECT 1 FROM asset_score x WHERE x.assessment_id = n.id)
                ORDER BY n.assessed_at DESC, n.id DESC LIMIT 1)) AS latest_final
      FROM assessment a WHERE a.id = :assessment_id
    """
)


@dataclass(frozen=True)
class AffectedAsset:
    ci_id: str
    name: str
    itop_url: str
    owner: str | None
    custodian: str | None
    criticality: str
    exposed: bool
    classification: str
    classification_at_evaluation: str
    finding_status: str
    score: int


@dataclass(frozen=True)
class Recommendation:
    assessment_id: uuid.UUID
    created_at: datetime
    cve: str | None
    product: str | None
    base: int
    judge_adjustment: int
    final: int
    level: str
    previous_final: int | None
    justification: str
    mitigation: str | None
    mitigation_draft: list[str] | None
    asset: AffectedAsset | None
    ticket_url: str | None
    feedback_count: int


@dataclass(frozen=True)
class FeedbackEntry:
    user: str
    channel: str
    verdict: str
    proposed_level: str | None
    proposed_score: int | None
    comment: str | None
    created_at: datetime
    active: bool
    on_older_version: bool


@dataclass(frozen=True)
class Query:
    """Optional narrowing: one assessment, one vulnerability group or one CI (FRO-12 timelines)."""

    assessment_id: uuid.UUID | None = None
    group_id: uuid.UUID | None = None
    ci_id: str | None = None  # iTop CI id


@dataclass
class _Parts:
    """What a page needs beyond its score rows, loaded once per page."""

    reasons: dict[uuid.UUID, list[JudgeReason]]
    drafts: dict[uuid.UUID, list[str]]
    tickets: dict[uuid.UUID, list[tuple[uuid.UUID, str]]]  # group -> (custodian team, iTop id)


def _parts(session: Session, rows: Sequence[Any]) -> _Parts:
    reviews = list({r.llm_review_id for r in rows if r.llm_review_id is not None})
    groups = list({r.finding_group_id for r in rows if r.finding_group_id is not None})
    parts = _Parts({}, {}, {})
    if reviews:
        for row in session.execute(_REASONS, {"reviews": reviews}):
            parts.reasons.setdefault(row.llm_review_id, []).append(JudgeReason(f"{row.description} ({row.points:+d})"))
        for row in session.execute(_DRAFT, {"reviews": reviews}):
            parts.drafts.setdefault(row.llm_review_id, []).append(row.action)
    if groups:
        for row in session.execute(_TICKETS, {"groups": groups}):
            parts.tickets.setdefault(row.finding_group_id, []).append((row.custodian_team_id, row.itop_ticket_id))
    return parts


def _live(rows: Sequence[Any]) -> Sequence[Any]:
    """Decommissioned CIs step aside while a live one remains (ARQ-03)."""
    return [r for r in rows if not r.retired] or rows


def _driver(rows: Sequence[Any]) -> Any:
    """EVA-07: the highest final; ties go to the CI name."""
    return max(sorted(_live(rows), key=lambda r: (r.asset_name, str(r.asset_id))), key=lambda r: r.final)


def _shown(rows: Sequence[Any]) -> Any:
    """FRO-13: the most restrictive CI at evaluation time; ties go to the higher final, then the name."""
    return min(
        _live(rows),
        key=lambda r: (CLASSIFICATION_ORDER.index(r.snap_confidentiality), -r.final, r.asset_name, str(r.asset_id)),
    )


def _ticket(parts: _Parts, group_id: uuid.UUID | None, team_id: uuid.UUID | None) -> str | None:
    """The iTop id of the group's ticket for the shown CI's custodian, else of the group's first ticket."""
    tickets = parts.tickets.get(group_id) if group_id is not None else None
    if not tickets:
        return None
    return next((itop for team, itop in tickets if team == team_id), tickets[0][1])


def _recommendation(
    rows: Sequence[Any], parts: _Parts, mitigation: str | None, itop_base_url: str | None
) -> Recommendation:
    driver, shown, first = _driver(rows), _shown(rows), rows[0]
    adjustment = first.judge_adjustment + driver.ci_adjustment
    justification = build_justification(
        JustificationInput(
            base=driver.base,
            final=driver.final,
            driving_ci=driver.asset_name,
            cvss_score=first.raw_cvss_score,
            in_kev=bool(first.raw_in_kev),
            criticality=driver.snap_criticality,
            exposed=driver.snap_exposed,
            confidentiality=driver.snap_confidentiality,
            personal_data=driver.snap_personal_data,
            judge_adjustment=adjustment,
            judge_reasons=tuple(parts.reasons.get(first.llm_review_id, ())),
            floor_applied=bool(driver.floor_applied),
            no_judge_review=bool(first.no_judge_review),
        ),
        first.assessed_at,
    )
    draft = parts.drafts.get(first.llm_review_id) if first.mitigation_status == "accepted" else None
    itop_id = _ticket(parts, first.finding_group_id, shown.snap_custodian_team_id)
    return Recommendation(
        assessment_id=first.assessment_id,
        created_at=first.assessed_at,
        cve=first.cve,
        product=first.product,
        base=driver.base,
        judge_adjustment=adjustment,
        final=driver.final,
        level=driver.level,
        previous_final=first.previous_final,
        justification=justification,
        mitigation=mitigation,
        mitigation_draft=draft or None,
        asset=AffectedAsset(
            ci_id=shown.ci_id,
            name=shown.asset_name,
            itop_url=ci_url(itop_base_url, shown.itop_class, shown.ci_id),
            owner=shown.owner,
            custodian=shown.custodian,
            criticality=shown.snap_criticality,
            exposed=shown.snap_exposed is True,
            classification=shown.classification,
            classification_at_evaluation=shown.snap_confidentiality,
            # An alert's CI has no scan finding: "no_data" says the scan has nothing on it.
            finding_status=shown.finding_status or "no_data",
            score=shown.final,
        ),
        ticket_url=ticket_url(itop_base_url, itop_id) or None,
        feedback_count=first.feedback_count,
    )


def list_recommendations(
    session: Session, query: Query, itop_base_url: str | None, *, after: TimeKey | None, limit: int
) -> tuple[list[Recommendation], TimeKey | None]:
    """Newest first. The second value keys the next page."""
    rows = session.execute(
        _PAGE,
        {
            "assessment_id": query.assessment_id,
            "group_id": query.group_id,
            "ci_id": query.ci_id,
            "after_at": after[0] if after else None,
            "after_id": after[1] if after else None,
            "limit": limit + 1,
        },
    ).all()
    by_assessment: dict[uuid.UUID, list[Any]] = {}
    for row in rows:
        by_assessment.setdefault(row.assessment_id, []).append(row)
    pages = list(by_assessment.values())
    kept = pages[:limit]
    parts = _parts(session, [r for page in kept for r in page])
    mitigations: dict[uuid.UUID, str | None] = {}
    out: list[Recommendation] = []
    for page in kept:
        group_id = page[0].finding_group_id
        if group_id is not None and group_id not in mitigations:
            mitigations[group_id] = mitigation_text(build_mitigation(session, group_id))
        out.append(_recommendation(page, parts, mitigations.get(group_id) if group_id else None, itop_base_url))
    next_key = (kept[-1][0].assessed_at, kept[-1][0].assessment_id) if len(pages) > limit else None
    return out, next_key


def get_recommendation(session: Session, assessment_id: uuid.UUID, itop_base_url: str | None) -> Recommendation | None:
    found, _next = list_recommendations(session, Query(assessment_id=assessment_id), itop_base_url, after=None, limit=1)
    return found[0] if found else None


def feedback_of(session: Session, assessment_id: uuid.UUID) -> list[FeedbackEntry] | None:
    """Feedback on one assessment, newest first; None if the assessment does not exist.

    `on_older_version` (FRO-15): a newer assessment of the same group or alert changed the score.
    """
    versions = session.execute(_NEWER_FINAL, {"assessment_id": assessment_id}).one_or_none()
    if versions is None:
        return None
    older = versions.latest_final is not None and versions.latest_final != versions.this_final
    return [
        FeedbackEntry(
            user=row.user,
            channel=row.channel,
            verdict=row.verdict,
            proposed_level=row.proposed_level,
            proposed_score=row.proposed_score,
            comment=row.comment,
            created_at=row.created_at,
            active=row.active,
            on_older_version=older,
        )
        for row in session.execute(_FEEDBACK, {"assessment_id": assessment_id, "limit": MAX_FEEDBACK})
    ]
