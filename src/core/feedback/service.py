"""FeedbackService (NOT-06, D-044): the one entry point for feedback from Slack and from the frontend.

* Only authorized users count: the e-mail must belong to an active user with the analyst or admin role (D-030).
* One active feedback per user and assessment: a new one archives the previous (`superseded_at`).
* Effects: `false_positive` suppresses the findings the rated assessment scored (ARQ-06, until their version or
  CVE changes) and leaves a private comment with who and when; `stop_suggestions` turns off suggestions on the
  rated tickets (TIC-07); `wrong_priority` leaves a private comment with the proposed level (calibration data).
  The others are only stored. Feedback never changes a score by itself.
* With the optional `ticket_itop_id` (the ticket the user clicked on) those effects only touch that ticket and its
  own CIs; without it they apply to every ticket of the assessment (the original behaviour). An id that is not a
  ticket of the rated group is rejected (`unknown_ticket`).
* The comment is untrusted input: stored as data, never sent to iTop and never interpreted (SEG-02/03).
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from sqlalchemy import select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from core.itop.outbox import ItopWrite, comment_payload, record_write
from notifications_api import FeedbackInput, FeedbackResult

log = logging.getLogger("core.feedback.service")

AUTHORIZED_ROLES: Final = frozenset({"analyst", "admin"})
LEVEL_ES: Final = {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja"}
VERDICT_ES: Final = {"false_positive": "Falso positivo", "wrong_priority": "Prioridad incorrecta"}

# The findings the rated assessment scored, with the version observed when it was made (FRO-15): findings of the
# group that existed then, on a CI scored in that assessment, whose state at that time was not fixed.
_ASSESSED_FINDINGS: Final = text(
    """SELECT f.id AS finding_id, last.observed_version FROM finding f
    JOIN installed_software i ON i.id = f.installed_software_id
    JOIN asset_score s ON s.asset_id = i.asset_id AND s.assessment_id = :assessment_id
    JOIN LATERAL (SELECT c.status, c.observed_version FROM finding_status_change c
                  WHERE c.finding_id = f.id AND c.changed_at <= :assessed_at
                  ORDER BY c.changed_at DESC, c.id DESC LIMIT 1) last ON true
    WHERE f.finding_group_id = :group_id AND last.status <> 'fixed'"""
)
# The same lock the ticket lifecycle takes (ARQ-04): feedback effects and a re-evaluation never interleave.
_GROUP_LOCK: Final = text("SELECT id FROM finding_group WHERE id = :group_id FOR UPDATE")
# Tickets that hold one of the assessed findings: the effects stay on the rated tickets (TIC-07).
_RATED_TICKETS: Final = text(
    """SELECT DISTINCT tf.ticket_id FROM ticket_finding tf
    WHERE tf.finding_id = ANY(:finding_ids) AND tf.removed_at IS NULL"""
)
_TICKET_FINDINGS: Final = text(
    "SELECT finding_id FROM ticket_finding WHERE ticket_id = :ticket_id AND removed_at IS NULL"
)
_LIFT_OTHER_VERSIONS: Final = text(
    """UPDATE suppression SET lifted_at = :now, lift_reason = 'version_changed'
    WHERE finding_id = :finding_id AND lifted_at IS NULL AND suppressed_version <> :version"""
)
_CURRENT_VERSION: Final = text("SELECT observed_version FROM finding_current WHERE finding_id = :finding_id")
# One writer at a time per user and assessment (D-044): a transaction-scoped advisory lock.
_LOCK: Final = text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))")


@dataclass(frozen=True)
class _Rated:
    """What a feedback rates: the stored row, its assessment, its author and, if sent, the clicked ticket."""

    feedback: m.Feedback
    assessment: m.Assessment
    user: m.AppUser
    clicked: m.Ticket | None


class FeedbackRejectedError(Exception):
    """The feedback is not accepted. `code` is stable; the message never echoes the input (SEG-21)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class SqlFeedbackService:
    """`notifications_api.FeedbackService` over PostgreSQL."""

    session_factory: sessionmaker[Session]
    clock: Callable[[], datetime] = utcnow

    def record(self, feedback: FeedbackInput) -> FeedbackResult:
        now = self.clock()
        with self.session_factory() as session, session.begin():
            user = self._authorized_user(session, feedback.user_email)
            assessment = self._assessment(session, feedback.assessment_id)
            clicked = self._clicked_ticket(session, feedback.ticket_itop_id, assessment)
            session.execute(_LOCK, {"key": f"feedback:{assessment.id}:{user.id}"})
            replaced = session.scalars(
                update(m.Feedback)
                .where(
                    m.Feedback.assessment_id == assessment.id,
                    m.Feedback.app_user_id == user.id,
                    m.Feedback.superseded_at.is_(None),
                )
                .values(superseded_at=now)
                .returning(m.Feedback.id)
            ).all()
            row = m.Feedback(
                assessment_id=assessment.id,
                app_user_id=user.id,
                channel=feedback.channel,
                verdict=feedback.verdict,
                proposed_level=feedback.proposed_level,
                proposed_score=feedback.proposed_score,
                # PostgreSQL text cannot hold NUL; the rest of the untrusted comment is kept as data.
                comment=feedback.comment.replace("\x00", "") if feedback.comment is not None else None,
                created_at=now,
            )
            session.add(row)
            session.flush()
            if assessment.finding_group_id is not None:
                self._apply_effects(session, _Rated(row, assessment, user, clicked), now)
            log.info("feedback %s stored (verdict %s, replaced %s)", row.id, row.verdict, bool(replaced))
            return FeedbackResult(feedback_id=str(row.id), replaced_previous=bool(replaced))

    # --- checks ---------------------------------------------------------------------------------------------
    @staticmethod
    def _authorized_user(session: Session, email: str) -> m.AppUser:
        user = session.scalars(select(m.AppUser).where(m.AppUser.email == email.strip())).first()
        if user is None or not user.active or user.role not in AUTHORIZED_ROLES:
            raise FeedbackRejectedError("unauthorized_user")
        return user

    @staticmethod
    def _assessment(session: Session, raw_id: str) -> m.Assessment:
        try:
            assessment_id = uuid.UUID(raw_id)
        except ValueError:
            raise FeedbackRejectedError("unknown_assessment") from None
        assessment = session.get(m.Assessment, assessment_id)
        if assessment is None:
            raise FeedbackRejectedError("unknown_assessment")
        return assessment

    @staticmethod
    def _clicked_ticket(session: Session, itop_id: str | None, assessment: m.Assessment) -> m.Ticket | None:
        """The ticket the user acted on (optional contract field); it must be a ticket of the rated group."""
        if itop_id is None:
            return None
        ticket = session.scalars(select(m.Ticket).where(m.Ticket.itop_ticket_id == itop_id)).first()
        if ticket is None or ticket.finding_group_id != assessment.finding_group_id:
            raise FeedbackRejectedError("unknown_ticket")
        return ticket

    # --- effects (NOT-06) -----------------------------------------------------------------------------------
    def _apply_effects(self, session: Session, rated: _Rated, now: datetime) -> None:
        feedback, assessment, user = rated.feedback, rated.assessment, rated.user
        session.execute(_GROUP_LOCK, {"group_id": assessment.finding_group_id})
        params = {
            "group_id": assessment.finding_group_id,
            "assessment_id": assessment.id,
            "assessed_at": assessment.assessed_at,
        }
        assessed = session.execute(_ASSESSED_FINDINGS, params).all()
        if rated.clicked is not None:
            # Only the clicked ticket and its own CIs (the other custodians' tickets are left alone, TIC-07).
            tickets = [rated.clicked]
            linked = set(session.scalars(_TICKET_FINDINGS, {"ticket_id": rated.clicked.id}).all())
            assessed = [row for row in assessed if row.finding_id in linked]
        else:
            ticket_ids = session.scalars(_RATED_TICKETS, {"finding_ids": [row.finding_id for row in assessed]}).all()
            tickets = [session.get_one(m.Ticket, ticket_id) for ticket_id in ticket_ids]
        if feedback.verdict == "false_positive":
            for row in assessed:
                self._suppress(session, feedback, row.finding_id, row.observed_version, now)
        elif feedback.verdict == "stop_suggestions":
            for ticket in tickets:
                ticket.suggestions_enabled = False
        if feedback.verdict in VERDICT_ES:
            who = user.display_name or user.email
            # TODO(P-009): iTop comments are in Spanish until the configured output language is wired in.
            message = f"Feedback «{VERDICT_ES[feedback.verdict]}» de {who} el {now.date().isoformat()}."
            if feedback.proposed_level:
                message += f" Nivel propuesto: {LEVEL_ES[feedback.proposed_level]}"
                message += f" ({feedback.proposed_score})." if feedback.proposed_score is not None else "."
            for ticket in tickets:
                write = ItopWrite(
                    ticket.id, "comment", comment_payload(message, private=True), f"feedback:{feedback.id}:{ticket.id}"
                )
                record_write(session, write, now)

    @staticmethod
    def _suppress(session: Session, feedback: m.Feedback, finding_id: uuid.UUID, version: str, now: datetime) -> None:
        """ARQ-06: the finding at the assessed version, only while that is still its current version (an older
        version's false positive is kept as feedback but never touches the current suppression); a suppression of
        another, older version is lifted first."""
        if session.scalar(_CURRENT_VERSION, {"finding_id": finding_id}) != version:
            return
        session.execute(_LIFT_OTHER_VERSIONS, {"now": now, "finding_id": finding_id, "version": version})
        session.execute(
            pg_insert(m.Suppression)
            .values(
                finding_id=finding_id,
                feedback_id=feedback.id,
                suppressed_version=version,
                reason="false_positive",
                created_at=now,
            )
            .on_conflict_do_nothing(index_elements=["finding_id"], index_where=text("lifted_at IS NULL"))
        )
