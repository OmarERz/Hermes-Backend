"""Ticket lifecycle per custodian (D-036, TIC-01..TIC-07): one decision pass per assessment of a group.

For each assessment the pass: groups the current findings by the custodian of their CI (no custodian → the default
team, P-020), links new CIs, moves CIs whose custodian changed, unlinks decommissioned CIs and then, per ticket,
decides what to write in iTop and which events to emit. Every iTop write goes through the outbox and every event
through `notification_event`, in the caller's transaction (ARQ-01, NOT-02). The pass is idempotent per assessment:
every write's key is (action, ticket, assessment).

Rules (docs/08 §1): a ticket for any score; CI added → updated list + comment; persists → comment on scans; rises →
urgency up + `level_up` unless a person changed the urgency (then a private suggestion, D-007); falls → only after
the hysteresis (D-006); some CIs fixed → comment + `partially_fixed`; all fixed → comment + `fixed` (a person
closes it); back after resolved/closed → reopen (or a new request if iTop cannot reopen) + `reopened`. A false
positive (suppression) never opens a ticket nor emits events for it (ARQ-06).
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from core.db import models as m
from core.itop.outbox import (
    IMPACT_CODES,
    ItopWrite,
    comment_payload,
    create_payload,
    record_write,
    stimulus_payload,
    update_payload,
)
from core.notifications.events import EventRecorder, TicketEvent, TicketEventType
from core.tickets import content
from core.tickets.context import linked_asset_ids, load_context, score_history
from core.tickets.rules import (
    CiFacts,
    Hysteresis,
    PriorityThresholds,
    UrgencyAction,
    UrgencyBands,
    impact,
    level,
    priority,
    target_urgency,
    urgency_action,
)

log = logging.getLogger("core.tickets.lifecycle")

LEVEL_ES: Final = content.LEVEL_ES

_FINDINGS: Final = text(
    """
    SELECT fc.finding_id, fc.status, fc.fixed_at, a.name AS asset_name, a.custodian_team_id,
           a.decommissioned_at IS NOT NULL AS decommissioned,
           EXISTS (SELECT 1 FROM suppression s WHERE s.finding_id = fc.finding_id AND s.lifted_at IS NULL
                     AND s.suppressed_version = fc.observed_version)
             AS suppressed
      FROM finding_current fc
      JOIN installed_software i ON i.id = fc.installed_software_id
      JOIN asset a ON a.id = i.asset_id
     WHERE fc.finding_group_id = :group_id
     ORDER BY a.name, fc.finding_id
    """
)
# ARQ-06: a false positive lasts until the finding's version changes; then the suppression is lifted.
_LIFT_STALE_SUPPRESSIONS: Final = text(
    """UPDATE suppression s SET lifted_at = :now, lift_reason = 'version_changed'
    FROM finding_current fc
    WHERE s.finding_id = fc.finding_id AND fc.finding_group_id = :group_id
      AND s.lifted_at IS NULL AND s.suppressed_version <> fc.observed_version"""
)
_SETTING: Final = text("SELECT value FROM setting_current WHERE setting_key = :key")
_LAST_FIX_REPORT: Final = text(
    """
    SELECT max(created_at) FROM ticket_update
     WHERE ticket_id = :ticket_id AND action IN ('partial_fix', 'fix_comment')
    """
)


@dataclass(frozen=True)
class _Finding:
    finding_id: uuid.UUID
    status: str
    fixed_at: datetime | None
    asset_name: str
    team_id: uuid.UUID | None
    decommissioned: bool
    suppressed: bool

    @property
    def current(self) -> bool:
        return self.status != "fixed" and not self.decommissioned


@dataclass
class _Plan:
    """What changed on one ticket during this pass, before deciding its writes."""

    created: bool = False
    added: list[_Finding] = field(default_factory=list)
    moved_out: list[tuple[_Finding, str]] = field(default_factory=list)
    decommissioned: list[_Finding] = field(default_factory=list)


@dataclass(frozen=True)
class _Params:
    bands: UrgencyBands
    hysteresis: Hysteresis
    thresholds: PriorityThresholds
    global_suggestions: bool
    default_team: m.Team | None
    scan: bool


@dataclass(frozen=True)
class LifecycleReport:
    created: int
    events: int
    writes: int


@dataclass
class TicketLifecycle:
    """Applies the ticket rules to one group after one of its assessments."""

    identity: content.ItopIdentity
    itop_base_url: str | None = None
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def apply(self, session: Session, assessment_id: uuid.UUID) -> LifecycleReport:
        """Run the pass in the caller's transaction; the group is locked for its duration (ARQ-04)."""
        assessment = session.get_one(m.Assessment, assessment_id)
        if assessment.finding_group_id is None:
            raise ValueError("ticket rules apply to group assessments, not to alerts")
        group_id = assessment.finding_group_id
        session.execute(select(m.FindingGroup.id).where(m.FindingGroup.id == group_id).with_for_update())
        params = self._params(session, assessment)
        now = self.clock()
        session.execute(_LIFT_STALE_SUPPRESSIONS, {"now": now, "group_id": group_id})
        state = _Pass(self, session, assessment, params, now)
        state.relink(self._findings(session, group_id, params))
        for ticket in state.tickets.values():
            state.decide(ticket)
        return LifecycleReport(created=state.created, events=state.events, writes=state.writes)

    # --- inputs --------------------------------------------------------------------------------------------
    @staticmethod
    def _findings(session: Session, group_id: uuid.UUID, params: _Params) -> list[_Finding]:
        findings = []
        for row in session.execute(_FINDINGS, {"group_id": group_id}).all():
            team_id = row.custodian_team_id or (params.default_team.id if params.default_team else None)
            if team_id is None:
                # TODO(P-020): no custodian and no default team configured: the finding waits for one.
                log.warning("finding %s has no custodian and there is no default team", row.finding_id)
            findings.append(
                _Finding(
                    row.finding_id,
                    row.status,
                    row.fixed_at,
                    row.asset_name,
                    team_id,
                    bool(row.decommissioned),
                    bool(row.suppressed),
                )
            )
        return findings

    @staticmethod
    def _params(session: Session, assessment: m.Assessment) -> _Params:
        version = session.get_one(m.FormulaVersion, assessment.formula_version_id)
        bands = session.scalars(
            select(m.FormulaUrgencyBand).where(m.FormulaUrgencyBand.formula_version_id == version.id)
        ).all()

        def setting(key: str, default: Any) -> Any:
            value = session.scalar(_SETTING, {"key": key})
            return default if value is None else value

        run = session.get_one(m.Run, assessment.run_id)
        return _Params(
            bands=UrgencyBands({band.urgency: band.min_score for band in bands}),
            hysteresis=Hysteresis(version.hysteresis_margin, version.hysteresis_evaluations, version.hysteresis_days),
            thresholds=PriorityThresholds(
                int(setting("event_priority.immediate", 90)), int(setting("event_priority.normal", 50))
            ),
            global_suggestions=bool(setting("human_ticket_suggestions", True)),
            default_team=_default_team(session, setting("default_team", None)),
            scan=run.kind == "scan",
        )


def _default_team(session: Session, name: object) -> m.Team | None:
    """P-020: the live team the `default_team` setting names (same name, ignoring case and surrounding spaces),
    else a live team flagged `is_default`.

    The inventory sync creates every team unflagged and nothing else sets the flag, so before this a CI without
    custodian never got its ticket (F20 dry run, P2-2): the setting is what the spec makes configurable (docs/11).
    """
    teams = session.scalars(select(m.Team).where(m.Team.removed_at.is_(None)).order_by(m.Team.itop_team_id)).all()
    wanted = name.strip().casefold() if isinstance(name, str) else ""
    if wanted:
        named = next((team for team in teams if team.name.strip().casefold() == wanted), None)
        if named is not None:
            return named
        log.warning("the default_team setting names no team of the inventory")
    return next((team for team in teams if team.is_default), None)


@dataclass
class _Pass:
    """State of one lifecycle pass over a group."""

    owner: TicketLifecycle
    session: Session
    assessment: m.Assessment
    params: _Params
    now: datetime
    tickets: dict[uuid.UUID, m.Ticket] = field(default_factory=dict)
    plans: dict[uuid.UUID, _Plan] = field(default_factory=dict)
    created: int = 0
    events: int = 0
    writes: int = 0
    findings: dict[uuid.UUID, _Finding] = field(default_factory=dict)

    def __post_init__(self) -> None:
        rows = self.session.scalars(
            select(m.Ticket).where(m.Ticket.finding_group_id == self.assessment.finding_group_id)
        ).all()
        self.tickets = {ticket.custodian_team_id: ticket for ticket in rows}

    def plan(self, ticket: m.Ticket) -> _Plan:
        return self.plans.setdefault(ticket.id, _Plan())

    # --- links ---------------------------------------------------------------------------------------------
    def relink(self, findings: list[_Finding]) -> None:
        self.findings = {f.finding_id: f for f in findings}
        by_id = {ticket.id: ticket for ticket in self.tickets.values()}
        links = {
            link.finding_id: link
            for link in self.session.scalars(
                select(m.TicketFinding).where(
                    m.TicketFinding.ticket_id.in_(list(by_id)), m.TicketFinding.removed_at.is_(None)
                )
            ).all()
        }
        for finding in findings:
            link = links.get(finding.finding_id)
            if link is None:
                continue
            ticket = by_id[link.ticket_id]
            if finding.decommissioned:
                link.removed_at, link.removal_reason = self.now, "decommissioned"
                self.plan(ticket).decommissioned.append(finding)
                del links[finding.finding_id]
            elif finding.current and finding.team_id is not None and finding.team_id != ticket.custodian_team_id:
                link.removed_at, link.removal_reason = self.now, "moved"
                new_team = self.session.get_one(m.Team, finding.team_id)
                self.plan(ticket).moved_out.append((finding, new_team.name))
                del links[finding.finding_id]
        self.session.flush()
        for finding in findings:
            if not finding.current or finding.finding_id in links or finding.team_id is None:
                continue
            target = self.tickets.get(finding.team_id)
            if target is None:
                if finding.suppressed:
                    continue  # a false positive never opens a ticket (ARQ-06)
                target = self._new_ticket(finding.team_id)
            self.session.add(m.TicketFinding(ticket_id=target.id, finding_id=finding.finding_id, added_at=self.now))
            self.plan(target).added.append(finding)
        self.session.flush()

    def _new_ticket(self, team_id: uuid.UUID) -> m.Ticket:
        ticket = m.Ticket(
            finding_group_id=self.assessment.finding_group_id,
            custodian_team_id=team_id,
            status="pending_creation",
            suggestions_enabled=True,
            created_at=self.now,
        )
        self.session.add(ticket)
        self.session.flush()
        self.tickets[team_id] = ticket
        self.plan(ticket).created = True
        self.created += 1
        return ticket

    # --- decisions -----------------------------------------------------------------------------------------
    def decide(self, ticket: m.Ticket) -> None:
        plan = self.plan(ticket)
        context = load_context(self.session, ticket, self.assessment)
        current = context.current_cis
        unchanged = not (plan.created or plan.added or plan.moved_out or plan.decommissioned)
        if unchanged and self._already_decided(ticket) and not self._unreported_fixes(ticket):
            # Already applied to this ticket with this assessment; only new fixes (a later scan with no new
            # assessment, e.g. every CI fixed) are worth another pass.
            return
        history = score_history(self.session, ticket, linked_asset_ids(self.session, ticket.id))
        previous = self._previous_score(ticket)
        if plan.created:
            self._create(ticket, context, "new_ticket", previous)
            return
        if ticket.status in ("resolved", "closed") and current:
            self._reopen(ticket, context, previous)
            if ticket.status == "pending_creation":
                return
        notes: list[str] = []
        if ticket.status == "pending_creation":
            # The queued create was built earlier: CI changes since then go as writes queued behind it.
            self._ci_changes(ticket, context, plan, notes)
            if notes:
                self._write(ticket, "comment", comment_payload("\n".join(notes)))
            return
        events: list[TicketEventType] = []
        self._ci_changes(ticket, context, plan, notes)
        self._fixes(ticket, context, notes, events)
        if context.score is not None and history:
            self._urgency(ticket, context, history, notes, events)
        if self.params.scan and current and not notes and not events:
            notes.append(f"Sigue presente en el escaneo del {self.now.date().isoformat()}.")
        if notes:
            self._write(ticket, "comment", comment_payload("\n".join(notes)))
        for event_type in events:
            self._event(ticket, context, event_type, previous)

    def _already_decided(self, ticket: m.Ticket) -> bool:
        found = self.session.scalar(
            select(m.TicketUpdate.id)
            .where(m.TicketUpdate.ticket_id == ticket.id, m.TicketUpdate.assessment_id == self.assessment.id)
            .limit(1)
        )
        return found is not None

    def _previous_score(self, ticket: m.Ticket) -> int | None:
        """The ticket score in the latest earlier assessment, over every linked CI (fixed ones included)."""
        everything = linked_asset_ids(self.session, ticket.id, current_only=False)
        earlier = [s for at, s in score_history(self.session, ticket, everything) if at < self.assessment.assessed_at]
        return earlier[-1] if earlier else None

    def _create(
        self, ticket: m.Ticket, context: content.TicketContext, event: TicketEventType, previous: int | None
    ) -> None:
        if not context.current_cis:
            return
        urgency = (
            self.params.bands.urgency(context.score) if context.score is not None else max(self.params.bands.minimums)
        )
        facts = [CiFacts(ci.criticality, ci.exposed) for ci in context.current_cis]
        fields = content.create_fields(context, self.owner.identity, urgency, impact(facts))
        default = self.params.default_team
        fallback = default.itop_team_id if default is not None else None
        self._write(ticket, "create", create_payload(fields, fallback_team_id=fallback))
        self._event(ticket, context, event, previous, urgency=urgency)

    def _reopen(self, ticket: m.Ticket, context: content.TicketContext, previous: int | None) -> None:
        if ticket.status == "resolved":
            self._write(ticket, "reopen", stimulus_payload("ev_reopen"))
            ticket.status = "open"
            self._event(ticket, context, "reopened", previous)
            return
        # A closed UserRequest cannot be reopened in iTop: a new request replaces it on the same ticket row.
        old_ref = ticket.itop_ref
        ticket.status, ticket.itop_ticket_id, ticket.itop_ref, ticket.closed_at = "pending_creation", None, None, None
        ticket.current_urgency, ticket.last_human_change_at, ticket.last_human_change_by = None, None, None
        ticket.itop_created_at, ticket.resolved_at = None, None  # the new request has its own dates (MTTR)
        self.session.flush()
        self._create(ticket, context, "reopened", previous)
        log.info("ticket %s re-created after %s was closed", ticket.id, old_ref)

    def _ci_changes(self, ticket: m.Ticket, context: content.TicketContext, plan: _Plan, notes: list[str]) -> None:
        if not (plan.added or plan.moved_out or plan.decommissioned):
            return
        fields: dict[str, Any] = {"functionalcis_list": content.ci_links(context.cis)}
        owners_before = {
            ci.owner_itop_id for ci in context.current_cis if ci.name not in {f.asset_name for f in plan.added}
        }
        if any(ci.owner_itop_id not in owners_before for ci in context.current_cis if ci.owner_itop_id):
            fields["contacts_list"] = content.owner_contacts(context.cis)
        self._write(ticket, "add_ci" if plan.added else "comment", update_payload(fields), key="ci_list")
        notes += [f"Se agregó el CI {f.asset_name}." for f in plan.added]
        notes += [f"El CI {f.asset_name} pasó al equipo {team}." for f, team in plan.moved_out]
        notes += [f"El CI {f.asset_name} se dio de baja en iTop." for f in plan.decommissioned]

    def _unreported_fixes(self, ticket: m.Ticket) -> list[_Finding]:
        """Linked findings fixed after the last fix comment of the ticket (or its creation)."""
        since = self.session.scalar(_LAST_FIX_REPORT, {"ticket_id": ticket.id}) or ticket.created_at
        linked = self.session.scalars(
            select(m.TicketFinding.finding_id).where(
                m.TicketFinding.ticket_id == ticket.id, m.TicketFinding.removed_at.is_(None)
            )
        ).all()
        return [
            f
            for fid in linked
            if (f := self.findings.get(fid)) is not None and f.status == "fixed" and f.fixed_at and f.fixed_at > since
        ]

    def _fixes(
        self, ticket: m.Ticket, context: content.TicketContext, notes: list[str], events: list[TicketEventType]
    ) -> None:
        fixed_now = self._unreported_fixes(ticket)
        if not fixed_now:
            return
        total, fixed = len(context.cis), sum(1 for ci in context.cis if ci.fixed)
        names = ", ".join(sorted({f.asset_name for f in fixed_now}))
        date = self.now.date().isoformat()
        if fixed == total:
            message = (
                f"No detectado en el escaneo del {date}: todos los CIs están corregidos. Una persona debe cerrarlo."
            )
            self._write(ticket, "fix_comment", comment_payload(message))
            events.append("fixed")
        else:
            self._write(ticket, "partial_fix", comment_payload(f"Corregido en {names}; {fixed} de {total} corregidos."))
            events.append("partially_fixed")

    def _urgency(
        self,
        ticket: m.Ticket,
        context: content.TicketContext,
        history: list[tuple[datetime, int]],
        notes: list[str],
        events: list[TicketEventType],
    ) -> None:
        current = ticket.current_urgency
        if current is None:
            return  # still being created: the create carries the urgency
        target = target_urgency(current, history, self.params.bands, self.params.hysteresis, self.now)
        action = urgency_action(
            current,
            target,
            human_changed=ticket.last_human_change_at is not None,
            ticket_suggestions=ticket.suggestions_enabled,
            global_suggestions=self.params.global_suggestions,
        )
        label = LEVEL_ES[level(target)]
        if action in (UrgencyAction.RAISE, UrgencyAction.LOWER):
            facts = [CiFacts(ci.criticality, ci.exposed) for ci in context.current_cis]
            fields = {"urgency": str(target), "impact": IMPACT_CODES[impact(facts)]}
            name = "raise_urgency" if action is UrgencyAction.RAISE else "lower_urgency"
            self._write(ticket, name, update_payload(fields))
            notes.append(
                f"Urgencia {'subida' if action is UrgencyAction.RAISE else 'bajada'} a {target} ({label}): "
                f"puntuación {context.score}, impulsada por {context.driving_ci}."
            )
            if action is UrgencyAction.RAISE:
                events.append("level_up")
        elif action is UrgencyAction.SUGGEST:
            who = ticket.last_human_change_by or "una persona"
            suggestion = (
                f"Sugerencia de Hermes: urgencia {target} ({label}) por la puntuación {context.score}. "
                f"No se cambió porque {who} modificó la urgencia."
            )
            self._write(ticket, "suggest", comment_payload(suggestion, private=True))
        elif action is UrgencyAction.AUDIT_ONLY:
            self.session.add(
                m.TicketUpdate(
                    ticket_id=ticket.id, action="suggest", assessment_id=self.assessment.id, created_at=self.now
                )
            )
        elif self.params.bands.urgency(history[-1][1]) > current:
            notes.append(
                f"La puntuación bajó a {history[-1][1]}; la urgencia baja cuando se cumpla la histéresis (D-006)."
            )

    # --- outputs -------------------------------------------------------------------------------------------
    def _write(self, ticket: m.Ticket, action: str, payload: dict[str, Any], *, key: str | None = None) -> None:
        idempotency_key = f"{key or action}:{ticket.id}:{self.assessment.id}"
        write = ItopWrite(ticket.id, action, payload, idempotency_key, self.assessment.id)
        if record_write(self.session, write, self.now) is not None:
            self.writes += 1

    def _event(
        self,
        ticket: m.Ticket,
        context: content.TicketContext,
        event_type: TicketEventType,
        previous: int | None,
        *,
        urgency: int | None = None,
    ) -> None:
        linked = self.session.scalars(
            select(m.TicketFinding.finding_id).where(
                m.TicketFinding.ticket_id == ticket.id, m.TicketFinding.removed_at.is_(None)
            )
        ).all()
        current = [f for fid in linked if (f := self.findings.get(fid)) is not None and f.current]
        if event_type != "fixed" and current and all(f.suppressed for f in current):
            return  # every current finding is a false positive: no events for it (ARQ-06)
        score = context.score if context.score is not None else previous
        if urgency is None and context.score is not None:
            urgency = self.params.bands.urgency(context.score)
        event = TicketEvent(
            event_type=event_type,
            priority=priority(score, self.params.thresholds),
            urgency=urgency if urgency is not None else ticket.current_urgency,
            previous=previous,
            assessment_id=self.assessment.id,
        )
        EventRecorder(self.owner.itop_base_url).record(self.session, ticket, context, event, self.now)
        self.events += 1
