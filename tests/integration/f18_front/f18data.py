"""The F18.1 scenario: the F10.2 findings scenario (tests/integration/f10_findings/f10data.py) plus activity of the
last hours, so the windows of the telemetry and the timeline are tested against the real clock.

Recent activity (relative to now):
  runs     scan succeeded by Ana (-3 h, 10 min) · news failed (-2 h) · nightly running (-10 min)
  reviews  judge applied 1 000 ms · judge no_judge_review 3 000 ms · cve_analyst applied 500 ms (all -1 h)
  config   one change by Ana (-30 min), version 2
  software "Software sin mapeo CPE" (no CPE) installed on CI-2 with version "N/A" (unknown)
"""

from __future__ import annotations

import importlib.util
import sys
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import ModuleType
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db import models as m


def _load_f10data() -> ModuleType:
    """The F10.2 scenario module, loaded from its file (test folders are not packages)."""
    if "f10data" in sys.modules:
        return sys.modules["f10data"]
    path = Path(__file__).resolve().parents[1] / "f10_findings" / "f10data.py"
    spec = importlib.util.spec_from_file_location("f10data", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["f10data"] = module
    spec.loader.exec_module(module)
    return module


f10data = _load_f10data()
NOW = datetime.now(UTC)


@dataclass
class Front:
    scenario: Any  # f10data.Scenario
    ana: uuid.UUID
    runs: dict[str, uuid.UUID] = field(default_factory=dict)
    reviews: dict[str, uuid.UUID] = field(default_factory=dict)
    updates: dict[str, uuid.UUID] = field(default_factory=dict)
    event: uuid.UUID | None = None


@dataclass(frozen=True)
class ReviewSpec:
    agent: str
    status: str
    latency: int
    at: datetime
    second_of: uuid.UUID | None = None
    proposed: int | None = None


def _review(session: Session, spec: ReviewSpec) -> uuid.UUID:
    agent, status, latency, at = spec.agent, spec.status, spec.latency, spec.at
    review = m.LlmReview(
        agent=agent,
        mode="scoring" if agent == "judge" else None,
        second_review_of_id=spec.second_of,
        model="deepseek-v4-pro",
        response_model={},
        prompt_version="v1",
        prompt_hash="h",
        schema_version="1",
        schema_hash="h",
        parameters={},
        input_ref="pkg",
        calls=[],
        status=status,
        attempts=2 if status == "no_judge_review" else 1,
        proposed_adjustment=spec.proposed,
        tokens_input=1000,
        tokens_cached=100,
        tokens_output=200,
        tokens_reasoning=0,
        cost_usd=Decimal("0.020000"),
        latency_ms=latency,
        ladder_level=0,
        created_at=at,
    )
    session.add(review)
    session.flush()
    return review.id


def _run(
    session: Session, kind: str, status: str, span: tuple[datetime, datetime | None], by: uuid.UUID | None
) -> uuid.UUID:
    start, end = span
    run = m.Run(
        kind=kind,
        status=status,
        progress=100 if end else 50,
        trigger_reason="manual" if by else "schedule",
        triggered_by=by,
        started_at=start,
        finished_at=end,
    )
    session.add(run)
    session.flush()
    return run.id


def build_front(session: Session) -> Front:
    scenario = f10data.build_scenario(session)
    ana = session.scalars(select(m.AppUser.id).where(m.AppUser.firebase_uid == "u-ana")).one()
    front = Front(scenario, ana)
    hour = timedelta(hours=1)
    front.runs["scan"] = _run(
        session, "scan", "succeeded", (NOW - 3 * hour, NOW - 3 * hour + timedelta(minutes=10)), ana
    )
    front.runs["news"] = _run(session, "news", "failed", (NOW - 2 * hour, NOW - 2 * hour + timedelta(minutes=1)), None)
    front.runs["nightly"] = _run(session, "nightly", "running", (NOW - timedelta(minutes=10), None), None)
    front.reviews["applied"] = _review(session, ReviewSpec("judge", "applied", 1000, NOW - hour))
    front.reviews["fallback"] = _review(session, ReviewSpec("judge", "no_judge_review", 3000, NOW - hour))
    front.reviews["cve"] = _review(session, ReviewSpec("cve_analyst", "applied", 500, NOW - hour))
    session.add(
        m.AuditLog(
            app_user_id=ana,
            action="config.update",
            entity_type="config",
            entity_id="2",
            before={"dead_zone": "4"},
            after={"values": {"dead_zone": "5"}, "summary": "Cambió: dead_zone"},
            created_at=NOW - timedelta(minutes=30),
        )
    )
    unmapped = session.scalars(
        select(m.SoftwareProduct.id).where(m.SoftwareProduct.itop_name == "Software sin mapeo CPE")
    ).one()
    session.add(
        m.InstalledSoftware(
            itop_instance_id="SI-90",
            asset_id=scenario.assets["CI-2"],
            software_product_id=unmapped,
            version="N/A",
            synced_at=NOW,
        )
    )
    session.flush()
    add_ticket_activity(session, front)
    return front


def add_ticket_activity(session: Session, front: Front) -> None:
    """Ticket R-000777 (G1): created (A2) and urgency raised; its iTop writes done and failed. Ticket 778 (G2):
    resolved 6 h after its creation in iTop and changed by a person. A second blind review of A2's review that
    agreed (+10). The error queue: a failed event, the failed iTop write and an LLM item that did not validate."""
    sc = front.scenario
    t777 = session.scalars(select(m.Ticket).where(m.Ticket.itop_ticket_id == "777")).one()
    t778 = session.scalars(select(m.Ticket).where(m.Ticket.itop_ticket_id == "778")).one()
    t778.resolved_at = t778.itop_created_at + timedelta(hours=6)  # type: ignore[operator]
    t778.last_human_change_at = NOW - timedelta(hours=5)
    t778.last_human_change_by = "agente.itop"
    hour = timedelta(hours=1)
    created = m.TicketUpdate(
        ticket_id=t777.id, action="create", assessment_id=sc.assessments["A2"], created_at=NOW - 4 * hour
    )
    raised = m.TicketUpdate(ticket_id=t777.id, action="raise_urgency", assessment_id=None, created_at=NOW - 3 * hour)
    session.add_all([created, raised])
    session.flush()
    front.updates["create"], front.updates["raise"] = created.id, raised.id
    for update, status in ((created, "done"), (raised, "failed")):
        session.add(
            m.ItopOutbox(
                ticket_update_id=update.id,
                idempotency_key=f"key-{update.id}",
                operation="create" if update is created else "update",
                payload={},
                status=status,
                attempts=1 if status == "done" else 5,
                last_error=None if status == "done" else "iTop respondió 500",
                created_at=update.created_at,
                done_at=update.created_at if status == "done" else None,
            )
        )
    event = m.NotificationEvent(
        contract_version="1.0",
        event_type="new_ticket",
        priority="immediate",
        ticket_id=t777.id,
        assessment_id=sc.assessments["A2"],
        payload={},
        status="failed",
        attempts=6,
        last_error="Slack no respondió",
        created_at=NOW - 2 * hour,
    )
    session.add(event)
    session.add(
        m.ErrorQueue(
            component="cve_analyst",
            cve_id="CVE-2026-10002",
            reason="L7: la salida no cumple el esquema",
            attempts=2,
            next_attempt_at=NOW + hour,
            status="pending",
            created_at=NOW - 90 * timedelta(minutes=1),
        )
    )
    session.flush()
    front.event = event.id
    first_review = session.scalars(
        select(m.Assessment.llm_review_id).where(m.Assessment.id == sc.assessments["A2"])
    ).one()
    front.reviews["first"] = first_review
    # Stored right after the first review (T1), so it stays out of the 24 h window of the telemetry tests.
    second = ReviewSpec("judge", "applied", 800, f10data.T1 + timedelta(minutes=1), second_of=first_review, proposed=10)
    front.reviews["second"] = _review(session, second)
