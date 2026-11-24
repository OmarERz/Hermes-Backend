"""The F18.1 scenario: the F10.2 findings scenario (tests/integration/f10_findings/f10data.py) plus activity of the
last hours, so the windows of the telemetry and the timeline are tested against the real clock.

Recent activity (relative to now):
  runs     scan succeeded by Ana (-3 h, 10 min) · news failed (-2 h) · nightly running (-10 min)
  reviews  judge applied 1 000 ms · judge no_judge_review 3 000 ms · cve_analyst applied 500 ms (all -1 h)
  config   one change by Ana (-30 min), version 2
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


def _review(session: Session, agent: str, status: str, latency: int, at: datetime) -> uuid.UUID:
    review = m.LlmReview(
        agent=agent,
        mode="scoring" if agent == "judge" else None,
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
        proposed_adjustment=None,
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
    front.reviews["applied"] = _review(session, "judge", "applied", 1000, NOW - hour)
    front.reviews["fallback"] = _review(session, "judge", "no_judge_review", 3000, NOW - hour)
    front.reviews["cve"] = _review(session, "cve_analyst", "applied", 500, NOW - hour)
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
    session.flush()
    return front
