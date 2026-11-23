"""First-run setup wizard (D-042, docs/13 §9): seven steps, each done, skipped or pending.

A step is done when the data already shows it (a profile with its main sector, a peer company, a successful scan…)
or when an admin marked it; a mark is an `audit_log` row (`setup.step`), so the wizard keeps no state of its own and
needs no table. Skipping is only a mark. The wizard never captures nor stores a key: the connections step only
reads the result of the connection checks (SEG-23).
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.db import models as m

ACTION: Final = "setup.step"
ENTITY: Final = "setup_step"
STEPS: Final = (
    "Conexiones",
    "Perfil de la empresa",
    "Empresas pares",
    "Fuentes",
    "Revisión del inventario",
    "Sensibilidad y fórmula",
    "Primer escaneo",
)

# Evidence in the data for steps 2 to 7 (step 1 comes from the connection checks).
_EVIDENCE: Final = text(
    """
    SELECT EXISTS (SELECT 1 FROM profile_sector WHERE is_primary) AS profile,
           EXISTS (SELECT 1 FROM peer_company) AS peers,
           EXISTS (SELECT 1 FROM audit_log WHERE "action" LIKE 'source.%' AND app_user_id IS NOT NULL) AS sources,
           EXISTS (SELECT 1 FROM asset) AS inventory,
           EXISTS (SELECT 1 FROM setting_value WHERE setting_key = 'sensitivity_profile') AS sensitivity,
           EXISTS (SELECT 1 FROM run WHERE kind = 'scan' AND status = 'succeeded') AS first_scan
    """
)
# The latest mark of each step.
_MARKS: Final = text(
    """
    SELECT DISTINCT ON (entity_id) entity_id, "after"
      FROM audit_log WHERE "action" = :action AND entity_type = :entity
     ORDER BY entity_id, created_at DESC, id DESC
    """
)


@dataclass(frozen=True)
class SetupStep:
    n: int
    name: str
    done: bool
    skipped: bool


def _marks(session: Session) -> dict[int, tuple[bool, bool]]:
    marks: dict[int, tuple[bool, bool]] = {}
    for row in session.execute(_MARKS, {"action": ACTION, "entity": ENTITY}):
        after = row.after if isinstance(row.after, dict) else {}
        if row.entity_id.isdigit():
            marks[int(row.entity_id)] = (bool(after.get("done")), bool(after.get("skipped")))
    return marks


def setup_status(session: Session, connections_ok: bool) -> list[SetupStep]:
    """The seven steps. `connections_ok`: every service passed its last connection check."""
    evidence = session.execute(_EVIDENCE).one()
    shown: Mapping[int, bool] = {
        1: connections_ok,
        2: evidence.profile,
        3: evidence.peers,
        4: evidence.sources,
        5: evidence.inventory,
        6: evidence.sensitivity,
        7: evidence.first_scan,
    }
    marks = _marks(session)
    steps: list[SetupStep] = []
    for n, name in enumerate(STEPS, start=1):
        marked_done, marked_skipped = marks.get(n, (False, False))
        done = bool(shown[n]) or marked_done
        steps.append(SetupStep(n=n, name=name, done=done, skipped=marked_skipped and not done))
    return steps


@dataclass(frozen=True)
class Mark:
    done: bool
    skipped: bool
    actor: uuid.UUID | None
    at: datetime


def mark_step(session: Session, n: int, mark: Mark, *, connections_ok: bool) -> SetupStep | None:
    """Record an admin's mark of step `n` (skipping wins over done) and return the step; None if `n` is no step.

    Flushes the audit row; the caller commits.
    """
    if not 1 <= n <= len(STEPS):
        return None
    before = next(s for s in setup_status(session, connections_ok) if s.n == n)
    after = {"done": mark.done and not mark.skipped, "skipped": mark.skipped}
    session.add(
        m.AuditLog(
            app_user_id=mark.actor,
            action=ACTION,
            entity_type=ENTITY,
            entity_id=str(n),
            before={"done": before.done, "skipped": before.skipped},
            after=after,
            created_at=mark.at,
        )
    )
    session.flush()
    return next(s for s in setup_status(session, connections_ok) if s.n == n)
