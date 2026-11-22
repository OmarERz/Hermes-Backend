"""Rules for editing sources (D-041, FUE-R4, SEG-15). Role checks belong to the API; these rules hold for everyone.

- Structural sources (NVD, CVE.org, KEV, EPSS, OSV) cannot be switched off.
- A custom feed is added by HTTPS only and enters as N4; N1 is reserved for official sources.
- Every change is written to `audit_log`.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id
from core.ingestion.ssrf import Resolver, UnsafeUrlError, system_resolver, validate_public_url

CUSTOM_KINDS = frozenset({"rss", "atom", "json", "csv", "api"})
CUSTOM_TIER = "N4"
TIERS = ("N1", "N2", "N3", "N4")
_CODE = re.compile(r"^[a-z0-9][a-z0-9_]{1,39}$")
MAX_URL_CHARS = 2048


class SourceRuleError(ValueError):
    """The change breaks a source rule; the message is meant for the person who asked."""


@dataclass(frozen=True)
class Change:
    """Who did what, when, to which source (one `audit_log` row)."""

    actor: uuid.UUID | None
    now: datetime
    action: str
    before: object = None
    after: object = None


def _audit(session: Session, source: m.Source, change: Change) -> None:
    session.add(
        m.AuditLog(
            id=new_id(),
            app_user_id=change.actor,
            action=change.action,
            entity_type="source",
            entity_id=str(source.id),
            before=change.before,
            after=change.after,
            created_at=change.now,
        )
    )


def _get(session: Session, source_id: uuid.UUID) -> m.Source:
    source = session.get(m.Source, source_id)
    if source is None:
        raise SourceRuleError("La fuente no existe")
    return source


def set_source_enabled(
    session: Session, source_id: uuid.UUID, enabled: bool, actor: uuid.UUID | None, now: datetime
) -> m.Source:
    source = _get(session, source_id)
    if source.is_structural and not enabled:
        raise SourceRuleError("Las fuentes estructurales no se pueden apagar")
    if source.enabled != enabled:
        action = "source.enable" if enabled else "source.disable"
        _audit(session, source, Change(actor, now, action, {"enabled": source.enabled}, {"enabled": enabled}))
        source.enabled = enabled
    session.commit()
    return source


def set_trust_tier(
    session: Session, source_id: uuid.UUID, tier: str, actor: uuid.UUID | None, now: datetime
) -> m.Source:
    """Only an admin may call this (API layer). N1 stays reserved for official sources."""
    source = _get(session, source_id)
    if tier not in TIERS:
        raise SourceRuleError("Nivel de confianza desconocido")
    if tier == "N1" and source.is_custom:
        raise SourceRuleError("N1 está reservado para fuentes oficiales")
    if source.trust_tier != tier:
        change = Change(actor, now, "source.trust_tier", {"trust_tier": source.trust_tier}, {"trust_tier": tier})
        _audit(session, source, change)
        source.trust_tier = tier
    session.commit()
    return source


@dataclass(frozen=True)
class NewSource:
    code: str
    name: str
    kind: str
    url: str


def add_custom_source(
    session: Session, new: NewSource, actor: uuid.UUID | None, now: datetime, resolver: Resolver = system_resolver
) -> m.Source:
    """A feed added by an analyst or admin: HTTPS only, public host, level N4, enabled."""
    if not _CODE.match(new.code):
        raise SourceRuleError("El código solo admite minúsculas, dígitos y guion bajo (2 a 40 caracteres)")
    if new.kind not in CUSTOM_KINDS:
        raise SourceRuleError("Tipo de fuente no admitido")
    if not new.name.strip():
        raise SourceRuleError("La fuente necesita un nombre")
    url = new.url.strip()
    if len(url) > MAX_URL_CHARS:
        raise SourceRuleError("La URL es demasiado larga")
    try:
        validate_public_url(url, resolver)
    except UnsafeUrlError as exc:
        raise SourceRuleError(f"URL no permitida: {exc}") from exc
    if session.scalar(select(m.Source.id).where(m.Source.code == new.code)) is not None:
        raise SourceRuleError("Ya existe una fuente con ese código")
    source = m.Source(
        id=new_id(),
        code=new.code,
        name=new.name.strip(),
        kind=new.kind,
        url=url,
        trust_tier=CUSTOM_TIER,
        is_structural=False,
        is_custom=True,
        enabled=True,
        created_by=actor,
        created_at=now,
    )
    session.add(source)
    session.flush()
    after = {"code": new.code, "kind": new.kind, "url": url, "trust_tier": CUSTOM_TIER}
    _audit(session, source, Change(actor, now, "source.create", None, after))
    session.commit()
    return source
