"""Rules for editing sources (D-041, FUE-R4, SEG-15, SEG-28). The API authenticates; these rules re-check the role.

- Structural sources (NVD, CVE.org, KEV, EPSS, OSV) cannot be switched off; their codes are reserved.
- A custom feed is added by an admin, over HTTPS, without secrets in the URL, and enters as N4.
- Only an admin changes a trust level, and N1 is reserved for the official (structural) sources.
- An analyst or admin switches optional sources on and off.
- Every change is written to `audit_log` (the URL without its query string).
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import parse_qsl, urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id
from core.ingestion.catalog import DEFAULT_SOURCES
from core.ingestion.ssrf import Resolver, UnsafeUrlError, system_resolver, validate_public_url

CUSTOM_KINDS = frozenset({"rss", "atom", "json", "csv", "api"})
CUSTOM_TIER = "N4"
TIERS = ("N1", "N2", "N3", "N4")
_CODE = re.compile(r"^[a-z0-9][a-z0-9_]{1,39}$")
MAX_URL_CHARS = 2048
RESERVED_CODES = frozenset(definition.code for definition in DEFAULT_SOURCES)
_SECRET_PARAMS = re.compile(r"token|key|secret|passw|auth|signature|sig$|credential", re.IGNORECASE)


class SourceRuleError(ValueError):
    """The change breaks a source rule; the message is meant for the person who asked."""


class SourcePermissionError(SourceRuleError):
    """The user's role does not allow the change."""


class SourceNotFoundError(SourceRuleError):
    """The source does not exist."""


class SourceConflictError(SourceRuleError):
    """The change clashes with what the source is (a structural source cannot be switched off)."""


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


def _require_role(session: Session, actor: uuid.UUID | None, allowed: tuple[str, ...]) -> uuid.UUID:
    user = session.get(m.AppUser, actor) if actor is not None else None
    if user is None or not user.active or user.role not in allowed:
        raise SourcePermissionError("No tienes permiso para este cambio")
    return user.id


def _get(session: Session, source_id: uuid.UUID) -> m.Source:
    source = session.get(m.Source, source_id)
    if source is None:
        raise SourceNotFoundError("La fuente no existe")
    return source


def set_source_enabled(
    session: Session, source_id: uuid.UUID, enabled: bool, actor: uuid.UUID | None, now: datetime
) -> m.Source:
    actor = _require_role(session, actor, ("analyst", "admin"))
    source = _get(session, source_id)
    if source.is_structural and not enabled:
        raise SourceConflictError("Las fuentes estructurales no se pueden apagar")
    if source.enabled != enabled:
        action = "source.enable" if enabled else "source.disable"
        _audit(session, source, Change(actor, now, action, {"enabled": source.enabled}, {"enabled": enabled}))
        source.enabled = enabled
    session.commit()
    return source


def set_trust_tier(
    session: Session, source_id: uuid.UUID, tier: str, actor: uuid.UUID | None, now: datetime
) -> m.Source:
    """Only an admin changes a trust level; N1 stays reserved for the official (structural) sources."""
    actor = _require_role(session, actor, ("admin",))
    source = _get(session, source_id)
    if tier not in TIERS:
        raise SourceRuleError("Nivel de confianza desconocido")
    if tier == "N1" and not source.is_structural:
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
    actor = _require_role(session, actor, ("admin",))
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
    if any(_SECRET_PARAMS.search(name) for name, _ in parse_qsl(urlsplit(url).query)):
        raise SourceRuleError("La URL no debe llevar llaves ni tokens: van en la configuración del servidor")
    if new.code in RESERVED_CODES or session.scalar(select(m.Source.id).where(m.Source.code == new.code)) is not None:
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
    parts = urlsplit(url)
    logged_url = f"{parts.scheme}://{parts.hostname}{parts.path}"  # no query string in the audit trail
    after = {"code": new.code, "kind": new.kind, "url": logged_url, "trust_tier": CUSTOM_TIER}
    _audit(session, source, Change(actor, now, "source.create", None, after))
    session.commit()
    return source
