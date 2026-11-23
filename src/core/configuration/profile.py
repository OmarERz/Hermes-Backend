"""Company profile and peer companies (FRO-03, FRO-04, docs/13 §4): sectors and countries as catalog codes.

The profile has one row. Its version is derived from the audit trail (1 plus the number of saved changes), which is
enough for the optimistic check of API-03. Every write is audited in the same transaction.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final

from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session

from core.configuration.errors import (
    ConflictError,
    NotFoundError,
    Problem,
    ValidationFailedError,
    VersionConflictError,
    check_text,
)
from core.db import models as m

PROFILE_LOCK: Final = 7_001_011
PEER_LOCK: Final = 7_001_012
COUNTRY: Final = re.compile(r"^[A-Z]{2}$")
LANGUAGE: Final = re.compile(r"^[a-z]{2}(-[A-Za-z]{2})?$")
GENERIC: Final = "Los datos enviados no son válidos."
MAX_NAME: Final = 200
MAX_ALIASES: Final = 50


@dataclass(frozen=True)
class Profile:
    sector: str
    subsectors: list[str]
    countries: list[str]
    language: str
    version: int


@dataclass(frozen=True)
class ProfileInput:
    sector: str
    subsectors: list[str]
    countries: list[str]
    language: str


@dataclass(frozen=True)
class Peer:
    id: str
    name: str
    aliases: list[str] = field(default_factory=list)
    domain: str | None = None
    sector: str = ""
    country: str = ""


@dataclass(frozen=True)
class Writer:
    user_id: uuid.UUID | None
    now: datetime


def _problem(field_name: str, issue: str, message: str = GENERIC) -> ValidationFailedError:
    return ValidationFailedError(message, (Problem(field_name, issue),))


@dataclass(frozen=True)
class _Entry:
    action: str
    entity: str
    entity_id: str
    before: Any
    after: Any


def _audit(session: Session, who: Writer, entry: _Entry) -> None:
    session.add(
        m.AuditLog(
            app_user_id=who.user_id,
            action=entry.action,
            entity_type=entry.entity,
            entity_id=entry.entity_id,
            before=entry.before,
            after=entry.after,
            created_at=who.now,
        )
    )


# --- profile ------------------------------------------------------------------------------------------------
def _profile_version(session: Session) -> int:
    count = session.scalar(select(func.count()).select_from(m.AuditLog).where(m.AuditLog.action == "profile.update"))
    return 1 + int(count or 0)


def get_profile(session: Session) -> Profile:
    row = session.get(m.CompanyProfile, 1)
    sectors = list(session.scalars(select(m.ProfileSector).order_by(m.ProfileSector.sector_code)))
    primary = next((s.sector_code for s in sectors if s.is_primary), "")
    return Profile(
        sector=primary,
        subsectors=[s.sector_code for s in sectors if not s.is_primary],
        countries=sorted(session.scalars(select(m.ProfileCountry.country_code))),
        language=row.output_language if row else "es",
        version=_profile_version(session),
    )


def _known_sector(session: Session, code: str, field_name: str) -> None:
    if session.get(m.Sector, code) is None:
        raise _problem(field_name, "unknown_sector", "El sector no existe en el catálogo.")


def update_profile(session: Session, who: Writer, expected_version: int, data: ProfileInput) -> Profile:
    session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": PROFILE_LOCK})
    if expected_version != _profile_version(session):
        raise VersionConflictError("El perfil cambió desde que lo leíste; vuelve a cargarlo.")
    check_text("body.sector", data.sector)
    check_text("body.subsectors", *data.subsectors)
    check_text("body.countries", *data.countries)
    if not LANGUAGE.match(data.language):
        raise _problem("body.language", "invalid_language")
    countries = sorted(set(data.countries))
    if len(countries) != len(data.countries) or any(not COUNTRY.match(c) for c in countries):
        raise _problem(
            "body.countries", "invalid_country", "Los países deben ser códigos ISO de dos letras, sin repetir."
        )
    subsectors = sorted(set(data.subsectors))
    if len(subsectors) != len(data.subsectors) or data.sector in subsectors:
        raise _problem("body.subsectors", "duplicate_sector", "Los sectores no deben repetirse.")
    _known_sector(session, data.sector, "body.sector")
    for code in subsectors:
        _known_sector(session, code, "body.subsectors")
    before = get_profile(session)
    row = session.get(m.CompanyProfile, 1)
    if row is None:
        row = m.CompanyProfile(id=1, company_name="", output_language=data.language, updated_at=who.now)
        session.add(row)
    row.output_language, row.updated_by, row.updated_at = data.language, who.user_id, who.now
    session.execute(delete(m.ProfileSector))
    session.execute(delete(m.ProfileCountry))
    session.flush()
    session.add(m.ProfileSector(sector_code=data.sector, is_primary=True))
    session.add_all(m.ProfileSector(sector_code=code, is_primary=False) for code in subsectors)
    session.add_all(m.ProfileCountry(country_code=code) for code in countries)
    session.flush()
    after = Profile(data.sector, subsectors, countries, data.language, before.version)
    _audit(session, who, _Entry("profile.update", "company_profile", "1", _as_dict(before), _as_dict(after)))
    return get_profile(session)


def _as_dict(profile: Profile) -> dict[str, Any]:
    return {
        "sector": profile.sector,
        "subsectors": profile.subsectors,
        "countries": profile.countries,
        "language": profile.language,
    }


# --- peer companies ---------------------------------------------------------------------------------------------
def _peer(session: Session, row: m.PeerCompany) -> Peer:
    aliases = sorted(
        session.scalars(select(m.PeerCompanyAlias.alias).where(m.PeerCompanyAlias.peer_company_id == row.id))
    )
    return Peer(str(row.id), row.name, aliases, row.domain, row.sector_code or "", row.country_code or "")


def list_peers(session: Session) -> list[Peer]:
    return [
        _peer(session, row)
        for row in session.scalars(select(m.PeerCompany).order_by(m.PeerCompany.name, m.PeerCompany.id))
    ]


def _unique_aliases(session: Session, aliases: list[str], own_id: uuid.UUID | None) -> list[str]:
    """Aliases are unique across peers after normalization (`peer_company_alias_normalized`): a clash is a 409."""
    kept: dict[str, str] = {}
    for alias in sorted({" ".join(a.split()) for a in aliases if a.strip()}):
        norm = session.scalar(text("SELECT normalize_text(:a)"), {"a": alias})
        kept.setdefault(str(norm), alias)
    for norm in kept:
        owner = session.scalar(
            text("SELECT peer_company_id FROM peer_company_alias WHERE normalize_text(alias) = :n"), {"n": norm}
        )
        if owner is not None and owner != own_id:
            raise ConflictError(
                "Un alias ya pertenece a otra empresa par.", (Problem("body.aliases", "duplicate_alias"),)
            )
    return sorted(kept.values())


def _validated(session: Session, data: Peer, own_id: uuid.UUID | None = None) -> tuple[str, list[str]]:
    check_text("body.name", data.name)
    check_text("body.aliases", *data.aliases)
    check_text("body.domain", data.domain)
    check_text("body.sector", data.sector)
    check_text("body.country", data.country)
    name = " ".join(data.name.split())
    if not name or len(name) > MAX_NAME:
        raise _problem("body.name", "invalid_name")
    aliases = _unique_aliases(session, data.aliases, own_id)
    if len(aliases) > MAX_ALIASES or any(len(a) > MAX_NAME for a in aliases):
        raise _problem("body.aliases", "invalid_aliases")
    if not COUNTRY.match(data.country):
        raise _problem("body.country", "invalid_country", "El país debe ser un código ISO de dos letras en mayúsculas.")
    _known_sector(session, data.sector, "body.sector")
    return name, aliases


def _check_unique(session: Session, name: str, own_id: uuid.UUID | None) -> None:
    other = session.scalar(select(m.PeerCompany.id).where(func.lower(m.PeerCompany.name) == name.lower()))
    if other is not None and other != own_id:
        raise ConflictError("Ya existe una empresa par con ese nombre.", (Problem("body.name", "duplicate_name"),))


def _write_peer(session: Session, row: m.PeerCompany, data: Peer, name: str, aliases: list[str]) -> None:
    row.name, row.domain = name, (data.domain or "").strip() or None
    row.sector_code, row.country_code = data.sector, data.country
    session.flush()
    session.execute(delete(m.PeerCompanyAlias).where(m.PeerCompanyAlias.peer_company_id == row.id))
    session.add_all(m.PeerCompanyAlias(peer_company_id=row.id, alias=a) for a in aliases)
    session.flush()


def create_peer(session: Session, who: Writer, data: Peer) -> Peer:
    session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": PEER_LOCK})
    name, aliases = _validated(session, data)
    _check_unique(session, name, None)
    row = m.PeerCompany(name=name, created_at=who.now)
    session.add(row)
    _write_peer(session, row, data, name, aliases)
    created = _peer(session, row)
    _audit(session, who, _Entry("peer_company.create", "peer_company", created.id, None, _peer_dict(created)))
    return created


def _find(session: Session, peer_id: str) -> m.PeerCompany:
    try:
        row = session.get(m.PeerCompany, uuid.UUID(peer_id))
    except ValueError:
        row = None
    if row is None:
        raise NotFoundError("La empresa par no existe.")
    return row


def update_peer(session: Session, who: Writer, peer_id: str, data: Peer) -> Peer:
    session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": PEER_LOCK})
    row = _find(session, peer_id)
    name, aliases = _validated(session, data, row.id)
    _check_unique(session, name, row.id)
    before = _peer_dict(_peer(session, row))
    _write_peer(session, row, data, name, aliases)
    updated = _peer(session, row)
    _audit(session, who, _Entry("peer_company.update", "peer_company", updated.id, before, _peer_dict(updated)))
    return updated


def delete_peer(session: Session, who: Writer, peer_id: str) -> None:
    session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": PEER_LOCK})
    row = _find(session, peer_id)
    cited = session.scalar(select(func.count()).select_from(m.NewsVictim).where(m.NewsVictim.peer_company_id == row.id))
    if cited:
        raise ConflictError("La empresa par está citada por noticias y no se puede borrar.")
    before = _peer_dict(_peer(session, row))
    session.execute(delete(m.PeerCompanyAlias).where(m.PeerCompanyAlias.peer_company_id == row.id))
    session.delete(row)
    session.flush()
    _audit(session, who, _Entry("peer_company.delete", "peer_company", peer_id, before, None))


def _peer_dict(peer: Peer) -> dict[str, Any]:
    return {
        "name": peer.name,
        "aliases": peer.aliases,
        "domain": peer.domain,
        "sector": peer.sector,
        "country": peer.country,
    }
