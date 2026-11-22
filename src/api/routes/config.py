"""Configuration, formula simulation, company profile and peer companies (docs/13 §3 to §4, API-03, API-05).

The services live in `core.configuration`; this module authenticates (the role table), converts and maps errors.
`POST /api/formula/simulate` still answers a sample result: the simulation engine (F4.3) is not integrated yet, but
the changes are already validated against the real active formula.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Path

from api.pagination import PAGINATED_RESPONSES, Page, PageQuery, Signer, paginate
from api.routes._auth import guard
from api.routes._config_support import CurrentUserDep, app_user_id, now, to_api_error
from api.routes._db import SessionDep
from api.routes.models import (
    CompanyProfile,
    ConfigDocument,
    ConfigParameter,
    ConfigUpdate,
    ConfigVersion,
    PeerCompany,
    PeerCompanyInput,
    ProfileUpdate,
    RestoreRequest,
    SimulationRequest,
    SimulationResult,
)
from core.configuration import formula_store, profile, service
from core.configuration.errors import ConfigError, Problem, ValidationFailedError
from core.scoring.formula_repo import load_active_formula

router = APIRouter(tags=["configuration"])
PeerId = Annotated[str, Path(alias="id")]


def _actor(session: SessionDep, user: CurrentUserDep) -> service.Actor:
    return service.Actor(app_user_id(session, user), user.role.value, now())


def _parameter(p: service.Parameter) -> ConfigParameter:
    return ConfigParameter.model_validate(
        {
            "key": p.key,
            "group": p.group,
            "type": p.type,
            "min": p.min,
            "max": p.max,
            "default": p.default,
            "level": p.level,
            "min_role": p.min_role,
            "description": p.description,
            "validations": list(p.validations),
        }
    )


@router.get("/api/config/schema", dependencies=[guard("GET", "/api/config/schema")])
def config_schema(session: SessionDep) -> list[ConfigParameter]:
    """Parameter schema the frontend builds its forms from (API-05): the formula and the settings catalog."""
    return [_parameter(p) for p in service.catalog(session)]


@router.get("/api/config", dependencies=[guard("GET", "/api/config")])
def get_config(session: SessionDep) -> ConfigDocument:
    return ConfigDocument(version=service.current_version(session), values=service.current_values(session))


@router.put("/api/config", dependencies=[guard("PUT", "/api/config")])
def put_config(update: ConfigUpdate, session: SessionDep, user: CurrentUserDep) -> ConfigDocument:
    """Optimistic concurrency: `expected_version` must be the current one, else 409 (API-03).

    The change is one new version, validated per parameter and, for the formula, against FRO-05; each parameter
    carries its own minimum role (API-05).
    """
    try:
        version, values = service.update(session, _actor(session, user), update.expected_version, update.changes)
    except ConfigError as error:
        raise to_api_error(error) from None
    session.commit()  # before answering: the client must not see a success that was not saved
    return ConfigDocument(version=version, values=values)


@router.get("/api/config/versions", dependencies=[guard("GET", "/api/config/versions")], responses=PAGINATED_RESPONSES)
def config_versions(params: PageQuery, signer: Signer, session: SessionDep) -> Page[ConfigVersion]:
    history = [
        ConfigVersion(
            version=entry.version,
            created_at=entry.created_at.isoformat().replace("+00:00", "Z"),
            author=entry.author,
            summary=entry.summary,
        )
        for entry in service.versions(session)
    ]
    return paginate(history, params, signer)


@router.post("/api/config/versions/{v}/restore", dependencies=[guard("POST", "/api/config/versions/{v}/restore")])
def restore_version(v: int, request: RestoreRequest, session: SessionDep, user: CurrentUserDep) -> ConfigDocument:
    """Restores a version as a new one without calling the judge (FRO-08).

    Like every configuration write it carries the expected current version (API-03): 409 if it changed.
    """
    try:
        version, values = service.restore(session, _actor(session, user), v, request.expected_version)
    except ConfigError as error:
        raise to_api_error(error) from None
    session.commit()
    return ConfigDocument(version=version, values=values)


@router.post("/api/formula/simulate", dependencies=[guard("POST", "/api/formula/simulate")])
def simulate(request: SimulationRequest, session: SessionDep) -> SimulationResult:
    """Preview only: it never changes data (FRO-06). The changes are checked against the active formula."""
    foreign = [key for key in request.changes if not formula_store.is_formula_key(key)]
    try:
        if foreign:
            raise ValidationFailedError(
                "Solo los parámetros de la fórmula se pueden simular.",
                tuple(Problem(f"body.changes.{key}", "unknown_parameter") for key in foreign),
            )
        _, formula = load_active_formula(session)
        formula_store.apply_changes(formula, request.changes)
    except ConfigError as error:
        raise to_api_error(error) from None
    return SimulationResult(
        changed_findings=7,
        level_matrix={"high": {"high": 10, "critical": 3}, "medium": {"medium": 22, "high": 4}},
        last_30_days_effect="3 hallazgos habrían subido a Alta en los últimos 30 días",
        top_movers=["CVE-2099-0002 en srv-example-02", "CVE-2099-0003 en srv-proxy-04"],
    )


def _profile_model(value: profile.Profile) -> CompanyProfile:
    return CompanyProfile(
        sector=value.sector,
        subsectors=value.subsectors,
        countries=value.countries,
        language=value.language,
        version=value.version,
    )


@router.get("/api/profile", dependencies=[guard("GET", "/api/profile")])
def get_profile(session: SessionDep) -> CompanyProfile:
    """The company profile; sector and subsectors are catalog codes."""
    return _profile_model(profile.get_profile(session))


@router.put("/api/profile", dependencies=[guard("PUT", "/api/profile")])
def put_profile(update: ProfileUpdate, session: SessionDep, user: CurrentUserDep) -> CompanyProfile:
    who = profile.Writer(app_user_id(session, user), now())
    data = profile.ProfileInput(update.sector, update.subsectors, update.countries, update.language)
    try:
        saved = profile.update_profile(session, who, update.expected_version, data)
    except ConfigError as error:
        raise to_api_error(error) from None
    session.commit()
    return _profile_model(saved)


def _peer_model(peer: profile.Peer) -> PeerCompany:
    return PeerCompany(
        id=peer.id, name=peer.name, aliases=peer.aliases, domain=peer.domain, sector=peer.sector, country=peer.country
    )


def _peer_data(peer: PeerCompanyInput, peer_id: str = "") -> profile.Peer:
    return profile.Peer(peer_id, peer.name, peer.aliases, peer.domain, peer.sector, peer.country)


@router.get("/api/peer-companies", dependencies=[guard("GET", "/api/peer-companies")], responses=PAGINATED_RESPONSES)
def list_peers(params: PageQuery, signer: Signer, session: SessionDep) -> Page[PeerCompany]:
    return paginate([_peer_model(p) for p in profile.list_peers(session)], params, signer)


@router.post("/api/peer-companies", status_code=201, dependencies=[guard("POST", "/api/peer-companies")])
def create_peer(peer: PeerCompanyInput, session: SessionDep, user: CurrentUserDep) -> PeerCompany:
    who = profile.Writer(app_user_id(session, user), now())
    try:
        created = profile.create_peer(session, who, _peer_data(peer))
    except ConfigError as error:
        raise to_api_error(error) from None
    session.commit()
    return _peer_model(created)


@router.put("/api/peer-companies/{id}", dependencies=[guard("PUT", "/api/peer-companies/{id}")])
def update_peer(peer_id: PeerId, peer: PeerCompanyInput, session: SessionDep, user: CurrentUserDep) -> PeerCompany:
    who = profile.Writer(app_user_id(session, user), now())
    try:
        updated = profile.update_peer(session, who, peer_id, _peer_data(peer, peer_id))
    except ConfigError as error:
        raise to_api_error(error) from None
    session.commit()
    return _peer_model(updated)


@router.delete("/api/peer-companies/{id}", status_code=204, dependencies=[guard("DELETE", "/api/peer-companies/{id}")])
def delete_peer(peer_id: PeerId, session: SessionDep, user: CurrentUserDep) -> None:
    who = profile.Writer(app_user_id(session, user), now())
    try:
        profile.delete_peer(session, who, peer_id)
    except ConfigError as error:
        raise to_api_error(error) from None
    session.commit()
