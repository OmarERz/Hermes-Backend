"""Configuration, formula simulation, company profile and peer companies (docs/13 §3 to §4, API-03, API-05)."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Annotated

from fastapi import APIRouter, Depends

from api.auth import CurrentUser, Role, get_current_user
from api.errors import ApiError, ErrorDetail
from api.pagination import Page, PageQuery, Signer, paginate
from api.routes import samples
from api.routes._auth import guard
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

router = APIRouter(tags=["configuration"])
CurrentUserDep = Annotated[CurrentUser, Depends(get_current_user)]


def _stale() -> ApiError:
    return ApiError(409, "version_conflict", "La configuración cambió desde que la leíste; vuelve a cargarla.")


def _validated_weights(changes: dict[str, str]) -> None:
    """FRO-05: the partial edit is merged with every current weight; each must be in 0..1 and the total exactly 1.0."""
    if not any(key.startswith("weights.") for key in changes):
        return
    merged = {k: v for k, v in samples.CONFIG_VALUES.items() if k.startswith("weights.")}
    merged.update({k: v for k, v in changes.items() if k.startswith("weights.")})
    try:
        values = {key: Decimal(value) for key, value in merged.items()}
    except InvalidOperation:
        raise ApiError(
            422,
            "validation_error",
            "Los datos enviados no son válidos.",
            [ErrorDetail(field="body.changes", issue="invalid_decimal")],
        ) from None
    if any(not Decimal(0) <= value <= Decimal(1) for value in values.values()):
        raise ApiError(
            422,
            "validation_error",
            "Cada peso debe estar entre 0 y 1.",
            [ErrorDetail(field="body.changes", issue="weight_out_of_range")],
        )
    if sum(values.values(), Decimal(0)) != Decimal(1):
        raise ApiError(
            422,
            "validation_error",
            "Los pesos deben sumar 1.0.",
            [ErrorDetail(field="body.changes", issue="weights_sum_to_one")],
        )


def _forbid_above_role(user: CurrentUser, keys: list[str]) -> None:
    """Each parameter declares its own minimum role in the catalog (API-05, docs/13 API-06)."""
    catalog = {parameter.key: parameter for parameter in samples.CONFIG_SCHEMA}
    for key in keys:
        if not user.role.at_least(Role(catalog[key].min_role)):
            raise ApiError(
                403,
                "forbidden",
                "No tienes permisos para cambiar este parámetro.",
                [ErrorDetail(field=f"body.changes.{key}", issue=f"requires_{catalog[key].min_role}")],
            )


@router.get("/api/config/schema", dependencies=[guard("GET", "/api/config/schema")])
def config_schema() -> list[ConfigParameter]:
    """Parameter schema the frontend builds its forms from (API-05)."""
    return samples.CONFIG_SCHEMA


@router.get("/api/config", dependencies=[guard("GET", "/api/config")])
def get_config() -> ConfigDocument:
    return ConfigDocument(version=samples.CONFIG_VERSION, values=samples.CONFIG_VALUES)


@router.put("/api/config", dependencies=[guard("PUT", "/api/config")])
def put_config(update: ConfigUpdate, user: CurrentUserDep) -> ConfigDocument:
    """Optimistic concurrency: `expected_version` must be the current one, else 409 (API-03)."""
    if update.expected_version != samples.CONFIG_VERSION:
        raise _stale()
    unknown = [k for k in update.changes if k not in samples.CONFIG_VALUES]
    if unknown:
        raise ApiError(
            422,
            "validation_error",
            "Los datos enviados no son válidos.",
            [ErrorDetail(field=f"body.changes.{key}", issue="unknown_parameter") for key in unknown],
        )
    _forbid_above_role(user, list(update.changes))
    _validated_weights(update.changes)
    return ConfigDocument(version=samples.CONFIG_VERSION + 1, values={**samples.CONFIG_VALUES, **update.changes})


@router.get("/api/config/versions", dependencies=[guard("GET", "/api/config/versions")])
def config_versions(params: PageQuery, signer: Signer) -> Page[ConfigVersion]:
    return paginate(samples.CONFIG_VERSIONS, params, signer)


@router.post("/api/config/versions/{v}/restore", dependencies=[guard("POST", "/api/config/versions/{v}/restore")])
def restore_version(v: int, request: RestoreRequest) -> ConfigDocument:
    """Restores a version as a new one and recalculates the bases by code, without calling the judge (FRO-08).

    Like every configuration write it carries the expected current version (API-03): 409 if it changed.
    """
    if request.expected_version != samples.CONFIG_VERSION:
        raise _stale()
    if v not in {item.version for item in samples.CONFIG_VERSIONS}:
        raise ApiError(404, "not_found", "La versión solicitada no existe.")
    return ConfigDocument(version=samples.CONFIG_VERSION + 1, values=samples.CONFIG_VALUES)


@router.post("/api/formula/simulate", dependencies=[guard("POST", "/api/formula/simulate")])
def simulate(request: SimulationRequest) -> SimulationResult:
    """Preview only: it never changes data (FRO-06)."""
    _validated_weights(request.changes)
    return SimulationResult(
        changed_findings=7,
        level_matrix={"high": {"high": 10, "critical": 3}, "medium": {"medium": 22, "high": 4}},
        last_30_days_effect="3 hallazgos habrían subido a Alta en los últimos 30 días",
        top_movers=["CVE-2099-0002 en srv-example-02", "CVE-2099-0003 en srv-proxy-04"],
    )


@router.get("/api/profile", dependencies=[guard("GET", "/api/profile")])
def get_profile() -> CompanyProfile:
    return samples.PROFILE


@router.put("/api/profile", dependencies=[guard("PUT", "/api/profile")])
def put_profile(update: ProfileUpdate) -> CompanyProfile:
    if update.expected_version != samples.PROFILE.version:
        raise _stale()
    return CompanyProfile(**update.model_dump(exclude={"expected_version"}), version=samples.PROFILE.version + 1)


@router.get("/api/peer-companies", dependencies=[guard("GET", "/api/peer-companies")])
def list_peers(params: PageQuery, signer: Signer) -> Page[PeerCompany]:
    return paginate(samples.PEERS, params, signer)


@router.post("/api/peer-companies", status_code=201, dependencies=[guard("POST", "/api/peer-companies")])
def create_peer(peer: PeerCompanyInput) -> PeerCompany:
    return PeerCompany(id="peer-3", **peer.model_dump())


def _peer(peer_id: str) -> PeerCompany:
    for peer in samples.PEERS:
        if peer.id == peer_id:
            return peer
    raise ApiError(404, "not_found", "La empresa par no existe.")


@router.put("/api/peer-companies/{id}", dependencies=[guard("PUT", "/api/peer-companies/{id}")])
def update_peer(id: str, peer: PeerCompanyInput) -> PeerCompany:  # noqa: A002 - path parameter name of API-06
    _peer(id)
    return PeerCompany(id=id, **peer.model_dump())


@router.delete("/api/peer-companies/{id}", status_code=204, dependencies=[guard("DELETE", "/api/peer-companies/{id}")])
def delete_peer(id: str) -> None:  # noqa: A002
    _peer(id)
