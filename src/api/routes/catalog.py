"""Sources, inventory pending items and CPE mapping (docs/13 §8, FRO-16, FRO-17, D-041)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from api.auth import CurrentUser, Role, get_current_user
from api.errors import ApiError, ErrorDetail
from api.pagination import Page, PageQuery, Signer, paginate
from api.routes import samples
from api.routes._auth import guard
from api.routes.models import CpeCandidate, InventoryPending, Mapping, MappingInput, Source, SourceCreate, SourcePatch

router = APIRouter(tags=["sources and inventory"])
CurrentUserDep = Annotated[CurrentUser, Depends(get_current_user)]


@router.get("/api/sources", dependencies=[guard("GET", "/api/sources")])
def list_sources(params: PageQuery, signer: Signer) -> Page[Source]:
    return paginate(samples.SOURCES, params, signer)


@router.post("/api/sources", status_code=201, dependencies=[guard("POST", "/api/sources")])
def create_source(source: SourceCreate) -> Source:
    """Own feeds enter as N4 (unverified) and inactive until an analyst activates them."""
    return Source(
        id="src-custom-1",
        name=source.name,
        type="feed",
        level="N4",
        structural=False,
        active=False,
        last_capture=None,
        items_per_run=0,
        health="ok",
    )


@router.patch("/api/sources/{id}", dependencies=[guard("PATCH", "/api/sources/{id}")])
def patch_source(id: str, patch: SourcePatch, user: CurrentUserDep) -> Source:  # noqa: A002 - path parameter name of API-06
    if patch.level is not None and not user.role.at_least(Role.ADMIN):
        # D-041: analysts activate or deactivate a source; only an admin changes its trust level.
        raise ApiError(
            403,
            "forbidden",
            "Solo un administrador puede cambiar el nivel de una fuente.",
            [ErrorDetail(field="body.level", issue="requires_admin")],
        )
    source = next((s for s in samples.SOURCES if s.id == id), None)
    if source is None:
        raise ApiError(404, "not_found", "La fuente no existe.")
    if source.structural and patch.active is False:
        raise ApiError(409, "structural_source", "Las fuentes estructurales no se pueden desactivar.")
    return source.model_copy(update=patch.model_dump(exclude_none=True))


@router.get("/api/pending/inventory", dependencies=[guard("GET", "/api/pending/inventory")])
def pending_inventory() -> InventoryPending:
    return samples.INVENTORY


@router.get("/api/cpe/candidates", dependencies=[guard("GET", "/api/cpe/candidates")])
def cpe_candidates(q: str = Query(min_length=2, max_length=100)) -> list[CpeCandidate]:
    return [c for c in samples.CPE_CANDIDATES if q.lower() in c.title.lower()] or samples.CPE_CANDIDATES[:1]


@router.put("/api/mappings/{software}", dependencies=[guard("PUT", "/api/mappings/{software}")])
def put_mapping(software: str, mapping: MappingInput) -> Mapping:
    return Mapping(software=software, cpe=mapping.cpe)
