"""Sources, inventory pending items and CPE mapping (docs/13 §8, FRO-16, FRO-17, D-041)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select

from api.auth import CurrentUser, Role, get_current_user
from api.errors import ApiError, ErrorDetail
from api.pagination import PAGINATED_RESPONSES, Page, PageQuery, Signer, paginate
from api.routes._auth import guard
from api.routes._db import SessionDep
from api.routes._state import SourceStore
from api.routes.models import (
    CpeCandidate,
    InventoryItem,
    InventoryPending,
    Mapping,
    MappingInput,
    Source,
    SourceCreate,
    SourcePatch,
)
from core.cpe.candidates import CpeDictionaryClient, cpe_uri, find_candidates, parse_cpe_name
from core.cpe.mapping import MappingError, set_mapping
from core.cpe.mapping import MappingInput as MappingData
from core.db.models import AppUser
from core.inventory.pending import MAX_PAGE, PendingItem, list_pending

router = APIRouter(tags=["sources and inventory"])
CurrentUserDep = Annotated[CurrentUser, Depends(get_current_user)]


@router.get("/api/sources", dependencies=[guard("GET", "/api/sources")], responses=PAGINATED_RESPONSES)
def list_sources(params: PageQuery, signer: Signer, sources: SourceStore) -> Page[Source]:
    return paginate(sources, params, signer)


@router.post("/api/sources", status_code=201, dependencies=[guard("POST", "/api/sources")])
def create_source(source: SourceCreate, sources: SourceStore) -> Source:
    """Own feeds enter as N4 (unverified) and inactive until an analyst activates them."""
    created = Source(
        id=f"src-custom-{len(sources) + 1}",
        name=source.name,
        type="feed",
        level="N4",
        structural=False,
        active=False,
        last_capture=None,
        items_per_run=0,
        health="ok",
    )
    sources.append(created)
    return created


@router.patch("/api/sources/{id}", dependencies=[guard("PATCH", "/api/sources/{id}")])
def patch_source(
    id: str,  # noqa: A002 - path parameter name of API-06
    patch: SourcePatch,
    user: CurrentUserDep,
    sources: SourceStore,
) -> Source:
    if patch.level is not None and not user.role.at_least(Role.ADMIN):
        # D-041: analysts activate or deactivate a source; only an admin changes its trust level.
        raise ApiError(
            403,
            "forbidden",
            "Solo un administrador puede cambiar el nivel de una fuente.",
            [ErrorDetail(field="body.level", issue="requires_admin")],
        )
    source = next((s for s in sources if s.id == id), None)
    if source is None:
        raise ApiError(404, "not_found", "La fuente no existe.")
    if source.structural and patch.active is False:
        raise ApiError(409, "structural_source", "Las fuentes estructurales no se pueden desactivar.")
    updated = source.model_copy(update=patch.model_dump(exclude_none=True))
    sources[sources.index(source)] = updated
    return updated


ISSUE_FIELDS = {
    "software_unmapped": "software_without_cpe",
    "unclassified": "without_classification",
    "exposure_unknown": "without_exposure",
    "owner_missing": "without_owner",
    "custodian_missing": "without_custodian",
}
ISSUE_DETAIL = {
    "unclassified": "Sin clasificación de datos",
    "exposure_unknown": "Sin dato de exposición",
    "owner_missing": "Sin dueño asignado",
    "custodian_missing": "Sin equipo custodio",
}


def _inventory_item(item: PendingItem) -> InventoryItem:
    if item.issue == "software_unmapped":
        count = item.installations or 0
        return InventoryItem(
            ci_id=str(item.software_product_id),
            name=item.software_name or "",
            detail=f"Software sin CPE ({count} instalaciones)",
        )
    return InventoryItem(
        ci_id=item.asset_itop_id or str(item.asset_id), name=item.asset_name or "", detail=ISSUE_DETAIL[item.issue]
    )


@router.get("/api/pending/inventory", dependencies=[guard("GET", "/api/pending/inventory")])
def pending_inventory(session: SessionDep) -> InventoryPending:
    """Inventory items waiting for a person, up to 200 per type (FRO-17); `outside_delivery_model` is not modelled."""
    lists = {
        field: [_inventory_item(i) for i in list_pending(session, issue, limit=MAX_PAGE)]
        for issue, field in ISSUE_FIELDS.items()
    }
    return InventoryPending(**lists, outside_delivery_model=[])


@router.get("/api/cpe/candidates", dependencies=[guard("GET", "/api/cpe/candidates")])
def cpe_candidates(
    request: Request, session: SessionDep, q: str = Query(min_length=2, max_length=100)
) -> list[CpeCandidate]:
    """Candidate CPE vendor and product pairs for a software name: NVD's dictionary plus what is already loaded."""
    dictionary: CpeDictionaryClient | None = request.app.state.cpe_dictionary
    try:
        found = find_candidates(session, q, dictionary)
    except ValueError:
        raise ApiError(
            422,
            "validation_error",
            "El texto de búsqueda no es válido.",
            [ErrorDetail(field="query.q", issue="invalid")],
        ) from None
    return [
        CpeCandidate(
            cpe=cpe_uri(c.vendor, c.product), title=c.title or f"{c.vendor} {c.product}", score=round(c.score, 2)
        )
        for c in found
    ]


@router.put("/api/mappings/{software}", dependencies=[guard("PUT", "/api/mappings/{software}")])
def put_mapping(software: str, mapping: MappingInput, session: SessionDep, user: CurrentUserDep) -> Mapping:
    """Maps a software product (its identifier) to the vendor and product of a CPE name (ESC-05, ESC-06)."""
    try:
        product_id = uuid.UUID(software)
    except ValueError:
        raise ApiError(404, "not_found", "El software no existe.") from None
    pair = parse_cpe_name(mapping.cpe)
    if pair is None:
        raise ApiError(
            422,
            "validation_error",
            "El CPE debe nombrar un fabricante y un producto.",
            [ErrorDetail(field="body.cpe", issue="invalid_cpe")],
        )
    app_user = session.scalar(select(AppUser.id).where(AppUser.firebase_uid == user.uid))
    try:
        set_mapping(session, product_id, MappingData(nvd_vendor=pair[0], nvd_product=pair[1]), mapped_by=app_user)
    except MappingError as error:
        raise ApiError(
            422, "validation_error", str(error), [ErrorDetail(field="body.cpe", issue="invalid_mapping")]
        ) from None
    except LookupError:
        raise ApiError(404, "not_found", "El software no existe.") from None
    return Mapping(software=str(product_id), cpe=mapping.cpe)
