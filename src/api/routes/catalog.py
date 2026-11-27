"""Inventory pending items and CPE mapping (docs/13 §8, FRO-17); sources are in `sources.py`."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select

from api.auth import CurrentUser, get_current_user
from api.errors import ApiError, ErrorDetail
from api.routes._auth import guard
from api.routes._db import SessionDep
from api.routes._paths import UuidId
from api.routes.models import (
    CpeCandidate,
    InventoryItem,
    InventoryPending,
    InventoryPendingTotals,
    Mapping,
    MappingInput,
)
from core.cpe.candidates import (
    CpeDictionaryClient,
    cpe_uri,
    local_candidates,
    merge_candidates,
    parse_cpe_name,
    search_dictionary,
)
from core.cpe.mapping import MappingError, set_mapping
from core.cpe.mapping import MappingInput as MappingData
from core.db.models import AppUser, AuditLog, CpeMapping
from core.inventory.pending import MAX_PAGE, PendingItem, first_pending

router = APIRouter(tags=["sources and inventory"])
CurrentUserDep = Annotated[CurrentUser, Depends(get_current_user)]


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
        product = str(item.software_product_id)
        return InventoryItem(
            ci_id=product,  # kept for clients generated before F18.6; `software_product_id` names it
            name=item.software_name or "",
            detail=f"Software sin CPE ({count} instalaciones)",
            software_product_id=product,
        )
    return InventoryItem(
        ci_id=item.asset_itop_id or str(item.asset_id),
        name=item.asset_name or "",
        detail=ISSUE_DETAIL[item.issue],
        itop_class=item.asset_class,
    )


@router.get("/api/pending/inventory", dependencies=[guard("GET", "/api/pending/inventory")])
def pending_inventory(session: SessionDep) -> InventoryPending:
    """Inventory items waiting for a person, up to 200 per type, with the total of each type (FRO-17, F18.6).

    `outside_delivery_model` stays empty: the iTop cache has no delivery model to compare the custodian teams with
    (pendientes F12 #34)."""
    pages = {field: first_pending(session, issue, limit=MAX_PAGE) for issue, field in ISSUE_FIELDS.items()}
    lists = {field: [_inventory_item(i) for i in items] for field, (items, _total) in pages.items()}
    # Each total comes from the statement that read its list, so the two never contradict each other
    totals = InventoryPendingTotals(
        **{field: total for field, (_items, total) in pages.items()}, outside_delivery_model=0
    )
    return InventoryPending(**lists, outside_delivery_model=[], totals=totals)


@router.get("/api/cpe/candidates", dependencies=[guard("GET", "/api/cpe/candidates")])
def cpe_candidates(
    request: Request, session: SessionDep, q: str = Query(min_length=2, max_length=100)
) -> list[CpeCandidate]:
    """Candidate CPE vendor and product pairs for a software name: NVD's dictionary plus what is already loaded."""
    dictionary: CpeDictionaryClient | None = request.app.state.cpe_dictionary
    # Every schema-valid string gets an answer: control characters become spaces and a search text with nothing
    # printable left simply has no candidates (instead of an undocumented 422).
    q = " ".join("".join(ch if ch.isprintable() else " " for ch in q).split())
    if not q:
        return []
    try:
        local = local_candidates(session, q)
        session.rollback()  # give the connection back before the slow remote search (NVD limits, retries)
        found = merge_candidates(local, search_dictionary(dictionary, q))
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
def put_mapping(software: UuidId, mapping: MappingInput, session: SessionDep, user: CurrentUserDep) -> Mapping:
    """Maps a software product (its identifier) to the vendor and product of a CPE name (ESC-05, ESC-06)."""
    try:  # defence in depth: the path pattern already refuses anything but a UUID (422)
        product_id = uuid.UUID(software)
    except ValueError:
        raise ApiError(404, "not_found", "El software no existe.") from None
    pair = parse_cpe_name(mapping.cpe)
    if pair is None:  # defence in depth: CPE_NAME_PATTERN already refuses these in the schema (422)
        raise ApiError(
            422,
            "validation_error",
            "El CPE debe nombrar un fabricante y un producto.",
            [ErrorDetail(field="body.cpe", issue="invalid_cpe")],
        )
    app_user = session.scalar(select(AppUser.id).where(AppUser.firebase_uid == user.uid))
    current = session.get(CpeMapping, product_id)
    # Editing the NVD pair keeps the CNA pair of an existing mapping: CVE.org matches must not disappear.
    data = MappingData(
        nvd_vendor=pair[0],
        nvd_product=pair[1],
        cna_vendor=current.cna_vendor if current else None,
        cna_product=current.cna_product if current else None,
    )
    before = _mapping_snapshot(current)
    try:
        saved = set_mapping(session, product_id, data, mapped_by=app_user)
    except MappingError as error:
        raise ApiError(
            422, "validation_error", str(error), [ErrorDetail(field="body.cpe", issue="invalid_mapping")]
        ) from None
    except LookupError:
        raise ApiError(404, "not_found", "El software no existe.") from None
    session.add(
        AuditLog(
            app_user_id=app_user,
            action="cpe_mapping_set",
            entity_type="cpe_mapping",
            entity_id=str(product_id),
            before=before,
            after=_mapping_snapshot(saved),
            created_at=datetime.now(UTC),
        )
    )
    session.commit()  # before answering: the client must not see a success that was not saved
    return Mapping(software=str(product_id), cpe=mapping.cpe)


def _mapping_snapshot(row: CpeMapping | None) -> dict[str, str | None] | None:
    if row is None:
        return None
    return {
        "nvd_vendor": row.nvd_vendor,
        "nvd_product": row.nvd_product,
        "cna_vendor": row.cna_vendor,
        "cna_product": row.cna_product,
        "origin": row.origin,
    }
