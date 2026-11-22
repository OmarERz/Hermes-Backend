"""Inventory pending items and CPE mapping (docs/13 §8, FRO-17); sources are in `sources.py`."""

from __future__ import annotations

from fastapi import APIRouter, Query

from api.routes import samples
from api.routes._auth import guard
from api.routes.models import CpeCandidate, InventoryPending, Mapping, MappingInput

router = APIRouter(tags=["sources and inventory"])


@router.get("/api/pending/inventory", dependencies=[guard("GET", "/api/pending/inventory")])
def pending_inventory() -> InventoryPending:
    return samples.INVENTORY


@router.get("/api/cpe/candidates", dependencies=[guard("GET", "/api/cpe/candidates")])
def cpe_candidates(q: str = Query(min_length=2, max_length=100)) -> list[CpeCandidate]:
    return [c for c in samples.CPE_CANDIDATES if q.lower() in c.title.lower()] or samples.CPE_CANDIDATES[:1]


@router.put("/api/mappings/{software}", dependencies=[guard("PUT", "/api/mappings/{software}")])
def put_mapping(software: str, mapping: MappingInput) -> Mapping:
    return Mapping(software=software, cpe=mapping.cpe)
