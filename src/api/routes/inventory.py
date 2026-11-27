"""Inventory and software of iTop for the front (D-088, F18.1): every live CI and its software, read only.

The inventory belongs to iTop (D-003): these routes never write; the front links each CI to iTop to edit it.
"""

from __future__ import annotations

from typing import Annotated, Literal, cast

from fastapi import APIRouter, Query

from api.errors import ApiError
from api.pagination import PAGINATED_RESPONSES, Page, PageQuery, Signer, decode_key, encode_key
from api.routes._auth import guard
from api.routes._db import SessionDep
from api.routes._paths import CiId
from api.routes.findings import ItopUrl, licence_info
from api.routes.models import (
    Classification,
    Criticality,
    InstalledSoftwareItem,
    InventoryAsset,
    InventoryAssetFilters,
    InventorySummary,
    Level,
    SoftwareCategory,
    SoftwareFilters,
    SoftwareHealth,
    SoftwareItem,
)
from core.views import assets
from core.views.common import iso
from core.views.telemetry import percent

router = APIRouter(tags=["inventory"])


def _asset_model(a: assets.InventoryAsset) -> InventoryAsset:
    return InventoryAsset(
        ci_id=a.ci_id,
        name=a.name,
        itop_class=a.itop_class,
        criticality=cast(Criticality, a.criticality),
        exposed=a.exposed,
        classification=cast(Classification, a.classification),
        personal_data=a.personal_data,
        owner=a.owner,
        custodian=a.custodian,
        service=a.service,
        os=a.os,
        itop_url=a.itop_url,
        synced_at=iso(a.synced_at),
        open_findings=a.open_findings,
        kev_findings=a.kev_findings,
        risk=a.risk,
        level=cast(Level | None, a.level),
        software_count=a.software_count,
        description=a.description,
        cpu=a.cpu,
        ram=a.ram,
    )


def _name_key(params: PageQuery, kind: str) -> assets.NameKey | None:
    key = decode_key(params, kind, ("str", "str"))
    return None if key is None else (key[0], key[1])


@router.get(
    "/api/inventory/assets", dependencies=[guard("GET", "/api/inventory/assets")], responses=PAGINATED_RESPONSES
)
def inventory_assets(
    params: PageQuery,
    signer: Signer,
    session: SessionDep,
    itop_url: ItopUrl,
    filters: Annotated[InventoryAssetFilters, Query()],
) -> Page[InventoryAsset]:
    """Every live CI of the iTop cache, with or without findings, alphabetical (AC-1). Its risk is the highest final
    of its open findings, never a sum (FRO-11)."""
    found, next_key = assets.list_assets(
        session,
        assets.AssetQuery(
            q=filters.q,
            itop_class=filters.itop_class,
            criticality=filters.criticality,
            exposed=filters.exposed,
            classification=filters.classification,
            owner=filters.owner,
            custodian=filters.custodian,
            with_findings=filters.with_findings,
        ),
        itop_url,
        after=_name_key(params, "inventory_assets"),
        limit=params.limit,
    )
    return Page[InventoryAsset](
        items=[_asset_model(a) for a in found], next_cursor=encode_key(signer, "inventory_assets", next_key)
    )


@router.get("/api/inventory/summary", dependencies=[guard("GET", "/api/inventory/summary")])
def inventory_summary(session: SessionDep) -> InventorySummary:
    """Totals of the live inventory and the health of its software: share with a CPE, with a known version and
    without open critical vulnerabilities (D-088)."""
    found = assets.summary(session)
    health = found.software
    return InventorySummary(
        total_assets=found.total_assets,
        by_class=found.by_class,
        by_criticality=found.by_criticality,
        by_exposure=found.by_exposure,
        by_classification=found.by_classification,
        owners=found.owners,
        without_owner=found.without_owner,
        custodians=found.custodians,
        with_open_findings=found.with_open_findings,
        with_kev_findings=found.with_kev_findings,
        last_sync_at=iso(found.last_sync_at) if found.last_sync_at else None,
        software=SoftwareHealth(
            total=health.total,
            with_cpe=health.with_cpe,
            with_known_version=health.with_known_version,
            without_critical=health.without_critical,
            cpe_percent=percent(health.with_cpe, health.total),
            known_version_percent=percent(health.with_known_version, health.total),
            without_critical_percent=percent(health.without_critical, health.total),
        ),
    )


@router.get(
    "/api/inventory/software", dependencies=[guard("GET", "/api/inventory/software")], responses=PAGINATED_RESPONSES
)
def inventory_software(
    params: PageQuery, signer: Signer, session: SessionDep, filters: Annotated[SoftwareFilters, Query()]
) -> Page[SoftwareItem]:
    """Software installed on live CIs, alphabetical (ST-1): versions, instances, CPE, its worst open level and the
    iTop categories of its live installations (ST-2), filtered by any of them."""
    found, next_key = assets.list_software(
        session,
        assets.SoftwareQuery(
            q=filters.q,
            has_cpe=filters.has_cpe,
            worst_level=filters.worst_level,
            with_vulnerabilities=filters.with_vulnerabilities,
            category=filters.category,
        ),
        after=_name_key(params, "inventory_software"),
        limit=params.limit,
    )
    return Page[SoftwareItem](
        items=[
            SoftwareItem(
                id=str(s.id),
                name=s.name,
                versions=s.versions,
                version_known=s.version_known,
                instances=s.instances,
                ci_count=s.ci_count,
                cpe=s.cpe,
                has_cpe=s.cpe is not None,
                open_vulnerabilities=s.open_vulnerabilities,
                worst_level=cast(Level | None, s.worst_level),
                categories=cast(list[SoftwareCategory], s.categories),
            )
            for s in found
        ],
        next_cursor=encode_key(signer, "inventory_software", next_key),
    )


@router.get(
    "/api/inventory/assets/{ci_id}/software", dependencies=[guard("GET", "/api/inventory/assets/{ci_id}/software")]
)
def asset_software(ci_id: CiId, session: SessionDep) -> list[InstalledSoftwareItem]:
    """The software installed on one live CI (AS-2), with its version, CPE and worst open level, and its iTop
    category, status, description and live licence (ST-3); 404 if the CI is not in the live inventory."""
    found = assets.asset_software(session, ci_id)
    if found is None:
        raise ApiError(404, "not_found", "El activo no existe.")
    return [
        InstalledSoftwareItem(
            software_id=str(i.software_id),
            name=i.name,
            version=i.version,
            version_known=i.version_known,
            cpe=i.cpe,
            has_cpe=i.cpe is not None,
            open_vulnerabilities=i.open_vulnerabilities,
            worst_level=cast(Level | None, i.worst_level),
            category=cast(SoftwareCategory | None, i.category),
            status=cast(Literal["active", "inactive"] | None, i.status),
            description=i.description,
            licence=licence_info(i.licence),
        )
        for i in found
    ]
