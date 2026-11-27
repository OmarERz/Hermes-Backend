"""F18.4: the software catalogue filters by category over the categories of a product's live installations."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from api.routes.models import InstalledSoftwareItem, InventoryAsset, SoftwareFilters, SoftwareItem
from core.views.assets import SoftwareItem as ViewSoftware
from core.views.assets import SoftwareQuery, _Findings, _software


def _product(*categories: str) -> ViewSoftware:
    return ViewSoftware(
        id=uuid.uuid4(),
        name="Apache httpd",
        versions=["2.4.58"],
        version_known=True,
        instances=len(categories) or 1,
        ci_count=1,
        cpe=None,
        open_vulnerabilities=0,
        worst_level=None,
        categories=list(categories),
    )


def test_a_product_matches_a_category_any_of_its_installations_has() -> None:
    both = _product("Middleware", "WebServer")
    assert SoftwareQuery(category="WebServer").matches(both)
    assert SoftwareQuery(category="Middleware").matches(both)
    assert not SoftwareQuery(category="DBServer").matches(both)
    assert SoftwareQuery().matches(_product())  # no filter: also a product with no synced category
    assert not SoftwareQuery(category="WebServer").matches(_product())
    assert not SoftwareQuery(category="WebServer", has_cpe=True).matches(both)  # the filters add up


def _install(product: uuid.UUID, **itop: Any) -> SimpleNamespace:
    row = {"category": None, "status": None, "licence_id": None, **itop}
    return SimpleNamespace(
        asset_id=uuid.uuid4(),
        product_id=product,
        product="Apache httpd",
        version="2.4.58",
        nvd_vendor=None,
        nvd_product=None,
        cna_vendor=None,
        cna_product=None,
        **row,
    )


def _licence(product: uuid.UUID, name: str, licence: uuid.UUID | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        id=licence or uuid.uuid4(),
        product_id=product,
        name=name,
        usage_limit=None,
        start_date=None,
        end_date=None,
        perpetual=False,
    )


def test_the_catalogue_counts_installations_by_category_status_and_licence() -> None:
    product, support = uuid.uuid4(), uuid.uuid4()
    installs = [
        _install(product, category="WebServer", status="active", licence_id=support),
        _install(product, category="WebServer", status="inactive", licence_id=support),
        _install(product, category="Middleware"),
        _install(product, licence_id=uuid.uuid4()),  # a licence of another software, as iTop's REST API allows
    ]
    licences = [_licence(product, "soporte", support), _licence(product, "Extendido"), _licence(uuid.uuid4(), "Otra")]
    [item] = _software(_Findings(), installs, licences)
    assert item.categories == ["Middleware", "WebServer"]
    assert item.by_category == {"Middleware": 1, "WebServer": 2}
    assert item.by_status == {"active": 1, "inactive": 1, "unknown": 2}
    # the product's own licences only, by name ignoring case; an unassigned one counts no installation
    assert [(lic.licence.name, lic.instances) for lic in item.licences] == [("Extendido", 0), ("soporte", 2)]
    assert item.licensed_instances == 3


def test_the_category_filter_takes_only_the_itop_classes() -> None:
    assert SoftwareFilters.model_validate({"category": "PCSoftware"}).category == "PCSoftware"
    for wrong in ("pcsoftware", "Server", ""):
        with pytest.raises(ValidationError):
            SoftwareFilters.model_validate({"category": wrong})


def test_the_new_fields_are_optional_for_the_published_models() -> None:
    """A compatible change: every F18.4 field has a default, so a response without them still validates."""
    for model, field_names in (
        (InventoryAsset, ("description", "cpu", "ram")),
        (SoftwareItem, ("categories", "by_category", "by_status", "licences", "licensed_instances")),
        (InstalledSoftwareItem, ("category", "status", "description", "licence")),
    ):
        for name in field_names:
            assert not model.model_fields[name].is_required(), f"{model.__name__}.{name}"
