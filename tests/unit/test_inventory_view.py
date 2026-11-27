"""F18.4: the software catalogue filters by category over the categories of a product's live installations."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from api.routes.models import InstalledSoftwareItem, InventoryAsset, SoftwareFilters, SoftwareItem
from core.views.assets import SoftwareItem as ViewSoftware
from core.views.assets import SoftwareQuery


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


def test_the_category_filter_takes_only_the_itop_classes() -> None:
    assert SoftwareFilters.model_validate({"category": "PCSoftware"}).category == "PCSoftware"
    for wrong in ("pcsoftware", "Server", ""):
        with pytest.raises(ValidationError):
            SoftwareFilters.model_validate({"category": wrong})


def test_the_new_fields_are_optional_for_the_published_models() -> None:
    """A compatible change: every F18.4 field has a default, so a response without them still validates."""
    for model, field_names in (
        (InventoryAsset, ("description", "cpu", "ram")),
        (SoftwareItem, ("categories",)),
        (InstalledSoftwareItem, ("category", "status", "description", "licence")),
    ):
        for name in field_names:
            assert not model.model_fields[name].is_required(), f"{model.__name__}.{name}"
