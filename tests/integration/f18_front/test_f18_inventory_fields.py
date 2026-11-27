"""F18.4: the inventory routes of F18.1 carry the iTop fields of F18.3 (D-088), over the F18.1 scenario.

Seeded: CI-1 (16 vCPU, 64 GB) and CI-2 (4 vCPU, 8 GB) with OpenSSL as `OtherSoftware`, active on CI-1 with the
live licence "Soporte OpenSSL", inactive on CI-2. Added here: CI-3's OpenSSL is a `WebServer`, CI-2's unmapped
product a `DBServer` with a removed licence, the decommissioned CI-4's OpenSSL a `Middleware` and a removed
installation on CI-1 a `PCSoftware`; neither of the last two may count. CI-1 gets a description and OpenSSL a
second live licence assigned to no installation.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from f18data import Front
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from core.db import models as m

pytestmark = pytest.mark.integration
Get = Callable[..., Any]
T0 = datetime(2026, 11, 27, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def categorised(database: tuple[str, Engine], front: Front) -> Front:
    with Session(database[1]) as session, session.begin():
        session.get_one(m.Asset, front.scenario.assets["CI-1"]).description = "Servidor de pagos"
        installs = {i.itop_instance_id: i for i in session.scalars(select(m.InstalledSoftware))}
        installs["SI-3"].itop_class = "WebServer"
        installs["SI-4"].itop_class = "Middleware"  # on the decommissioned CI-4
        retired = m.SoftwareLicence(
            itop_licence_id="LIC-90", name="Retirada", perpetual=True, synced_at=T0, removed_at=T0
        )
        extended = m.SoftwareLicence(
            itop_licence_id="LIC-2",
            software_product_id=installs["SI-1"].software_product_id,
            name="Soporte extendido",
            perpetual=True,
            synced_at=T0,
        )
        session.add_all([retired, extended])
        session.flush()
        unmapped = installs["SI-90"]
        unmapped.itop_class, unmapped.status, unmapped.software_licence_id = "DBServer", "active", retired.id
        session.add(
            m.InstalledSoftware(
                itop_instance_id="SI-91",
                asset_id=front.scenario.assets["CI-1"],
                software_product_id=installs["SI-1"].software_product_id,
                version="1.0",
                itop_class="PCSoftware",
                synced_at=T0,
                removed_at=T0,
            )
        )
    return front


def test_inventory_assets_carry_description_cpu_and_ram(get: Get, categorised: Front) -> None:
    assets = {a["ci_id"]: a for a in get("/api/inventory/assets")["items"]}
    assert {ci: (a["itop_class"], a["cpu"], a["ram"]) for ci, a in assets.items()} == {
        "CI-1": ("Server", "16 vCPU", "64 GB"),
        "CI-2": ("VirtualMachine", "4 vCPU", "8 GB"),
        "CI-3": ("Server", None, None),  # no data in iTop: null, never invented
    }
    assert {ci: a["description"] for ci, a in assets.items()} == {
        "CI-1": "Servidor de pagos",
        "CI-2": None,
        "CI-3": None,
    }
    assert [a["ci_id"] for a in get("/api/inventory/assets", q="pagos")["items"]] == ["CI-1"]  # filters unchanged


def test_asset_software_carries_category_status_description_and_licence(get: Get, categorised: Front) -> None:
    payments = get("/api/inventory/assets/CI-1/software")
    assert [(i["name"], i["category"]) for i in payments] == [("OpenSSL", "OtherSoftware")]  # SI-91 is removed
    assert {k: payments[0][k] for k in ("status", "description", "licence")} == {
        "status": "active",
        "description": "Biblioteca TLS del sistema",
        "licence": {
            "name": "Soporte OpenSSL",
            "usage_limit": "10 servidores",
            "start_date": "2026-01-01",
            "end_date": "2026-12-31",
            "perpetual": False,
        },
    }
    intranet = {i["name"]: i for i in get("/api/inventory/assets/CI-2/software")}
    assert (intranet["OpenSSL"]["status"], intranet["OpenSSL"]["licence"]) == ("inactive", None)
    # a removed licence is not shown
    assert (intranet["Software sin mapeo CPE"]["category"], intranet["Software sin mapeo CPE"]["licence"]) == (
        "DBServer",
        None,
    )
    orphan = get("/api/inventory/assets/CI-3/software")
    assert [(i["category"], i["status"], i["description"], i["licence"]) for i in orphan] == [
        ("WebServer", None, None, None)
    ]


def test_software_catalogue_shows_and_filters_the_categories(get: Get, categorised: Front) -> None:
    items = {s["name"]: s for s in get("/api/inventory/software")["items"]}
    # OpenSSL: the classes of its live installations (CI-3 WebServer, CI-1 and CI-2 OtherSoftware), sorted.
    # Neither the decommissioned CI-4's Middleware nor the removed PCSoftware installation counts.
    assert items["OpenSSL"]["categories"] == ["OtherSoftware", "WebServer"]
    assert items["Software sin mapeo CPE"]["categories"] == ["DBServer"]

    def names(**filters: object) -> list[str]:
        return [s["name"] for s in get("/api/inventory/software", **filters)["items"]]

    assert names(category="WebServer") == ["OpenSSL"]  # any of its installations has it
    assert names(category="DBServer") == ["Software sin mapeo CPE"]
    assert names(category="Middleware") == [] and names(category="PCSoftware") == []
    assert names(category="OtherSoftware", has_cpe=True) == ["OpenSSL"]


def test_software_catalogue_counts_installations_by_category_status_and_licence(get: Get, categorised: Front) -> None:
    items = {s["name"]: s for s in get("/api/inventory/software")["items"]}
    openssl = items["OpenSSL"]
    # CI-1 active, CI-2 inactive, CI-3 without a status; CI-4 (decommissioned) and SI-91 (removed) do not count
    assert openssl["by_category"] == {"OtherSoftware": 2, "WebServer": 1}
    assert openssl["by_status"] == {"active": 1, "inactive": 1, "unknown": 1}
    assert openssl["licensed_instances"] == 1
    assert [(lic["name"], lic["perpetual"], lic["instances"]) for lic in openssl["licences"]] == [
        ("Soporte extendido", True, 0),  # live and tied to the product, assigned to no installation
        ("Soporte OpenSSL", False, 1),
    ]
    assert openssl["licences"][1] == {
        "name": "Soporte OpenSSL",
        "usage_limit": "10 servidores",
        "start_date": "2026-01-01",
        "end_date": "2026-12-31",
        "perpetual": False,
        "instances": 1,
    }
    unmapped = items["Software sin mapeo CPE"]
    # its installation points to a removed licence: neither counted nor listed
    assert unmapped["by_status"] == {"active": 1, "inactive": 0, "unknown": 0}
    assert unmapped["licensed_instances"] == 0 and unmapped["licences"] == []


def test_software_catalogue_refuses_an_unknown_category(client: TestClient) -> None:
    for category in ("Laptop", "dbserver", "x" * 101):
        response = client.get("/api/inventory/software", params={"category": category})
        assert response.status_code == 422, category
        assert response.json()["error"]["code"] == "validation_error"
