"""The CI detail carries the iTop inventory fields of F18.3 (D-088): class, description, CPU and RAM of the CI and
its live software with category, status, description and live licence."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, date, datetime
from typing import Any

import pytest
from f10data import Scenario
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from core.db import models as m

pytestmark = pytest.mark.integration
Get = Callable[..., Any]
T0 = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def licensed(database: tuple[str, Engine], scenario: Scenario) -> Scenario:
    """CI-1's OpenSSL gets a live licence, CI-2's a removed one; CI-1 also has an uninstalled product."""
    with Session(database[1]) as session, session.begin():
        installs = {
            i.asset_id: i
            for i in session.scalars(
                select(m.InstalledSoftware).where(m.InstalledSoftware.itop_instance_id.in_(("SI-1", "SI-2")))
            )
        }
        ci1, ci2 = installs[scenario.assets["CI-1"]], installs[scenario.assets["CI-2"]]
        live = m.SoftwareLicence(
            itop_licence_id="400",
            software_product_id=ci1.software_product_id,
            name="Soporte OpenSSL",
            usage_limit="10 servidores",
            start_date=date(2026, 1, 1),
            end_date=date(2026, 12, 31),
            perpetual=False,
            synced_at=T0,
        )
        removed = m.SoftwareLicence(itop_licence_id="401", name="Retirada", perpetual=True, synced_at=T0, removed_at=T0)
        session.add_all([live, removed])
        session.flush()
        ci1.software_licence_id, ci2.software_licence_id = live.id, removed.id
        ci1.description = "Biblioteca TLS del front de pagos"
        gone = m.SoftwareProduct(itop_name="Retired tool", first_seen_at=T0)
        session.add(gone)
        session.flush()
        session.add(
            m.InstalledSoftware(
                itop_instance_id="SI-90",
                asset_id=ci1.asset_id,
                software_product_id=gone.id,
                version="1.0",
                itop_class="PCSoftware",
                synced_at=T0,
                removed_at=T0,
            )
        )
        session.get_one(m.Asset, scenario.assets["CI-1"]).description = "Servidor de pagos"
    return scenario


def test_asset_detail_carries_host_and_installation_fields(get: Get, licensed: Scenario) -> None:
    detail = get("/api/assets/CI-1")
    assert (detail["itop_class"], detail["description"], detail["cpu"], detail["ram"]) == (
        "Server",
        "Servidor de pagos",
        "16 vCPU",
        "64 GB",
    )
    openssl = [s for s in detail["software"] if s["software"] == "OpenSSL"]
    assert openssl == [
        {
            "software": "OpenSSL",
            "version": "3.0.7",
            "category": "OtherSoftware",
            "status": "active",
            "description": "Biblioteca TLS del front de pagos",
            "licence": {
                "name": "Soporte OpenSSL",
                "usage_limit": "10 servidores",
                "start_date": "2026-01-01",
                "end_date": "2026-12-31",
                "perpetual": False,
            },
        }
    ]
    assert "Retired tool" not in {s["software"] for s in detail["software"]}  # uninstalled: not shown


def test_a_removed_licence_is_not_shown_and_inactive_is_reported(get: Get, licensed: Scenario) -> None:
    detail = get("/api/assets/CI-2")
    assert (detail["itop_class"], detail["cpu"], detail["ram"]) == ("VirtualMachine", "4 vCPU", "8 GB")
    openssl = next(s for s in detail["software"] if s["software"] == "OpenSSL")
    assert (openssl["status"], openssl["licence"]) == ("inactive", None)


def test_a_ci_without_inventory_data_answers_nulls(get: Get, licensed: Scenario) -> None:
    detail = get("/api/assets/CI-3")
    assert {k: detail[k] for k in ("itop_class", "description", "cpu", "ram")} == {
        "itop_class": "Server",
        "description": None,
        "cpu": None,
        "ram": None,
    }
    # an installation not synced since F18.3 keeps every new field null
    assert detail["software"] == [
        {
            "software": "OpenSSL",
            "version": "3.0.7",
            "category": None,
            "status": None,
            "description": None,
            "licence": None,
        }
    ]
