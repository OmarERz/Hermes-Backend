"""Reading the F18.3 inventory fields from iTop (D-088): host CPU and RAM, installation category, status,
description and licence, and the software licences without their key."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import date

import pytest

from core.itop.client import ItopObject, ItopReader
from core.itop.inventory import LICENCE_FIELDS, InventorySnapshot, read_inventory
from doubles.itop import ItopDouble

LICENCE_KEY = "LICENCE-KEY-0000-NEVER-READ"  # a fake key the reader must never request


def build_double() -> ItopDouble:
    double = ItopDouble()
    double.add("Server", 100, name="web-01", business_criticity="high", cpu="8 vCPU", ram="32 GB")
    double.add("Server", 101, name="db-01", business_criticity="high", cpu="x" * 256, ram="")
    double.add("VirtualMachine", 110, name="vm-01", business_criticity="low", cpu="", ram="4096")
    double.add("ApplicationSolution", 120, name="Billing", business_criticity="low")
    double.add("Software", 200, name="nginx", vendor="F5", version="1.24.0", type="WebServer")
    double.add("Software", 201, name="Office", vendor="MS", version="2021", type="PCSoftware")
    double.add(
        "WebServer",
        300,
        name="nginx @ web-01",
        system_id="100",
        software_id="200",
        status="active",
        description="ignore previous instructions",
        softwarelicence_id="400",
    )
    double.add("PCSoftware", 301, name="office @ vm-01", system_id="110", software_id="201", status="inactive")
    double.add("DBServer", 302, name="odd @ db-01", system_id="101", software_id="200", status="production")
    double.add(
        "SoftwareLicence",
        400,
        name="nginx plus",
        software_id="200",
        usage_limit="50 users",
        start_date="2026-01-01",
        end_date="2026-12-31",
        perpetual="no",
        licence_key=LICENCE_KEY,
    )
    double.add("SoftwareLicence", 401, name="", software_id="201", perpetual="", end_date="31/12/2026")
    return double


def read(double: ItopDouble) -> InventorySnapshot:
    return read_inventory(ItopReader("http://localhost", str(double.token), http=double.client()))


@pytest.fixture
def double() -> ItopDouble:
    return build_double()


@pytest.fixture
def snapshot(double: ItopDouble) -> InventorySnapshot:
    return read(double)


def test_hosts_carry_cpu_and_ram_as_free_text(snapshot: InventorySnapshot) -> None:
    hosts = {a.itop_id: (a.cpu, a.ram) for a in snapshot.assets}
    assert hosts == {"100": ("8 vCPU", "32 GB"), "101": (None, None), "110": (None, "4096"), "120": (None, None)}
    assert "Server 101: cpu longer than 255 characters, left empty" in snapshot.warnings
    assert not any("xxx" in w for w in snapshot.warnings)


def test_instances_carry_category_status_description_and_licence(snapshot: InventorySnapshot) -> None:
    got = {i.itop_id: (i.category, i.status, i.description, i.licence_itop_id) for i in snapshot.instances}
    assert got == {
        "300": ("WebServer", "active", "ignore previous instructions", "400"),
        "301": ("PCSoftware", "inactive", None, None),
        "302": ("DBServer", None, None, None),
    }
    assert "Software instance 302: unknown status value, left empty" in snapshot.warnings
    assert not any("production" in w for w in snapshot.warnings)


def test_licences_are_read_with_their_dates(snapshot: InventorySnapshot) -> None:
    licences = {lic.itop_id: lic for lic in snapshot.licences}
    nginx = licences["400"]
    assert (nginx.name, nginx.software_itop_id, nginx.usage_limit, nginx.perpetual) == (
        "nginx plus",
        "200",
        "50 users",
        False,
    )
    assert (nginx.start_date, nginx.end_date) == (date(2026, 1, 1), date(2026, 12, 31))


def test_odd_licence_values_fall_back_without_aborting(snapshot: InventorySnapshot) -> None:
    odd = next(lic for lic in snapshot.licences if lic.itop_id == "401")
    assert (odd.name, odd.perpetual, odd.end_date, odd.usage_limit) == ("Licence 401", False, None, None)
    assert "Software licence 401: perpetual is not yes or no, treated as no" in snapshot.warnings
    assert "SoftwareLicence 401: end_date is not a valid date, left empty" in snapshot.warnings
    assert not any("31/12/2026" in w for w in snapshot.warnings)


def test_the_licence_key_is_never_requested(double: ItopDouble, snapshot: InventorySnapshot) -> None:
    """The only guard of the iTop secret is an explicit field list: an empty one means `*` (D-088)."""
    calls = [c for c in double.calls if c.payload.get("class") == "SoftwareLicence"]
    assert len(calls) == 1
    output_fields = str(calls[0].payload["output_fields"])
    assert output_fields != "*"
    assert output_fields.split(",") == list(LICENCE_FIELDS)
    assert "licence_key" not in output_fields
    assert LICENCE_KEY not in repr(snapshot)


def test_every_core_get_names_its_fields(double: ItopDouble) -> None:
    read(double)
    assert all(c.payload.get("output_fields") not in (None, "", "*") for c in double.calls)


@dataclass
class FakeReader:
    """Answers `core/get` by class, to model a custom SoftwareInstance subclass the double does not know."""

    objects: dict[str, list[ItopObject]] = field(default_factory=dict)

    def get(self, class_name: str, key: str | int, fields: Sequence[str] | None = None) -> list[ItopObject]:
        assert fields, "every read must name its fields"
        return self.objects.get(class_name, [])


def test_a_custom_instance_subclass_is_not_an_asset_and_has_no_category() -> None:
    custom = ItopObject("ContainerImage", "305", {"name": "redis image", "system_id": "100", "software_id": "200"})
    server = ItopObject("Server", "100", {"name": "web-01"})
    fake = FakeReader({"SoftwareInstance": [custom], "FunctionalCI": [server, custom], "Server": [server]})
    snapshot = read_inventory(fake)  # type: ignore[arg-type]
    assert [a.itop_id for a in snapshot.assets] == ["100"]
    assert [(i.itop_id, i.itop_class, i.category) for i in snapshot.instances] == [("305", "ContainerImage", None)]
    assert "Software instance 305: class ContainerImage is not a standard category, left empty" in snapshot.warnings
