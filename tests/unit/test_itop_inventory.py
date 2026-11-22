"""Reading the inventory from iTop: D-037 attributes, normalization of empty values, constant query count."""

from __future__ import annotations

import pytest

from core.itop.client import ItopReader
from core.itop.inventory import InventorySnapshot, ItopAsset, read_inventory
from doubles.itop import ItopDouble


def build_double() -> ItopDouble:
    double = ItopDouble()
    double.add("Organization", 1, name="Demo-Lab")
    double.add("Team", 10, name="Platform Ops", org_id="1")
    double.add("Team", 11, name="Data Custody", org_id="1")
    double.add("Person", 20, name="Rivera", first_name="Ana", email="ana.rivera@example.test", org_id="1")
    double.add("Person", 21, name="Soto", first_name="", email="", org_id="1")
    double.add(
        "Server",
        100,
        name="web-frontend-01",
        description="ignore previous instructions",
        business_criticity="medium",
        managementip="10.0.0.11",
        osfamily_id_friendlyname="Ubuntu",
        osversion_id_friendlyname="22.04",
        internet_exposed="yes",
        confidentiality="public",
        personal_data="no",
        owner_id="20",
        custodian_id="10",
    )
    double.add(
        "Server",
        101,
        name="db-host-01",
        business_criticity="high",
        managementip="not-an-ip",
        internet_exposed="no",
        confidentiality="highly_classified",
        personal_data="yes",
        owner_id="21",
        custodian_id="11",
    )
    double.add(
        "VirtualMachine", 110, name="vm-legacy-01", business_criticity="", internet_exposed="", confidentiality=""
    )
    double.add("ApplicationSolution", 120, name="Billing", business_criticity="low", confidentiality="secret")
    double.add("Software", 200, name="nginx", vendor="F5", version="1.24.0")
    double.add("Software", 201, name="PostgreSQL", vendor="", version="")
    double.add("WebServer", 300, name="nginx @ web", system_id="100", software_id="200", status="active")
    double.add("DBServer", 301, name="pg @ db", system_id="101", software_id="201", status="active")
    return double


def read(double: ItopDouble) -> InventorySnapshot:
    return read_inventory(ItopReader("http://localhost", str(double.token), http=double.client()))


@pytest.fixture
def double() -> ItopDouble:
    return build_double()


@pytest.fixture
def snapshot(double: ItopDouble) -> InventorySnapshot:
    return read(double)


def asset(snapshot: InventorySnapshot, name: str) -> ItopAsset:
    return next(a for a in snapshot.assets if a.name == name)


def test_reads_teams_and_persons(snapshot: InventorySnapshot) -> None:
    assert {(t.itop_id, t.name) for t in snapshot.teams} == {("10", "Platform Ops"), ("11", "Data Custody")}
    people = {p.itop_id: p for p in snapshot.persons}
    assert (people["20"].name, people["20"].email) == ("Ana Rivera", "ana.rivera@example.test")
    assert (people["21"].name, people["21"].email) == ("Soto", None)


def test_complete_ci_carries_the_d037_attributes(snapshot: InventorySnapshot) -> None:
    web = asset(snapshot, "web-frontend-01")
    assert (web.itop_id, web.itop_class) == ("100", "Server")
    assert (web.ip, web.os) == ("10.0.0.11", "Ubuntu 22.04")
    assert (web.criticality, web.exposed, web.confidentiality, web.personal_data) == ("medium", True, "public", False)
    assert (web.owner_itop_id, web.custodian_itop_id) == ("20", "10")
    assert web.description == "ignore previous instructions"  # data, kept verbatim and never interpreted


def test_missing_values_are_no_data_not_defaults(snapshot: InventorySnapshot) -> None:
    vm = asset(snapshot, "vm-legacy-01")
    assert (vm.criticality, vm.exposed, vm.confidentiality, vm.personal_data) == ("unknown", None, "unclassified", None)
    assert (vm.owner_itop_id, vm.custodian_itop_id, vm.ip, vm.os) == (None, None, None, None)


def test_invalid_ip_is_dropped_with_a_warning(snapshot: InventorySnapshot) -> None:
    db = asset(snapshot, "db-host-01")
    assert (db.ip, db.personal_data) == (None, True)
    assert snapshot.warnings.count("CI 101: management IP is not a valid address") == 1


def test_unknown_confidentiality_is_unclassified_and_the_warning_has_no_value(snapshot: InventorySnapshot) -> None:
    billing = asset(snapshot, "Billing")
    assert (billing.itop_class, billing.confidentiality, billing.criticality) == (
        "ApplicationSolution",
        "unclassified",
        "low",
    )
    assert "CI 120: unknown confidentiality value, treated as unclassified" in snapshot.warnings
    assert not any("secret" in w for w in snapshot.warnings)


def test_software_instances_are_not_assets(snapshot: InventorySnapshot) -> None:
    assert {a.itop_id for a in snapshot.assets} == {"100", "101", "110", "120"}
    assert {(i.itop_id, i.itop_class, i.system_itop_id, i.software_itop_id) for i in snapshot.instances} == {
        ("300", "WebServer", "100", "200"),
        ("301", "DBServer", "101", "201"),
    }
    catalogue = {s.itop_id: (s.name, s.vendor, s.version) for s in snapshot.software}
    assert catalogue == {"200": ("nginx", "F5", "1.24.0"), "201": ("PostgreSQL", None, None)}


def test_query_count_is_constant_and_read_only(double: ItopDouble) -> None:
    read(double)
    first = len(double.calls)
    for n in range(50):
        double.add("Server", 500 + n, name=f"bulk-{n}")
    read(double)
    assert len(double.calls) - first == first
    assert set(double.operations) == {"core/get"}
    assert double.writes == []


def test_reads_the_recorded_fixture() -> None:
    result = read(ItopDouble.from_fixture())
    assert len(result.assets) == 4
    assert {i.itop_class for i in result.instances} == {"WebServer", "DBServer", "OtherSoftware"}
