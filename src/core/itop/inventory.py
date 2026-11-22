"""Read the CMDB inventory from iTop: CIs with the D-037 extension attributes, software, teams, persons (ESC-03).

The result is a plain snapshot (`InventorySnapshot`); saving it into the cache is `core.inventory.sync`. The query
count does not grow with the inventory: one `core/get` per class family. Class and field names are those of
iTop 3.2.2 per its source and the prototype; ⚠️ confirm them against the live instance (P-011).
Values are data, not instructions: `description` and names are stored and never interpreted.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Final

from core.itop import oql
from core.itop.client import ItopObject, ItopReader

# Software instances are not CIs of the cache: they become `installed_software` (ESC-03).
SOFTWARE_INSTANCE_CLASSES: Final = frozenset(
    {"SoftwareInstance", "DBServer", "WebServer", "Middleware", "OtherSoftware", "PCSoftware"}
)
# Classes that carry a management IP and an OS (not part of FunctionalCI itself).
HOST_CLASSES: Final = ("Server", "VirtualMachine")

CI_FIELDS: Final = (
    "name",
    "description",
    "business_criticity",
    "internet_exposed",
    "confidentiality",
    "personal_data",
    "owner_id",
    "custodian_id",
)
HOST_FIELDS: Final = ("managementip", "osfamily_id_friendlyname", "osversion_id_friendlyname")

CRITICALITIES: Final = frozenset({"high", "medium", "low"})
CONFIDENTIALITIES: Final = frozenset({"public", "classified", "highly_classified", "unclassified"})


@dataclass(frozen=True)
class ItopTeam:
    itop_id: str
    name: str


@dataclass(frozen=True)
class ItopPerson:
    itop_id: str
    name: str
    email: str | None


@dataclass(frozen=True)
class ItopAsset:
    itop_id: str
    itop_class: str
    name: str
    ip: str | None
    os: str | None
    criticality: str  # high | medium | low | unknown
    exposed: bool | None  # None = no data
    confidentiality: str  # public | classified | highly_classified | unclassified
    personal_data: bool | None  # None = unknown
    owner_itop_id: str | None
    custodian_itop_id: str | None
    description: str | None


@dataclass(frozen=True)
class ItopSoftware:
    itop_id: str
    name: str
    vendor: str | None
    version: str | None


@dataclass(frozen=True)
class ItopSoftwareInstance:
    itop_id: str
    itop_class: str
    system_itop_id: str | None
    software_itop_id: str | None


@dataclass
class InventorySnapshot:
    """One consistent read of the inventory (ESC-04). `warnings` name ids, never values."""

    teams: list[ItopTeam] = field(default_factory=list)
    persons: list[ItopPerson] = field(default_factory=list)
    assets: list[ItopAsset] = field(default_factory=list)
    software: list[ItopSoftware] = field(default_factory=list)
    instances: list[ItopSoftwareInstance] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _yes_no(value: str | None) -> bool | None:
    return {"yes": True, "no": False}.get((value or "").lower())


def _ip(raw: str | None, ci_id: str, warnings: list[str]) -> str | None:
    if raw is None:
        return None
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        warnings.append(f"CI {ci_id}: management IP is not a valid address")
        return None


def _os(host: ItopObject | None) -> str | None:
    if host is None:
        return None
    parts = [p for p in (host.text("osfamily_id_friendlyname"), host.text("osversion_id_friendlyname")) if p]
    return " ".join(parts) or None


def _asset(ci: ItopObject, host: ItopObject | None, warnings: list[str]) -> ItopAsset:
    criticality = (ci.text("business_criticity") or "").lower()
    if criticality not in CRITICALITIES:
        criticality = "unknown"
    confidentiality = (ci.text("confidentiality") or "").lower()
    if confidentiality not in CONFIDENTIALITIES:
        if confidentiality:
            warnings.append(f"CI {ci.key}: unknown confidentiality value, treated as unclassified")
        confidentiality = "unclassified"
    personal = (ci.text("personal_data") or "").lower()  # "unknown" and empty both mean unknown
    return ItopAsset(
        itop_id=ci.key,
        itop_class=ci.class_name,
        name=ci.text("name") or f"{ci.class_name} {ci.key}",
        ip=_ip(host.text("managementip") if host else None, ci.key, warnings),
        os=_os(host),
        criticality=criticality,
        exposed=_yes_no(ci.text("internet_exposed")),
        confidentiality=confidentiality,
        personal_data=_yes_no(personal),
        owner_itop_id=ci.text("owner_id"),
        custodian_itop_id=ci.text("custodian_id"),
        description=ci.text("description"),
    )


def _person(obj: ItopObject) -> ItopPerson:
    full = " ".join(p for p in (obj.text("first_name"), obj.text("name")) if p)
    return ItopPerson(itop_id=obj.key, name=full or f"Person {obj.key}", email=obj.text("email"))


def read_inventory(reader: ItopReader) -> InventorySnapshot:
    """Read teams, persons, CIs, the software catalogue and the software instances (constant query count)."""
    snapshot = InventorySnapshot()
    teams = reader.get("Team", oql.select("Team"), ["name"])
    snapshot.teams = [ItopTeam(t.key, t.text("name") or f"Team {t.key}") for t in teams]
    persons = reader.get("Person", oql.select("Person"), ["name", "first_name", "email"])
    snapshot.persons = [_person(p) for p in persons]

    hosts: dict[str, ItopObject] = {}
    for class_name in HOST_CLASSES:
        for host in reader.get(class_name, oql.select(class_name), HOST_FIELDS):
            hosts[host.key] = host
    cis = reader.get("FunctionalCI", oql.select("FunctionalCI"), CI_FIELDS)
    snapshot.assets = [
        _asset(ci, hosts.get(ci.key), snapshot.warnings) for ci in cis if ci.class_name not in SOFTWARE_INSTANCE_CLASSES
    ]

    catalogue = reader.get("Software", oql.select("Software"), ["name", "vendor", "version"])
    snapshot.software = [
        ItopSoftware(s.key, s.text("name") or f"Software {s.key}", s.text("vendor"), s.text("version"))
        for s in catalogue
    ]
    instances = reader.get("SoftwareInstance", oql.select("SoftwareInstance"), ["system_id", "software_id"])
    snapshot.instances = [
        ItopSoftwareInstance(i.key, i.class_name, i.text("system_id"), i.text("software_id")) for i in instances
    ]
    return snapshot
