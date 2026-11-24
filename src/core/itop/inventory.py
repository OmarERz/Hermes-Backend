"""Read the CMDB inventory from iTop: CIs with the D-037 extension attributes, software, licences, teams, persons.

The result is a plain snapshot (`InventorySnapshot`); saving it into the cache is `core.inventory.sync`. The query
count does not grow with the inventory: one `core/get` per class family. Class and field names are those of
iTop 3.2.2 per its source and the prototype; ⚠️ confirm them against the live instance (P-011). The F18.3 fields
(D-088: host CPU and RAM, installation category, status, description and licence) were checked against the
iTop 3.2.2 datamodel (docs/datos/propuestas/inventario-itop.md §1.1).
Values are data, not instructions: `description`, names, CPU and RAM are stored and never interpreted.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import date
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
HOST_FIELDS: Final = ("managementip", "osfamily_id_friendlyname", "osversion_id_friendlyname", "cpu", "ram")
INSTANCE_FIELDS: Final = ("system_id", "software_id", "status", "description", "softwarelicence_id")
# Never `licence_key` (a customer secret, D-088): the list is explicit because an empty one means "*" to iTop.
LICENCE_FIELDS: Final = ("name", "software_id", "usage_limit", "start_date", "end_date", "perpetual")

CRITICALITIES: Final = frozenset({"high", "medium", "low"})
CONFIDENTIALITIES: Final = frozenset({"public", "classified", "highly_classified", "unclassified"})
# The installation category is its real iTop class: SoftwareInstance is abstract (iTop 3.2.2 datamodel).
SOFTWARE_CATEGORIES: Final = frozenset({"DBServer", "Middleware", "OtherSoftware", "PCSoftware", "WebServer"})
INSTALL_STATUSES: Final = frozenset({"active", "inactive"})
MAX_SHORT_TEXT: Final = 255  # iTop AttributeString; the cache CHECKs the same bound


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
    cpu: str | None = None  # Server and VirtualMachine only, free text as iTop keeps it
    ram: str | None = None


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
    category: str | None = None  # itop_class when it is one of SOFTWARE_CATEGORIES
    status: str | None = None  # active | inactive | None (no data)
    description: str | None = None
    licence_itop_id: str | None = None


@dataclass(frozen=True)
class ItopSoftwareLicence:
    itop_id: str
    name: str
    software_itop_id: str | None
    usage_limit: str | None
    start_date: date | None
    end_date: date | None
    perpetual: bool


@dataclass
class InventorySnapshot:
    """One consistent read of the inventory (ESC-04). `warnings` name ids, never values."""

    teams: list[ItopTeam] = field(default_factory=list)
    persons: list[ItopPerson] = field(default_factory=list)
    assets: list[ItopAsset] = field(default_factory=list)
    software: list[ItopSoftware] = field(default_factory=list)
    instances: list[ItopSoftwareInstance] = field(default_factory=list)
    licences: list[ItopSoftwareLicence] = field(default_factory=list)
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


def _short_text(obj: ItopObject, name: str, warnings: list[str]) -> str | None:
    """An iTop string field for a bounded cache column; one that does not fit is dropped (id named, never value)."""
    value = obj.text(name)
    if value is not None and len(value) > MAX_SHORT_TEXT:
        warnings.append(f"{obj.class_name} {obj.key}: {name} longer than {MAX_SHORT_TEXT} characters, left empty")
        return None
    return value


def _date(obj: ItopObject, name: str, warnings: list[str]) -> date | None:
    value = obj.text(name)
    if value is None:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        warnings.append(f"{obj.class_name} {obj.key}: {name} is not a valid date, left empty")
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
        cpu=_short_text(host, "cpu", warnings) if host else None,
        ram=_short_text(host, "ram", warnings) if host else None,
    )


def _person(obj: ItopObject) -> ItopPerson:
    full = " ".join(p for p in (obj.text("first_name"), obj.text("name")) if p)
    return ItopPerson(itop_id=obj.key, name=full or f"Person {obj.key}", email=obj.text("email"))


def _instance(obj: ItopObject, warnings: list[str]) -> ItopSoftwareInstance:
    category = obj.class_name if obj.class_name in SOFTWARE_CATEGORIES else None
    if category is None:
        warnings.append(f"Software instance {obj.key}: class {obj.class_name} is not a standard category, left empty")
    status = obj.text("status")
    if status is not None and status not in INSTALL_STATUSES:
        warnings.append(f"Software instance {obj.key}: unknown status value, left empty")
        status = None
    return ItopSoftwareInstance(
        itop_id=obj.key,
        itop_class=obj.class_name,
        system_itop_id=obj.text("system_id"),
        software_itop_id=obj.text("software_id"),
        category=category,
        status=status,
        description=obj.text("description"),
        licence_itop_id=obj.text("softwarelicence_id"),
    )


def _licence(obj: ItopObject, warnings: list[str]) -> ItopSoftwareLicence:
    perpetual = _yes_no(obj.text("perpetual"))
    if perpetual is None:  # NOT NULL in iTop with default "no"; an odd value must not abort the sync
        warnings.append(f"Software licence {obj.key}: perpetual is not yes or no, treated as no")
    return ItopSoftwareLicence(
        itop_id=obj.key,
        name=_short_text(obj, "name", warnings) or f"Licence {obj.key}",
        software_itop_id=obj.text("software_id"),
        usage_limit=_short_text(obj, "usage_limit", warnings),
        start_date=_date(obj, "start_date", warnings),
        end_date=_date(obj, "end_date", warnings),
        perpetual=bool(perpetual),
    )


def read_inventory(reader: ItopReader) -> InventorySnapshot:
    """Read teams, persons, CIs, the software catalogue, instances and licences (constant query count)."""
    snapshot = InventorySnapshot()
    teams = reader.get("Team", oql.select("Team"), ["name"])
    snapshot.teams = [ItopTeam(t.key, t.text("name") or f"Team {t.key}") for t in teams]
    persons = reader.get("Person", oql.select("Person"), ["name", "first_name", "email"])
    snapshot.persons = [_person(p) for p in persons]

    hosts: dict[str, ItopObject] = {}
    for class_name in HOST_CLASSES:
        for host in reader.get(class_name, oql.select(class_name), HOST_FIELDS):
            hosts[host.key] = host
    # Instances first: whatever iTop returns as a SoftwareInstance (a custom subclass too) is not an asset.
    instances = reader.get("SoftwareInstance", oql.select("SoftwareInstance"), INSTANCE_FIELDS)
    instance_ids = {i.key for i in instances}
    cis = reader.get("FunctionalCI", oql.select("FunctionalCI"), CI_FIELDS)
    snapshot.assets = [
        _asset(ci, hosts.get(ci.key), snapshot.warnings)
        for ci in cis
        if ci.class_name not in SOFTWARE_INSTANCE_CLASSES and ci.key not in instance_ids
    ]

    catalogue = reader.get("Software", oql.select("Software"), ["name", "vendor", "version"])
    snapshot.software = [
        ItopSoftware(s.key, s.text("name") or f"Software {s.key}", s.text("vendor"), s.text("version"))
        for s in catalogue
    ]
    snapshot.instances = [_instance(i, snapshot.warnings) for i in instances]
    licences = reader.get("SoftwareLicence", oql.select("SoftwareLicence"), LICENCE_FIELDS)
    snapshot.licences = [_licence(lic, snapshot.warnings) for lic in licences]
    return snapshot
