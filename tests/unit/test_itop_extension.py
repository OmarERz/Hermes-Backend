"""The hermes-ci-attributes iTop extension (D-037, F16.1): what the console shows and what the backend may do.

Static checks of our own files (the live compile is checked by the slow e2e test): the least-privilege profile allows
exactly the stimuli the outbox sends, every concrete CI class shows the five attributes, and both dictionaries label
every attribute and every value.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from core.itop.outbox import STIMULI

pytestmark = pytest.mark.unit

EXTENSION = Path(__file__).resolve().parents[2] / "docker" / "itop" / "extensions" / "hermes-ci-attributes"
DATAMODEL = (EXTENSION / "datamodel.hermes-ci-attributes.xml").read_text(encoding="utf-8")
FIELDS = ("internet_exposed", "confidentiality", "personal_data", "owner_id", "custodian_id")
ENUMS = {
    "internet_exposed": {"yes", "no"},
    "confidentiality": {"public", "classified", "highly_classified", "unclassified"},
    "personal_data": {"yes", "no", "unknown"},
}
# Concrete FunctionalCI classes of the installed iTop 3.2.2 modules, software instances excluded (they are not CIs
# of the Hermes inventory): listed from the live instance with MetaModel::EnumChildClasses.
CI_CLASSES = {
    "ApplicationSolution", "BusinessProcess", "DatabaseSchema", "Enclosure", "Farm", "Hypervisor", "IPPhone",
    "MiddlewareInstance", "MobilePhone", "NetworkDevice", "PC", "PDU", "Peripheral", "Phone", "PowerSource", "Printer",
    "Rack", "Server", "Tablet", "VirtualMachine", "WebApplication",
}  # fmt: skip


def test_the_backend_profile_allows_only_the_stimuli_the_outbox_sends() -> None:
    profile = re.search(r"<profile id=\"100\".*?</profile>", DATAMODEL, re.S)
    assert profile and "<name>Hermes Backend</name>" in profile.group(0)
    allowed = set(re.findall(r'<action id="stimulus:(\w+)">allow</action>', profile.group(0)))
    assert allowed == set(STIMULI) == {"ev_reopen"}


def test_every_concrete_ci_class_shows_the_five_attributes() -> None:
    classes = re.findall(r'<class id="(\w+)" _delta="must_exist">(.*?)</class>', DATAMODEL, re.S)
    shown = {name: body for name, body in classes if "fieldset:Hermes:security" in body}
    assert set(shown) == CI_CLASSES
    for name, body in shown.items():
        assert re.findall(r'<item id="(\w+)"><rank>', body) == list(FIELDS), name


@pytest.mark.parametrize(("file", "language"), [("es_cr", "ES CR"), ("en", "EN US")])
def test_the_dictionaries_label_every_attribute_and_value(file: str, language: str) -> None:
    text = (EXTENSION / "dictionaries" / f"{file}.dict.hermes-ci-attributes.php").read_text(encoding="utf-8")
    assert f"Dict::Add('{language}'" in text
    keys = set(re.findall(r"^\s*'([^']+)' =>", text, re.M))
    expected = {"Hermes:security"}
    for field in FIELDS:
        expected |= {f"Class:FunctionalCI/Attribute:{field}", f"Class:FunctionalCI/Attribute:{field}+"}
        expected |= {f"Class:FunctionalCI/Attribute:{field}/Value:{value}" for value in ENUMS.get(field, set())}
    assert keys == expected


def test_the_enum_values_of_the_datamodel_match_the_inventory_reader() -> None:
    for field, values in ENUMS.items():
        block = re.search(rf'<field id="{field}" xsi:type="AttributeEnum".*?</field>', DATAMODEL, re.S)
        assert block, field
        assert set(re.findall(r'<value id="(\w+)">', block.group(0))) == values, field
