"""Request bounds (F12.3, ASVS 5.0 V2.2.1): every text of a request body has a length and every list a size."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import BaseModel, ValidationError

from api.routes.models import (
    CNA_NAME_PATTERN,
    CPE_NAME_PATTERN,
    MAX_CODE,
    MAX_CONFIG_CHANGES,
    MAX_CONFIG_VALUE,
    MAX_LIST_ITEMS,
    MAX_NAME,
    MAX_URL,
    CnaNames,
    ConfigUpdate,
    ConnectionTestRequest,
    FeedbackRequest,
    MappingInput,
    PeerCompany,
    PeerCompanyInput,
    ProfileUpdate,
    SimulationRequest,
    SourceCreate,
    StixExportRequest,
)
from core.configuration.errors import ValidationFailedError, check_text
from core.cpe.candidates import parse_cpe_parts
from core.cpe.mapping import MappingInput as MappingData
from core.cpe.mapping import validate

pytestmark = pytest.mark.unit

PEER = {"name": "Banco Par", "aliases": [], "domain": "par.example", "sector": "finance", "country": "MX"}
PROFILE = {"expected_version": 1, "sector": "finance", "subsectors": [], "countries": ["MX"], "language": "es"}


def changes(count: int, value: str = "1", key_length: int = 10) -> dict[str, str]:
    return {f"{i:0{key_length}d}": value for i in range(count)}


ACCEPTED: list[tuple[type[BaseModel], dict[str, Any]]] = [
    (ConfigUpdate, {"expected_version": 1, "changes": changes(MAX_CONFIG_CHANGES, "x" * MAX_CONFIG_VALUE)}),
    (SimulationRequest, {"changes": changes(MAX_CONFIG_CHANGES, key_length=MAX_CODE)}),
    (PeerCompanyInput, {**PEER, "name": "n" * MAX_NAME, "aliases": ["a" * MAX_NAME] * MAX_LIST_ITEMS}),
    (ProfileUpdate, {**PROFILE, "subsectors": ["s" * MAX_CODE] * MAX_LIST_ITEMS}),
    (SourceCreate, {"name": "n" * MAX_NAME, "url": "https://" + "u" * (MAX_URL - 8)}),
    (MappingInput, {"cpe": "cpe:2.3:a:" + "v" * 200 + ":" + "p" * 200 + ":" + "1" * 100}),  # 512 characters
    (FeedbackRequest, {"assessment_id": "a" * MAX_CODE, "verdict": "relevant"}),
    (StixExportRequest, {"scope": "run", "run_id": "r" * MAX_CODE}),
]

REFUSED: list[tuple[type[BaseModel], dict[str, Any]]] = [
    (ConfigUpdate, {"expected_version": 1, "changes": changes(MAX_CONFIG_CHANGES + 1)}),
    (ConfigUpdate, {"expected_version": 1, "changes": {"k": "x" * (MAX_CONFIG_VALUE + 1)}}),
    (SimulationRequest, {"changes": changes(1, key_length=MAX_CODE + 1)}),
    (PeerCompanyInput, {**PEER, "name": "n" * (MAX_NAME + 1)}),
    (PeerCompanyInput, {**PEER, "name": ""}),
    (PeerCompanyInput, {**PEER, "aliases": ["a"] * (MAX_LIST_ITEMS + 1)}),
    (PeerCompanyInput, {**PEER, "aliases": ["a" * (MAX_NAME + 1)]}),
    (PeerCompanyInput, {**PEER, "domain": "d" * 254}),
    (PeerCompanyInput, {**PEER, "sector": "s" * (MAX_CODE + 1)}),
    (ProfileUpdate, {**PROFILE, "sector": "s" * (MAX_CODE + 1)}),
    (ProfileUpdate, {**PROFILE, "subsectors": ["s"] * (MAX_LIST_ITEMS + 1)}),
    (ProfileUpdate, {**PROFILE, "countries": ["MX"] * 301}),
    (SourceCreate, {"name": "n" * (MAX_NAME + 1), "url": "https://feed.example"}),
    (SourceCreate, {"name": "feed", "url": "https://" + "u" * (MAX_URL - 7)}),
    (MappingInput, {"cpe": "cpe:2.3:a:" + "v" * 200 + ":" + "p" * 200 + ":" + "1" * 101}),
    (FeedbackRequest, {"assessment_id": "a" * (MAX_CODE + 1), "verdict": "relevant"}),
    (StixExportRequest, {"scope": "run", "run_id": "r" * (MAX_CODE + 1)}),
    (StixExportRequest, {"scope": "date_range", "date_from": "d" * (MAX_CODE + 1)}),
    (ConnectionTestRequest, {"names": ["itop"] * 11}),
]


@pytest.mark.parametrize(("model", "body"), ACCEPTED, ids=lambda v: getattr(v, "__name__", ""))
def test_bodies_at_the_bound_are_accepted(model: type[BaseModel], body: dict[str, Any]) -> None:
    model.model_validate(body)


@pytest.mark.parametrize(("model", "body"), REFUSED, ids=lambda v: getattr(v, "__name__", ""))
def test_bodies_past_the_bound_are_refused(model: type[BaseModel], body: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(body)


def test_empty_aliases_stay_accepted_for_the_service_to_drop() -> None:
    assert PeerCompanyInput.model_validate({**PEER, "aliases": ["", "Par"]}).aliases == ["", "Par"]


def test_a_stored_peer_with_values_longer_than_the_new_bounds_still_lists() -> None:
    """Rows saved before F12.3 keep loading: the response model does not carry the input bounds."""
    long_row = {**PEER, "id": "p-1", "name": "n" * 500, "aliases": ["a"] * 80, "domain": "d" * 400, "sector": "s" * 150}
    assert PeerCompany.model_validate(long_row).domain == "d" * 400


def test_the_bounds_are_published_in_the_openapi_schema() -> None:
    schema = ConfigUpdate.model_json_schema()
    assert schema["properties"]["changes"]["maxProperties"] == MAX_CONFIG_CHANGES
    assert schema["properties"]["changes"]["propertyNames"] == {"maxLength": MAX_CODE}
    assert PeerCompanyInput.model_json_schema()["properties"]["name"]["maxLength"] == MAX_NAME


@pytest.mark.parametrize(
    "text",
    [f"Banco{chr(0x202E)}raP", f"a{chr(0x2066)}b", f"x{chr(0x202A)}y", "tab\tname", "del\x7f", "nul\x00"],
)
def test_bidirectional_and_control_characters_are_refused(text: str) -> None:
    with pytest.raises(ValidationFailedError) as caught:
        check_text("body.name", text)
    assert caught.value.problems[0].issue == "invalid_characters"


def test_ordinary_unicode_names_pass() -> None:
    check_text("body.name", "Banco Ñandú · Grupo «Par» 中文 עברית", None)


@settings(max_examples=300)
@given(st.from_regex(CPE_NAME_PATTERN, fullmatch=True).filter(lambda name: len(name) <= 512))
def test_every_schema_valid_cpe_name_is_one_the_mapping_accepts(name: str) -> None:
    """F12.3: the schema pattern is the mapping's own rule, so a schema-valid name is never refused later."""
    MappingInput.model_validate({"cpe": name})
    parsed = parse_cpe_parts(name)
    assert parsed is not None
    validate(MappingData(nvd_vendor=parsed[1], nvd_product=parsed[2], nvd_part=parsed[0]))


@settings(max_examples=300)
@given(st.from_regex(CNA_NAME_PATTERN, fullmatch=True).filter(lambda name: len(name) <= 200))
def test_every_schema_valid_cna_name_is_one_the_mapping_accepts(name: str) -> None:
    """F15.9: a CNA name the schema accepts is never refused by the mapping service (Schemathesis positive data)."""
    names = CnaNames.model_validate({"vendor": name, "product": name})
    validate(MappingData(cna_vendor=names.vendor, cna_product=names.product))
