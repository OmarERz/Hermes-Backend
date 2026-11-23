"""F10.6: the OpenAPI document is documented for client generation (operation ids, tags, descriptions, examples)."""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Any

import pytest
from export_openapi import build_openapi
from pydantic import BaseModel

from api.auth import admin_routes
from api.errors import ErrorResponse
from api.itop_webhook import ItopWebhookCall, WebhookAccepted
from api.openapi_docs import ENUMS, OPERATIONS, TAGS
from api.routes import models as route_models
from core.db.seeds import WEIGHTS
from notifications_api import FeedbackResult

pytestmark = pytest.mark.contract
DOCUMENT = build_openapi()
OPERATION_ID = re.compile(r"^[a-z]+(_[a-z]+)+$")
METHODS = ("get", "put", "post", "delete", "patch")


def operations() -> list[tuple[str, str, dict[str, Any]]]:
    return [
        (method.upper(), path, operation)
        for path, item in DOCUMENT["paths"].items()
        for method, operation in item.items()
        if method in METHODS
    ]


def test_every_operation_has_a_unique_explicit_snake_case_operation_id() -> None:
    ids = [operation["operationId"] for _, _, operation in operations()]
    assert len(ids) == len(set(ids)), "operation ids must be unique"
    for operation_id in ids:
        assert OPERATION_ID.match(operation_id), operation_id
        assert "_api_" not in operation_id, f"{operation_id} is the auto-generated name"
    assert {(method, path) for method, path, _ in operations()} == set(OPERATIONS)


def test_every_operation_has_a_declared_tag_summary_and_description() -> None:
    declared = {tag for tag, _, _ in TAGS}
    assert [t["name"] for t in DOCUMENT["tags"]] == [tag for tag, _, _ in TAGS]
    for method, path, operation in operations():
        assert operation["tags"] and set(operation["tags"]) <= declared, (method, path)
        assert operation["summary"].strip() and operation["description"].strip(), (method, path)
        assert operation["summary"] != operation["operationId"].replace("_", " ").title()


def test_every_schema_property_and_parameter_is_described() -> None:
    missing = [
        f"{name}.{prop}"
        for name, schema in DOCUMENT["components"]["schemas"].items()
        for prop, body in schema.get("properties", {}).items()
        if "description" not in body and not any("description" in part for part in body.get("anyOf", []))
    ]
    assert not missing, missing
    unlabeled = [
        f"{method} {path} {parameter['name']}"
        for method, path, operation in operations()
        for parameter in operation.get("parameters", [])
        if "description" not in parameter
    ]
    assert not unlabeled, unlabeled


def test_every_enum_value_is_described() -> None:
    checked = 0
    for name, schema in DOCUMENT["components"]["schemas"].items():
        for prop, body in schema.get("properties", {}).items():
            variants = [body, *body.get("anyOf", []), *(body.get("items", {}) and [body["items"]])]
            for variant in variants:
                if "enum" in variant and tuple(variant["enum"]) in ENUMS:
                    text = body.get("description", "") + variant.get("description", "")
                    for value in variant["enum"]:
                        assert f"`{value}`" in text, f"{name}.{prop} does not describe {value}"
                    checked += 1
    assert checked > 20


def test_info_has_description_contact_and_a_local_server() -> None:
    info = DOCUMENT["info"]
    assert info["description"] and info["contact"]["name"]
    urls = [server["url"] for server in DOCUMENT["servers"]]
    assert urls[0] == "/"  # a client that takes the first server stays on its own origin
    assert "http://127.0.0.1:8000" in urls


MODELS: dict[str, type[BaseModel]] = {
    **{name: cls for name, cls in vars(route_models).items() if isinstance(cls, type) and issubclass(cls, BaseModel)},
    "ErrorResponse": ErrorResponse,
    "RoleAssignment": admin_routes.RoleAssignment,
    "FeedbackResult": FeedbackResult,
    "ItopWebhookCall": ItopWebhookCall,
    "WebhookAccepted": WebhookAccepted,
}


def test_examples_are_valid_instances_of_their_schema() -> None:
    with_examples = {
        name: schema["examples"] for name, schema in DOCUMENT["components"]["schemas"].items() if "examples" in schema
    }
    assert len(with_examples) >= 20
    for name, examples in with_examples.items():
        for example in examples:
            MODELS[name].model_validate(example)


def test_formula_examples_keep_the_weights_summing_to_one() -> None:
    schemas = DOCUMENT["components"]["schemas"]
    for name in ("ConfigUpdate", "SimulationRequest"):
        for example in schemas[name]["examples"]:
            weights = {
                key.removeprefix("weights."): Decimal(v)
                for key, v in example["changes"].items()
                if key.startswith("weights.")
            }
            total = sum({**{k: Decimal(v) for k, v in WEIGHTS.items()}, **weights}.values())
            assert total == Decimal(1), f"{name} example weights sum to {total}"
