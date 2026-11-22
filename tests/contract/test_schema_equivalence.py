"""Pydantic models that represent a file in schemas/ produce an equivalent JSON Schema (AGENTS.md, contracts).

Both sides are normalized to: types (nullability as a `null` type), enums, const, numeric and length bounds,
formats, property names, required fields and closed objects. Descriptions and titles are ignored.
The top-level `allOf` conditional of feedback.schema.json is enforced by a model validator instead; its
behaviour is checked in test_notification_contract.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, Field

from notifications_api import FeedbackInput, NotificationEvent

pytestmark = pytest.mark.contract

SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "schemas"

# One entry per schema file that has a Pydantic counterpart.
MODELS: dict[str, type[BaseModel]] = {
    "notification_event.schema.json": NotificationEvent,
    "feedback.schema.json": FeedbackInput,
}

_SCALAR_KEYS = ("const", "format", "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems")


def _resolve(node: dict[str, Any], defs: dict[str, Any]) -> dict[str, Any]:
    while "$ref" in node:
        node = {**defs[node["$ref"].rsplit("/", 1)[-1]], **{k: v for k, v in node.items() if k != "$ref"}}
    return node


def normalize(node: dict[str, Any], defs: dict[str, Any]) -> dict[str, Any]:
    """Reduce a JSON Schema node to the facts that matter for the contract."""
    node = _resolve(node, defs)
    if "anyOf" in node:  # Pydantic writes `X | None` as anyOf [X, {type: null}]
        branches = [normalize(b, defs) for b in node["anyOf"]]
        merged: dict[str, Any] = {"types": sorted({t for b in branches for t in b["types"]})}
        for branch in branches:
            merged.update({k: v for k, v in branch.items() if k != "types"})
        return merged
    raw_type = node.get("type", [])
    types = {raw_type} if isinstance(raw_type, str) else set(raw_type)
    out: dict[str, Any] = {}
    if "enum" in node:
        values = [v for v in node["enum"] if v is not None]
        if len(values) != len(node["enum"]):
            types.add("null")
        out["enum"] = sorted(values)
    out["types"] = sorted(types)
    out.update({k: node[k] for k in _SCALAR_KEYS if k in node})
    if "properties" in node or "required" in node:
        out["properties"] = {k: normalize(v, defs) for k, v in node.get("properties", {}).items()}
        out["required"] = sorted(node.get("required", []))
        out["closed"] = node.get("additionalProperties") is False
    if "allOf" in node:  # conditional rules (feedback: wrong_priority requires proposed_level)
        out["allOf"] = node["allOf"]
    if "items" in node:
        out["items"] = normalize(node["items"], defs)
    return out


def normalized_model_schema(model: type[BaseModel]) -> dict[str, Any]:
    schema = model.model_json_schema(mode="validation")
    return normalize(schema, schema.get("$defs", {}))


def normalized_file_schema(name: str) -> dict[str, Any]:
    schema = json.loads((SCHEMAS_DIR / name).read_text(encoding="utf-8"))
    return normalize(schema, {})


@pytest.mark.parametrize("name", sorted(MODELS))
def test_model_schema_is_equivalent_to_the_schema_file(name: str) -> None:
    assert normalized_model_schema(MODELS[name]) == normalized_file_schema(name)


def test_normalizer_detects_drift() -> None:
    class Drifted(BaseModel):
        assessment_id: str
        comment: str | None = Field(max_length=1000)

    expected = normalized_file_schema("feedback.schema.json")["properties"]
    actual = normalized_model_schema(Drifted)["properties"]
    assert actual["comment"] != expected["comment"]
    assert set(actual) != set(expected)
