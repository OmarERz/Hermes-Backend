"""Every contract in schemas/ is valid JSON Schema (AGENTS.md: the schemas are law)."""

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from jsonschema.validators import validator_for

pytestmark = pytest.mark.contract

SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "schemas"
SCHEMA_FILES = sorted(SCHEMAS_DIR.glob("*.schema.json"))
TOOL_FILES = sorted(p for p in SCHEMAS_DIR.glob("*.json") if not p.name.endswith(".schema.json"))


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def test_schema_files_are_discovered() -> None:
    assert SCHEMA_FILES
    assert TOOL_FILES


@pytest.mark.parametrize("path", SCHEMA_FILES, ids=lambda p: p.name)
def test_schema_is_valid_against_its_declared_dialect(path: Path) -> None:
    schema = load(path)
    assert "$schema" in schema, "every *.schema.json declares its dialect"
    validator_for(schema).check_schema(schema)


@pytest.mark.parametrize("path", SCHEMA_FILES, ids=lambda p: p.name)
def test_schema_id_matches_file_name(path: Path) -> None:
    assert load(path)["$id"] == path.name


def tool_definitions(path: Path) -> list[dict[str, Any]]:
    data = load(path)
    return data if isinstance(data, list) else [data]


@pytest.mark.parametrize("path", TOOL_FILES, ids=lambda p: p.name)
def test_llm_tool_parameters_are_valid_json_schema(path: Path) -> None:
    tools = tool_definitions(path)
    assert tools
    for tool in tools:
        assert tool["type"] == "function"
        function = tool["function"]
        assert function["name"]
        Draft202012Validator.check_schema(function["parameters"])
