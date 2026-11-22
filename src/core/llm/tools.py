"""Tool definitions loaded from schemas/*_tool.json and schemas/judge_tools.json (strict mode, JUE-03)."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from core.llm.errors import ToolArgumentsError, ToolDefinitionError

SCHEMAS_DIR_ENV = "SCHEMAS_DIR"
_SOURCE_TREE_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"


def default_schemas_dir() -> Path:
    """Where the schemas live: `$SCHEMAS_DIR` (the image sets /app/schemas, the installed package has no schemas/
    next to it) or the repository's `schemas/` when running from the source tree."""
    configured = os.environ.get(SCHEMAS_DIR_ENV, "").strip()
    return Path(configured) if configured else _SOURCE_TREE_SCHEMAS


# Keywords DeepSeek strict mode does not support (docs/07 JUE-03): length and item-count limits are checked by code.
_UNSUPPORTED_IN_STRICT = frozenset({"minLength", "maxLength", "minItems", "maxItems"})


@dataclass(frozen=True)
class ToolDefinition:
    """One function tool: its OpenAI-format definition plus a validator for its arguments."""

    name: str
    definition: Mapping[str, Any]

    @property
    def parameters(self) -> Mapping[str, Any]:
        parameters: Mapping[str, Any] = self.definition["function"]["parameters"]
        return parameters

    def validate_arguments(self, arguments: Any) -> None:
        """Raise ToolArgumentsError listing field paths and rules; never the offending values."""
        errors = sorted(Draft202012Validator(self.parameters).iter_errors(arguments), key=lambda e: list(e.path))
        if errors:
            problems = [f"{'.'.join(str(p) for p in e.path) or '<root>'}: {e.validator}" for e in errors]
            raise ToolArgumentsError(self.name, problems)


def check_strict_compatible(name: str, node: Any, path: str = "parameters") -> None:
    """Strict mode needs every object property required, additionalProperties false and no length/count limits."""
    if isinstance(node, list):
        for index, item in enumerate(node):
            check_strict_compatible(name, item, f"{path}[{index}]")
        return
    if not isinstance(node, dict):
        return
    if node.get("type") == "object" or "properties" in node:
        properties = node.get("properties", {})
        if node.get("additionalProperties") is not False:
            raise ToolDefinitionError(f"tool {name!r}: {path} must set additionalProperties: false")
        if set(node.get("required", [])) != set(properties):
            raise ToolDefinitionError(f"tool {name!r}: {path} must list every property as required")
    for keyword in _UNSUPPORTED_IN_STRICT & node.keys():
        raise ToolDefinitionError(f"tool {name!r}: {path} uses {keyword}, unsupported in strict mode")
    for key, value in node.items():
        check_strict_compatible(name, value, f"{path}.{key}")


def make_tool(definition: Mapping[str, Any]) -> ToolDefinition:
    """Build a tool from an OpenAI-format function definition, enforcing strict-mode rules."""
    function = definition.get("function")
    if definition.get("type") != "function" or not isinstance(function, dict) or "name" not in function:
        raise ToolDefinitionError("not a function tool definition")
    name = str(function["name"])
    if function.get("strict") is not True:
        raise ToolDefinitionError(f"tool {name!r} must set strict: true")
    check_strict_compatible(name, function.get("parameters"))
    return ToolDefinition(name=name, definition=definition)


def load_tools(schemas_dir: Path | None = None) -> dict[str, ToolDefinition]:
    """Load every tool from schemas/*_tool.json (one definition each) and schemas/judge_tools.json (a list)."""
    schemas_dir = schemas_dir or default_schemas_dir()
    tools: dict[str, ToolDefinition] = {}
    files = [*sorted(schemas_dir.glob("*_tool.json")), schemas_dir / "judge_tools.json"]
    for path in files:
        if not path.is_file():
            raise ToolDefinitionError(f"tool file not found: {path.name}")
        data = json.loads(path.read_text(encoding="utf-8"))
        for definition in data if isinstance(data, list) else [data]:
            tool = make_tool(definition)
            if tool.name in tools:
                raise ToolDefinitionError(f"duplicate tool name {tool.name!r}")
            tools[tool.name] = tool
    return tools
