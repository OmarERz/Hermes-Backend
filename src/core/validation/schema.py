"""Layer VAL-02: JSON Schema validation plus the length and count limits strict mode cannot express (VAL-04).

The tool schemas live in `schemas/` (the contract). `ToolSchema` carries the version and a hash of the schema so each
stored output records what it was validated with.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

from core.validation.violations import Violation

SCHEMAS_DIR_ENV = "SCHEMAS_DIR"
MAX_DEPTH = 8  # the tool schemas nest 4 levels; anything deeper is not walked
UNIT_RANGE_FIELDS = frozenset({"confidence", "cvss_confidence"})  # schemas state 0 to 1 only in prose
DEFAULT_MAX_ITEMS = 200  # a weekly roundup lists 20 CVEs; 200 is generous and still bounded
DEFAULT_MAX_CHARS = 300
MAX_CHARS_BY_FIELD = {"quote": 600, "summary": 1500, "description": 600, "notes": 1500, "affected_versions": 200}
MAX_ITEMS_BY_FIELD = {"event_types": 8, "aliases": 20, "malware": 30}


def schemas_dir() -> Path:
    return Path(os.environ.get(SCHEMAS_DIR_ENV) or Path.cwd() / "schemas")


@dataclass(frozen=True)
class Limits:
    max_items: dict[str, int] = field(default_factory=lambda: dict(MAX_ITEMS_BY_FIELD))
    max_chars: dict[str, int] = field(default_factory=lambda: dict(MAX_CHARS_BY_FIELD))
    default_items: int = DEFAULT_MAX_ITEMS
    default_chars: int = DEFAULT_MAX_CHARS


@dataclass(frozen=True)
class ToolSchema:
    """A tool schema frozen at load time: the hash and the schema applied come from the same serialized copy."""

    name: str
    version: str
    hash: str
    parameters_json: str

    @property
    def parameters(self) -> dict[str, Any]:
        loaded: dict[str, Any] = json.loads(self.parameters_json)
        return loaded

    @classmethod
    def from_tool(cls, tool: dict[str, Any], version: str) -> ToolSchema:
        function = tool["function"]
        canonical = json.dumps(tool, sort_keys=True, separators=(",", ":"))
        return cls(
            name=function["name"],
            version=version,
            hash=hashlib.sha256(canonical.encode()).hexdigest(),
            parameters_json=json.dumps(function["parameters"], sort_keys=True),
        )

    @classmethod
    def load(cls, filename: str, version: str, directory: Path | None = None) -> ToolSchema:
        path = (directory or schemas_dir()) / filename
        return cls.from_tool(json.loads(path.read_text(encoding="utf-8")), version)


_SAFE_KEY = re.compile(r"^[A-Za-z0-9_]{1,40}$")


def _path(parent: str, key: str | int) -> str:
    """A location for the retry text: model-chosen keys that are not plain names never get copied into it."""
    if isinstance(key, int):
        return f"{parent}[{key}]"
    name = key if _SAFE_KEY.match(key) else "<key>"
    return f"{parent}.{name}" if parent else name


def _dotted(parts: Iterable[str | int]) -> str:
    path = ""
    for part in parts:
        path = _path(path, part)
    return path


@dataclass
class _Walk:
    limits: Limits
    out: list[Violation]

    def check(self, value: Any, path: str, key: str, depth: int = 0) -> None:
        if depth > MAX_DEPTH:
            self.out.append(Violation("VAL-02.limits", path, "The output is nested too deeply", "depth"))
        elif isinstance(value, dict):
            for child_key, child in value.items():
                self.check(child, _path(path, child_key), child_key, depth + 1)
        elif isinstance(value, list):
            cap = self.limits.max_items.get(key, self.limits.default_items)
            if len(value) > cap:
                self.out.append(Violation("VAL-02.limits", path, f"{len(value)} items, at most {cap}", "max_items"))
            for index, child in enumerate(value):
                self.check(child, _path(path, index), key, depth + 1)
        elif isinstance(value, str):
            cap = self.limits.max_chars.get(key, self.limits.default_chars)
            if len(value) > cap:
                message = f"{len(value)} characters, at most {cap}"
                self.out.append(Violation("VAL-02.limits", path, message, "max_chars"))


def _describe(error: ValidationError) -> tuple[str, str]:
    """A diagnostic and a constraint code that never copy the rejected value (it could be long or hostile)."""
    kind = str(error.validator)
    instance = error.instance
    if kind == "required" and isinstance(instance, dict):
        required = error.validator_value if isinstance(error.validator_value, list) else []
        missing = sorted(str(f) for f in required if f not in instance)
        names = ", ".join(name for name in missing if _SAFE_KEY.match(name))
        return f"Missing required field(s): {names}", f"required:{','.join(missing)}"
    if kind == "additionalProperties" and isinstance(instance, dict):
        allowed = dict(error.schema).get("properties", {}) if isinstance(error.schema, dict) else {}
        extra = sorted(str(k) for k in instance if k not in allowed)
        names = ", ".join(name for name in extra if _SAFE_KEY.match(name))
        return f"Unexpected field(s) in this object: {names}", f"additionalProperties:{','.join(extra)}"
    if kind == "type":
        return f"Expected type {error.validator_value}", "type"
    if kind == "enum":
        return "The value is not one of the allowed values", "enum"
    return f"Violates the '{kind}' constraint", kind


def _check_ranges(value: Any, path: str, key: str, out: list[Violation], depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        return
    if isinstance(value, dict):
        for child_key, child in value.items():
            _check_ranges(child, _path(path, child_key), child_key, out, depth + 1)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_ranges(child, _path(path, index), key, out, depth + 1)
    elif (
        key in UNIT_RANGE_FIELDS
        and isinstance(value, int | float)
        and not isinstance(value, bool)
        and not 0 <= value <= 1
    ):
        out.append(Violation("VAL-02.limits", path, "The value must be between 0 and 1", "range"))


def _too_deep(value: Any) -> bool:
    """Iterative depth check, so a hostile structure is rejected before anything recurses over it."""
    stack = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_DEPTH:
            return True
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
    return False


def validate_schema(output: Any, schema: ToolSchema, limits: Limits | None = None) -> list[Violation]:
    """Violations of the tool schema (types, enums, required, no extra fields) and of the size limits."""
    if _too_deep(output):
        return [Violation("VAL-02.limits", "", "The output is nested too deeply", "depth")]
    errors = sorted(
        Draft202012Validator(schema.parameters).iter_errors(output), key=lambda e: [str(p) for p in e.absolute_path]
    )
    violations: list[Violation] = []
    for error in errors:
        message, code = _describe(error)
        violations.append(Violation("VAL-02.schema", _dotted(error.absolute_path), message, code))
    if isinstance(output, dict):
        _Walk(limits or Limits(), violations).check(output, "", "")
        _check_ranges(output, "", "", violations)
    return violations
