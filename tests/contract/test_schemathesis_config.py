"""Every cursor-paginated operation lets Schemathesis treat its documented 400 `invalid_cursor` as accepted.

A cursor generated from the schema is never a valid signed one, so the API correctly answers 400; without an entry in
`schemathesis.toml` that answer fails `make prepush` (D-086) as a schema-valid request rejected. Checked here, with no
running stack, so a new paginated route cannot reach the pre-push gate without its entry.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

pytestmark = pytest.mark.contract
ROOT = Path(__file__).resolve().parents[2]
OPENAPI = json.loads((ROOT / "openapi" / "openapi.json").read_text(encoding="utf-8"))
CONFIG = tomllib.loads((ROOT / "schemathesis.toml").read_text(encoding="utf-8"))


def paginated() -> set[str]:
    return {
        f"{method.upper()} {path}"
        for path, item in OPENAPI["paths"].items()
        for method, operation in item.items()
        if any(p.get("name") == "cursor" and p.get("in") == "query" for p in operation.get("parameters", []))
    }


def accepting_400() -> set[str]:
    found = set()
    for entry in CONFIG.get("operations", []):
        statuses = entry.get("checks", {}).get("positive_data_acceptance", {}).get("expected-statuses", [])
        if "400" in statuses:
            found.add(entry["include-name"])
    return found


def test_every_paginated_operation_accepts_its_cursor_400() -> None:
    missing = sorted(paginated() - accepting_400())
    assert not missing, f"add these to schemathesis.toml (see its header): {missing}"


def test_only_paginated_operations_accept_a_400() -> None:
    assert sorted(accepting_400() - paginated()) == []
