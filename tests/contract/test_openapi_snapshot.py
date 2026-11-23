"""The committed OpenAPI snapshot is the frontend contract: route changes must regenerate it (`make openapi`)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from export_openapi import DEFAULT_OUTPUT, build_openapi, main, render

pytestmark = pytest.mark.contract


def test_committed_snapshot_equals_current_openapi() -> None:
    committed = json.loads(DEFAULT_OUTPUT.read_text(encoding="utf-8"))
    assert committed == json.loads(render(build_openapi())), "OpenAPI changed: run `make openapi` and commit it"


def test_snapshot_publishes_health_and_hides_nothing_secret() -> None:
    document = build_openapi()
    assert "/api/health" in document["paths"]
    assert "openapi:openapi" not in render(document)


def test_export_writes_and_check_detects_drift(tmp_path: Path) -> None:
    target = tmp_path / "out" / "openapi.json"
    assert main(["--output", str(target), "--check"]) == 1  # missing file
    assert main(["--output", str(target)]) == 0
    assert target.read_text(encoding="utf-8") == render(build_openapi())
    assert main(["--output", str(target), "--check"]) == 0
    target.write_text("{}\n", encoding="utf-8")
    assert main(["--output", str(target), "--check"]) == 1
