"""The import-linter contracts in pyproject.toml encode the package boundaries of docs/03 §1."""

import tomllib
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"

EXPECTED = {
    "notifications_slack": {"core", "api", "workers"},
    "notifications_api": {"api", "core", "workers", "notifications_slack"},
    "core": {"api", "workers"},
    "workers": {"api"},
}


def test_boundary_contracts_match_architecture() -> None:
    config = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["tool"]["importlinter"]
    actual = {
        contract["source_modules"][0]: set(contract["forbidden_modules"])
        for contract in config["contracts"]
        if contract["type"] == "forbidden"
    }
    assert actual == EXPECTED
