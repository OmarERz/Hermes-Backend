"""Smoke test: every package of the layout in docs/03 §1 imports and ships type information."""

import importlib
from pathlib import Path

import pytest

PACKAGES = ["api", "core", "notifications_api", "notifications_slack", "slack_app", "workers"]


@pytest.mark.parametrize("name", PACKAGES)
def test_package_imports_and_is_typed(name: str) -> None:
    module = importlib.import_module(name)
    assert module.__doc__
    assert module.__file__ is not None
    assert (Path(module.__file__).parent / "py.typed").is_file()
