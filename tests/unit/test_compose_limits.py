"""Every Compose service keeps the F12.3 limits: bounded processes and rotated logs (KICS cannot check them)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]


def services() -> dict[str, dict[str, Any]]:
    # yaml.safe_load resolves the `<<: *anchor` merge keys, like Compose does.
    document = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    return document["services"]


@pytest.mark.parametrize("name", sorted(services()))
def test_every_service_has_a_process_limit_and_rotated_logs(name: str) -> None:
    service = services()[name]
    assert 0 < int(service["pids_limit"]) <= 1024, name
    logging = service["logging"]
    assert logging["driver"] == "json-file", name
    assert logging["options"]["max-size"] and int(logging["options"]["max-file"]) >= 1, name


def test_the_expected_services_exist_in_compose() -> None:
    assert {"db", "auth-emulator", "api", "workers", "embeddings", "demo"} <= set(services())
