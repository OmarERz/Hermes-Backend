"""Every Compose service keeps the F12.3 limits: bounded processes and rotated logs (KICS cannot check them).

Covers the Hermes stack (compose.yaml) and the persistent iTop (compose.itop.yaml, F16.1), which also must keep
running after a host restart and without added capabilities.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILES = ("compose.yaml", "compose.itop.yaml")


def services(file: str = "compose.yaml") -> dict[str, dict[str, Any]]:
    # yaml.safe_load resolves the `<<: *anchor` merge keys, like Compose does.
    document = yaml.safe_load((ROOT / file).read_text(encoding="utf-8"))
    return document["services"]


ALL_SERVICES = [(file, name) for file in COMPOSE_FILES for name in sorted(services(file))]


@pytest.mark.parametrize(("file", "name"), ALL_SERVICES)
def test_every_service_has_a_process_limit_and_rotated_logs(file: str, name: str) -> None:
    service = services(file)[name]
    assert 0 < int(service["pids_limit"]) <= 1024, name
    logging = service["logging"]
    assert logging["driver"] == "json-file", name
    assert logging["options"]["max-size"] and int(logging["options"]["max-file"]) >= 1, name


def test_the_expected_services_exist_in_compose() -> None:
    assert {"db", "auth-emulator", "api", "workers", "embeddings", "demo"} <= set(services())


@pytest.mark.parametrize("name", sorted(services("compose.itop.yaml")))
def test_itop_services_restart_and_drop_every_capability(name: str) -> None:
    service = services("compose.itop.yaml")[name]
    assert service["restart"] == "unless-stopped", name
    assert service["cap_drop"] == ["ALL"], name
    assert "cap_add" not in service, name
    assert "no-new-privileges:true" in service["security_opt"], name
    assert "healthcheck" in service, name


def test_itop_keeps_its_data_and_compiled_model_in_volumes() -> None:
    itop = services("compose.itop.yaml")
    mounts = {volume.split(":")[1] for volume in itop["itop"]["volumes"] if not volume.startswith(".")}
    assert {"/var/www/html/conf", "/var/www/html/data", "/var/www/html/env-production"} <= mounts
    assert "itop_db:/var/lib/mysql" in itop["itop-db"]["volumes"]
    # the cron container runs the same code, so it sees the same configuration, data and model
    assert set(itop["itop-cron"]["volumes"]) == set(itop["itop"]["volumes"])


def test_itop_passwords_travel_as_secret_files_never_as_values() -> None:
    itop = services("compose.itop.yaml")
    for name, service in itop.items():
        for key in service.get("environment") or {}:
            assert "PASSWORD" not in key or key.endswith("_FILE"), (name, key)
            assert "TOKEN" not in key or key.endswith("_FILE"), (name, key)
    assert {"itop_db_password", "itop_admin_password", "itop_webhook_token"} <= set(itop["itop"]["secrets"])
