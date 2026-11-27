"""The test containers of a run publish their ports on the loopback interface only (F18.5, nmap check).

Testcontainers publishes an exposed port on every interface (0.0.0.0 and ::): the throwaway database and the Auth
emulator of a run would answer on the WSL or LAN address while the tests run. `on_loopback` binds them to 127.0.0.1.
"""

from __future__ import annotations

import docker
import pytest

from harness.isolation import LABEL, LOOPBACK, RUN_ID

pytestmark = pytest.mark.integration


def test_the_database_and_the_emulator_listen_on_loopback_only(postgres_url: str, emulator_host: str) -> None:
    client = docker.from_env()
    try:
        mine = client.api.containers(filters={"label": f"{LABEL}.run={RUN_ID}"})
    finally:
        client.close()
    published = {
        (port["PrivatePort"], port.get("IP"))
        for container in mine
        for port in container.get("Ports") or []
        if port.get("PublicPort")
    }
    assert {private for private, _ in published} >= {5432, 9099}
    assert {address for _, address in published} == {LOOPBACK}
    assert postgres_url.split("@", 1)[1].startswith(f"{LOOPBACK}:")
    assert emulator_host.startswith(f"{LOOPBACK}:")
