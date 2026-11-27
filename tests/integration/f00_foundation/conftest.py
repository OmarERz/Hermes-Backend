"""One Firebase Auth emulator for the f00 tests, built under a tag of this run only (tests/harness/isolation.py)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from testcontainers.core.container import DockerContainer
from testcontainers.core.wait_strategies import LogMessageWaitStrategy

from harness.isolation import LABELS, LOOPBACK, ROOT, built_image, on_loopback


@pytest.fixture(scope="session")
def emulator_host() -> Iterator[str]:
    """host:port of a private emulator container on the loopback interface; its image tag is unique to this run and
    removed by tag only."""
    with built_image(ROOT / "docker" / "auth-emulator", "hermes-test-auth-emulator") as tag:
        container = on_loopback(
            DockerContainer(tag, labels=LABELS)
            .with_exposed_ports(9099)
            .waiting_for(LogMessageWaitStrategy("All emulators ready").with_startup_timeout(180))
        )
        with container:
            yield f"{LOOPBACK}:{container.get_exposed_port(9099)}"
