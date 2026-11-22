"""The emulator token CLI against the real Firebase Auth emulator image (docker/auth-emulator, D-069)."""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from testcontainers.core.container import DockerContainer
from testcontainers.core.image import DockerImage
from testcontainers.core.wait_strategies import LogMessageWaitStrategy

from core.devtools import emulator

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def emulator_host() -> Iterator[str]:
    with DockerImage(path=str(ROOT / "docker" / "auth-emulator"), tag="hermes-auth-emulator-test") as image:
        container = (
            DockerContainer(str(image))
            .with_exposed_ports(9099)
            .waiting_for(LogMessageWaitStrategy("All emulators ready").with_startup_timeout(180))
        )
        with container:
            yield f"{container.get_container_host_ip()}:{container.get_exposed_port(9099)}"


def payload(token: str) -> dict[str, object]:
    # emulator tokens are unsigned: decode the payload only
    segment = token.split(".")[1]
    claims: dict[str, object] = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    return claims


@pytest.mark.parametrize("role", emulator.ROLES)
def test_token_carries_role_and_project(
    emulator_host: str, role: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("FIREBASE_AUTH_EMULATOR_HOST", emulator_host)
    monkeypatch.setenv("FIREBASE_PROJECT_ID", "demo-hermes")
    for _ in range(2):  # the second run reuses the user
        assert emulator.main(["token", "--role", role]) == 0
        claims = payload(capsys.readouterr().out.strip())
        assert claims["role"] == role
        assert claims["aud"] == "demo-hermes"
