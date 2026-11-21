"""F0 acceptance: `docker compose up` brings the whole stack up clean (docs/12 F0, docs/14 §4.2).

Slow and needs Docker: run with `uv run pytest -m e2e`.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.slow]

ROOT = Path(__file__).resolve().parents[3]
PROJECT = "hermes-e2e"
PORTS = {"API_PORT": "18000", "AUTH_EMULATOR_PORT": "19099", "DB_PORT": "15432"}


def compose(env: dict[str, str], *args: str, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    docker = shutil.which("docker")
    assert docker, "docker is required"
    return subprocess.run(
        [docker, "compose", "-p", PROJECT, *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


@pytest.fixture(scope="module")
def stack() -> Iterator[dict[str, str]]:
    env = {**os.environ, **PORTS, "POSTGRES_PASSWORD": secrets.token_urlsafe(16)}
    up = compose(env, "up", "-d", "--build", "--wait", "--wait-timeout", "300")
    try:
        assert up.returncode == 0, up.stderr[-3000:]
        yield env
    finally:
        compose(env, "down", "-v", "--remove-orphans", timeout=300)


def get(url: str) -> tuple[int, bytes]:
    response = httpx.get(url, timeout=5)
    return response.status_code, response.content


def test_api_health(stack: dict[str, str]) -> None:
    status, body = get(f"http://127.0.0.1:{PORTS['API_PORT']}/api/health")
    assert status == 200
    assert json.loads(body) == {"status": "ok"}


def test_auth_emulator_answers(stack: dict[str, str]) -> None:
    status, _ = get(f"http://127.0.0.1:{PORTS['AUTH_EMULATOR_PORT']}/")
    assert status == 200


def test_all_services_running(stack: dict[str, str]) -> None:
    ps = compose(stack, "ps", "--format", "json")
    services = {json.loads(line)["Service"]: json.loads(line)["State"] for line in ps.stdout.splitlines() if line}
    assert services == {"db": "running", "auth-emulator": "running", "api": "running", "workers": "running"}


def test_api_runs_as_non_root(stack: dict[str, str]) -> None:
    whoami = compose(stack, "exec", "-T", "api", "id", "-u")
    assert whoami.stdout.strip() == "10001"
