"""F0 acceptance: `docker compose up` brings the whole stack up clean (docs/12 F0, docs/14 §4.2).

Slow and needs Docker: run with `uv run pytest -m e2e`.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from harness.isolation import free_port, run_name

pytestmark = [pytest.mark.e2e, pytest.mark.slow]

ROOT = Path(__file__).resolve().parents[3]
# Unique per run: other worktrees may run this weekly suite on the same Docker host (tests/harness/isolation.py).
PROJECT = run_name("hermes-e2e")
PORTS = {name: str(free_port()) for name in ("API_PORT", "AUTH_EMULATOR_PORT", "DB_PORT")}


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
    # reserved URL characters on purpose: the password must not need encoding
    env = {
        **os.environ,
        **PORTS,
        "CURSOR_SIGNING_KEY": secrets.token_urlsafe(32),
        "POSTGRES_PASSWORD": "p/w@" + secrets.token_urlsafe(12) + ":x",
        "MIGRATOR_DB_PASSWORD": secrets.token_urlsafe(16),
        "APP_DB_PASSWORD": "a@p/" + secrets.token_urlsafe(12),
        "RETENTION_DB_PASSWORD": secrets.token_urlsafe(16),
    }
    secrets_dir = tempfile.mkdtemp(prefix="hermes-e2e-secrets-")
    env["COMPOSE_SECRETS_DIR"] = secrets_dir
    written = subprocess.run(
        [shutil.which("bash") or "/bin/bash", str(ROOT / "docker" / "compose-secrets.sh")],
        env=env,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert written.returncode == 0, written.stderr
    up = compose(env, "up", "-d", "--build", "--wait", "--wait-timeout", "300")
    try:
        assert up.returncode == 0, up.stderr[-3000:]
        yield env
    finally:
        compose(env, "down", "-v", "--remove-orphans", "--rmi", "local", timeout=300)
        shutil.rmtree(secrets_dir, ignore_errors=True)


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
    ps = compose(stack, "ps", "--all", "--format", "json")
    services = {json.loads(line)["Service"]: json.loads(line)["State"] for line in ps.stdout.splitlines() if line}
    assert services == {
        "db": "running",
        "auth-emulator": "running",
        "provision": "exited",
        "migrate": "exited",
        "bootstrap": "exited",
        "api": "running",
        "workers": "running",
        "embeddings": "running",
    }


def test_migrations_ran_as_migrator(stack: dict[str, str]) -> None:
    query = "SELECT tableowner, count(*) FROM pg_tables WHERE schemaname = 'public' GROUP BY 1"
    out = compose(stack, "exec", "-T", "db", "psql", "-U", "hermes", "-d", "hermes", "-tAc", query)
    assert out.stdout.strip() == "migrator|77"  # 76 model tables + alembic_version


def test_factory_values_were_loaded_once_by_the_bootstrap(stack: dict[str, str]) -> None:
    query = "SELECT (SELECT count(*) FROM formula_version WHERE status = 'active'), (SELECT count(*) FROM source)"
    out = compose(stack, "exec", "-T", "db", "psql", "-U", "hermes", "-d", "hermes", "-tAc", query)
    active, sources = out.stdout.strip().split("|")
    assert active == "1" and int(sources) > 0
    again = compose(stack, "run", "--rm", "bootstrap")  # a second start changes nothing
    assert again.returncode == 0 and "already present" in again.stdout


def test_the_demo_profile_runs_one_full_cycle(stack: dict[str, str]) -> None:
    demo = compose(stack, "--profile", "demo", "run", "--rm", "demo")
    assert demo.returncode == 0, demo.stderr
    assert "demo ready" in demo.stdout and "2 assessment(s)" in demo.stdout
    query = (
        "SELECT (SELECT count(*) FROM ticket), (SELECT count(*) FROM itop_outbox), "
        "(SELECT count(*) FROM notification_event)"
    )
    out = compose(stack, "exec", "-T", "db", "psql", "-U", "hermes", "-d", "hermes", "-tAc", query)
    tickets, outbox, events = (int(n) for n in out.stdout.strip().split("|"))
    assert tickets >= 2 and outbox >= tickets and events >= tickets


def test_api_connects_as_the_app_role(stack: dict[str, str]) -> None:
    code = (
        "from core.config import Settings; from core.db.session import make_session_factory; "
        "from sqlalchemy import text; s = make_session_factory(Settings())(); "
        "print(s.execute(text('SELECT current_user')).scalar_one())"
    )
    out = compose(stack, "exec", "-T", "api", "python", "-c", code)
    assert out.stdout.strip() == "app", out.stderr[-2000:]


def test_api_runs_as_non_root(stack: dict[str, str]) -> None:
    whoami = compose(stack, "exec", "-T", "api", "id", "-u")
    assert whoami.stdout.strip() == "10001"


def test_provisioning_is_repeatable(stack: dict[str, str]) -> None:
    """Re-running provision on an already provisioned volume (e.g. one created before F0.6) succeeds."""
    rerun = compose(stack, "run", "--rm", "provision")
    assert rerun.returncode == 0, rerun.stderr[-2000:]
    assert "database provisioned" in rerun.stdout
