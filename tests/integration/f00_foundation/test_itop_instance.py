"""F0.7 acceptance: the iTop 3.2.2 test instance installs unattended and serves REST with the least-privilege token.

Slow and needs Docker (several minutes the first time: it builds the image): run with `uv run pytest -m e2e`.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest

from harness import itop_seed
from harness.isolation import free_port, run_name

pytestmark = [pytest.mark.e2e, pytest.mark.slow]

ROOT = Path(__file__).resolve().parents[3]
# Unique per run: other worktrees may run this weekly suite on the same Docker host (tests/harness/isolation.py).
PROJECT = run_name("hermes-itop-e2e")
PORT = str(free_port())
REST = f"http://127.0.0.1:{PORT}/webservices/rest.php"


def compose(env: dict[str, str], *args: str, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    docker = shutil.which("docker")
    assert docker, "docker is required"
    return subprocess.run(
        [docker, "compose", "-p", PROJECT, "-f", "compose.itop.yaml", "--profile", "itop", *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def read_token(env: dict[str, str], name: str) -> str:
    done = compose(env, "exec", "-T", "itop", "cat", f"/var/www/html/data/{name}")
    assert done.returncode == 0, done.stderr[-1000:]
    return done.stdout.strip()


def rest(token: str, operation: dict[str, Any]) -> dict[str, Any]:
    response = httpx.post(
        REST,
        params={"version": "1.3"},
        headers={"Auth-Token": token},
        data={"json_data": json.dumps(operation)},
        timeout=30,
    )
    body: dict[str, Any] = response.json()
    return body


class Receiver(BaseHTTPRequestHandler):
    """Stands in for the backend webhook route: records what iTop POSTs."""

    received: ClassVar[list[tuple[str, str, bytes]]] = []

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        Receiver.received.append((self.path, self.headers.get("Authorization", ""), body))
        self.send_response(200)
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Keep the test output quiet."""


@pytest.fixture(scope="module")
def webhook_receiver() -> Iterator[str]:
    # Reachable from the container through host.docker.internal, so it cannot be bound to loopback only;
    # it lives for the duration of the test module and only records what it receives.
    server = HTTPServer(("", 0), Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://host.docker.internal:{server.server_port}/api/itop/webhook"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(scope="module")
def instance(webhook_receiver: str) -> Iterator[dict[str, str]]:
    env = {
        **os.environ,
        "ITOP_WEBHOOK_URL": webhook_receiver,
        "ITOP_WEBHOOK_TOKEN": "webhook-test-secret",
        "ITOP_PORT": PORT,
        "ITOP_DB_ROOT_PASSWORD": secrets.token_urlsafe(16),
        "ITOP_DB_PASSWORD": secrets.token_urlsafe(16),
        "ITOP_ADMIN_PASSWORD": "Aa1-" + secrets.token_urlsafe(16),
    }
    try:
        up = compose(env, "up", "-d", "--build", "--wait", "--wait-timeout", "300")
        assert up.returncode == 0, up.stderr[-3000:]
        install = compose(env, "exec", "-T", "-u", "www-data", "itop", "/opt/hermes-itop/install.sh")
        assert install.returncode == 0, install.stdout[-2000:] + install.stderr[-2000:]
        yield env
    finally:
        compose(env, "down", "-v", "--remove-orphans", "--rmi", "local", timeout=300)


def test_seed_then_read_with_the_rest_user(instance: dict[str, str]) -> None:
    seed = itop_seed.ItopRest(f"http://127.0.0.1:{PORT}", read_token(instance, "hermes-seed-token"))
    assert itop_seed.run([str(ROOT / "docker" / "itop" / "stack.yaml"), "--apply"], itop=seed) == 0

    token = read_token(instance, "hermes-rest-token")
    assert rest(token, {"operation": "list_operations"})["code"] == 0

    found = rest(
        token,
        {
            "operation": "core/get",
            "class": "FunctionalCI",
            "key": "SELECT FunctionalCI WHERE internet_exposed = 'yes'",
            "output_fields": "name,confidentiality,personal_data,owner_id,custodian_id",
        },
    )
    assert found["code"] == 0
    names = {o["fields"]["name"] for o in found["objects"].values()}
    assert names == {"web-frontend-01", "web-frontend-02"}
    web = next(o["fields"] for o in found["objects"].values() if o["fields"]["name"] == "web-frontend-01")
    assert web["confidentiality"] == "public"
    assert web["owner_id"] and web["custodian_id"]


def test_rest_user_has_least_privilege(instance: dict[str, str]) -> None:
    token = read_token(instance, "hermes-rest-token")
    denied = rest(token, {"operation": "core/create", "class": "Server", "fields": {"name": "x"}, "comment": "t"})
    assert denied["code"] != 0
    assert rest("not-a-token", {"operation": "list_operations"})["code"] == 1


def test_sample_ticket_can_be_assigned_and_resolved(instance: dict[str, str]) -> None:
    # The least-privilege backend user can read, assign and resolve the sample ticket (service_id is already set)
    token = read_token(instance, "hermes-rest-token")
    key = "SELECT UserRequest WHERE title LIKE 'CVE-2026-0001%'"
    ticket = rest(
        token, {"operation": "core/get", "class": "UserRequest", "key": key, "output_fields": "status,agent_id"}
    )
    ((object_key, found),) = [(o["key"], o["fields"]) for o in ticket["objects"].values()]
    assert found["status"] == "new"
    key = int(object_key)  # stimuli on a single id: an OQL key counts as a bulk operation, which the profile lacks
    assigned = rest(
        token,
        {
            "operation": "core/apply_stimulus",
            "class": "UserRequest",
            "key": key,
            "stimulus": "ev_assign",
            "fields": {
                "team_id": "SELECT Team WHERE name = 'Platform Ops'",
                "agent_id": "SELECT Person WHERE name = 'Rivera'",
            },
            "comment": "test",
        },
    )
    assert assigned["code"] == 0, assigned
    resolved = rest(
        token,
        {
            "operation": "core/apply_stimulus",
            "class": "UserRequest",
            "key": key,
            "stimulus": "ev_resolve",
            "fields": {"resolution_code": "software patch", "solution": "patched"},
            "comment": "test",
        },
    )
    assert resolved["code"] == 0, resolved


def test_updating_a_ticket_rings_the_webhook(instance: dict[str, str]) -> None:
    token = read_token(instance, "hermes-rest-token")
    ticket = rest(
        token, {"operation": "core/get", "class": "UserRequest", "key": "SELECT UserRequest", "output_fields": "ref"}
    )
    ((key, found),) = [(o["key"], o["fields"]) for o in ticket["objects"].values()]
    updated = rest(
        token,
        {
            "operation": "core/update",
            "class": "UserRequest",
            "key": int(key),
            "fields": {"title": "changed"},
            "comment": "t",
        },
    )
    assert updated["code"] == 0, updated
    deadline = time.monotonic() + 15
    while not Receiver.received and time.monotonic() < deadline:
        time.sleep(0.5)
    assert Receiver.received, "iTop did not call the webhook"
    path, authorization, body = Receiver.received[-1]
    assert path == "/api/itop/webhook"
    assert authorization == "Bearer webhook-test-secret"
    assert json.loads(body) == {"class": "UserRequest", "id": key, "ref": found["ref"]}
