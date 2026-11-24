"""F0.7 and F16.1 acceptance: the persistent iTop 3.2.2 installs unattended, serves REST with the least-privilege token,
shows the Hermes attributes in its console, runs its cron and keeps data and compiled model when recreated.

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
PROVISION = "/opt/hermes-itop/provision.php"


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


def www_data(env: dict[str, str], *command: str) -> str:
    done = compose(env, "exec", "-T", "-u", "www-data", "itop", *command)
    assert done.returncode == 0, done.stdout[-2000:] + done.stderr[-2000:]
    return done.stdout


def read_token(env: dict[str, str], name: str) -> str:
    return www_data(env, "cat", f"/var/www/html/data/{name}").strip()


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
def instance(webhook_receiver: str, tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, str]]:
    # The secret files compose.itop.yaml mounts, in a private directory of this run (make itop-secrets writes the
    # real ones); the webhook token is a fixed test value the receiver checks.
    secret_dir = tmp_path_factory.mktemp("itop-secrets")
    for name in ("itop_db_root_password", "itop_db_password", "itop_admin_password"):
        (secret_dir / name).write_text("Aa1-" + secrets.token_urlsafe(16))
    (secret_dir / "itop_webhook_token").write_text("webhook-test-secret")
    env = {
        **os.environ,
        "COMPOSE_SECRETS_DIR": str(secret_dir),
        "ITOP_WEBHOOK_URL": webhook_receiver,
        "ITOP_PORT": PORT,
    }
    try:
        up = compose(env, "up", "-d", "--build", "--wait", "--wait-timeout", "300")
        assert up.returncode == 0, up.stderr[-3000:]
        install = compose(env, "exec", "-T", "-u", "www-data", "itop", "/opt/hermes-itop/install.sh")
        assert install.returncode == 0, install.stdout[-2000:] + install.stderr[-2000:]
        www_data(env, "php", PROVISION, "seed-user", "on")
        seed = itop_seed.ItopRest(f"http://127.0.0.1:{PORT}", read_token(env, "hermes-seed-token"))
        assert itop_seed.run([str(ROOT / "docker" / "itop" / "stack.yaml"), "--apply"], itop=seed) == 0
        yield env
    finally:
        # The image stays: its tag is shared with a persistent iTop that may run on the same host.
        compose(env, "down", "-v", "--remove-orphans", timeout=300)


def test_read_the_seeded_stack_with_the_rest_user(instance: dict[str, str]) -> None:
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


def test_the_seed_token_only_works_while_the_seed_user_is_on(instance: dict[str, str]) -> None:
    www_data(instance, "php", PROVISION, "seed-user", "on")
    token = read_token(instance, "hermes-seed-token")
    assert rest(token, {"operation": "list_operations"})["code"] == 0
    www_data(instance, "php", PROVISION, "seed-user", "off")
    assert "hermes-seed-token" not in www_data(instance, "ls", "/var/www/html/data")
    refused = httpx.post(REST, params={"version": "1.3"}, headers={"Auth-Token": token},
                         data={"json_data": json.dumps({"operation": "list_operations"})}, timeout=30)  # fmt: skip
    # a disabled user gets the login page or an error, never a successful REST answer
    assert '"code":0' not in refused.text.replace(" ", "")


def test_people_assign_and_resolve_and_the_backend_reopens(instance: dict[str, str]) -> None:
    # Assigning and resolving are people's work in the console (an administrator here); the backend may only reopen.
    token = read_token(instance, "hermes-rest-token")
    key_oql = "SELECT UserRequest WHERE title LIKE 'CVE-2026-0001%'"
    ticket = rest(
        token, {"operation": "core/get", "class": "UserRequest", "key": key_oql, "output_fields": "status,agent_id"}
    )
    ((object_key, found),) = [(o["key"], o["fields"]) for o in ticket["objects"].values()]
    assert found["status"] == "new"
    key = int(object_key)  # stimuli on a single id: an OQL key counts as a bulk operation, which the profile lacks
    assign = {"team_id": "SELECT Team WHERE name = 'Platform Ops'", "agent_id": "SELECT Person WHERE name = 'Rivera'"}

    def stimulus(as_token: str, name: str, fields: dict[str, str] | None = None) -> dict[str, Any]:
        operation = {"operation": "core/apply_stimulus", "class": "UserRequest", "key": key, "stimulus": name}
        return rest(as_token, {**operation, "fields": fields or {}, "comment": "test"})

    # The profile grants the backend only ev_reopen. iTop enforces stimulus grants in the console; its REST
    # core/apply_stimulus checks only modify and bulk modify on the class, so over REST the outbox's own allowlist
    # (core.itop.outbox.STIMULI) is what keeps the backend to ev_reopen.
    script = (
        'require "/var/www/html/approot.inc.php"; require APPROOT."/application/startup.inc.php";'
        'UserRights::Login("hermes-rest"); foreach (["ev_assign", "ev_resolve", "ev_reopen"] as $s) {'
        'echo $s, "=", UserRights::IsStimulusAllowed("UserRequest", $s) ? "yes" : "no", " "; }'
    )
    assert www_data(instance, "php", "-r", script).split() == ["ev_assign=no", "ev_resolve=no", "ev_reopen=yes"]

    www_data(instance, "php", PROVISION, "seed-user", "on")
    admin = read_token(instance, "hermes-seed-token")
    try:
        assert stimulus(admin, "ev_assign", assign)["code"] == 0
        resolution = {"resolution_code": "software patch", "solution": "patched"}
        assert stimulus(admin, "ev_resolve", resolution)["code"] == 0
    finally:
        www_data(instance, "php", PROVISION, "seed-user", "off")

    reopened = stimulus(token, "ev_reopen")
    assert reopened["code"] == 0, reopened
    status = rest(token, {"operation": "core/get", "class": "UserRequest", "key": key, "output_fields": "status"})
    assert next(iter(status["objects"].values()))["fields"]["status"] == "assigned"


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


def test_the_console_shows_the_hermes_attributes_in_spanish(instance: dict[str, str]) -> None:
    script = (
        'require "/var/www/html/approot.inc.php"; require APPROOT."/application/startup.inc.php";'
        'Dict::SetUserLanguage("ES CR");'
        '$z = MetaModel::FlattenZList(MetaModel::GetZListItems("Server", "details"));'
        'echo json_encode(["fields" => array_values(array_intersect($z, ["internet_exposed", "confidentiality",'
        '"personal_data", "owner_id", "custodian_id"])), "block" => Dict::S("Hermes:security"),'
        '"label" => MetaModel::GetLabel("Server", "custodian_id")]);'
    )
    shown = json.loads(www_data(instance, "php", "-r", script))
    assert shown == {
        "fields": ["internet_exposed", "confidentiality", "personal_data", "owner_id", "custodian_id"],
        "block": "Seguridad (Hermes)",
        "label": "Equipo custodio",
    }


def test_the_cron_logs_in_with_its_param_file(instance: dict[str, str]) -> None:
    done = compose(
        instance,
        "exec", "-T", "itop-cron", "php", "/var/www/html/webservices/cron.php",
        "--param_file=/var/www/html/data/hermes-cron.params", "--status_only=1",
    )  # fmt: skip
    assert done.returncode == 0, done.stdout[-2000:]
    assert "Task Class" in done.stdout  # logged in as hermes-cron (an administrator); wrong credentials exit 1


def test_recreated_containers_keep_the_data_and_the_compiled_model(instance: dict[str, str]) -> None:
    recreated = compose(instance, "up", "-d", "--force-recreate", "--wait", "--wait-timeout", "300")
    assert recreated.returncode == 0, recreated.stderr[-3000:]
    assert "its model is up to date" in www_data(instance, "/opt/hermes-itop/install.sh")
    token = read_token(instance, "hermes-rest-token")
    found = rest(token, {"operation": "core/get", "class": "Server", "key": "SELECT Server", "output_fields": "name"})
    assert found["code"] == 0
    assert {o["fields"]["name"] for o in found["objects"].values()} >= {"web-frontend-01", "db-host-01"}
