"""Real Firebase project mode (D-087): compose.firebase.yaml moves the API from the Auth emulator to the real project.

The default stack (compose.yaml alone) keeps the emulator; the override mounts the service account as a Docker secret
into the API only, points FIREBASE_CREDENTIALS_FILE at it, empties FIREBASE_AUTH_EMULATOR_HOST and refuses to start
without the project and the file. `docker compose config` checks the merge the way Compose does it (no daemon, no
network); a placeholder JSON stands in for the service account.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]
MOUNT_NAME = "firebase_service_account"
MOUNTED = f"/run/secrets/{MOUNT_NAME}"
DOCKER = shutil.which("docker")
needs_docker = pytest.mark.skipif(DOCKER is None, reason="docker CLI not installed")


def compose_config(tmp_path: Path, *files: str, **env: str) -> subprocess.CompletedProcess[str]:
    assert DOCKER is not None
    clean = {k: v for k, v in os.environ.items() if not k.startswith(("FIREBASE_", "COMPOSE_"))}
    args = [DOCKER, "compose", "--env-file", os.devnull, "--project-name", "hermes-config-test"]
    for name in files:
        args += ["-f", str(ROOT / name)]
    return subprocess.run(  # noqa: S603 - fixed docker compose arguments, no shell, no external input
        [*args, "config", "--format", "json"],
        env={**clean, "COMPOSE_SECRETS_DIR": str(tmp_path), **env},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def merged(tmp_path: Path) -> dict[str, Any]:
    placeholder = tmp_path / "service-account.json"
    placeholder.write_text("{}", encoding="utf-8")
    result = compose_config(
        tmp_path,
        "compose.yaml",
        "compose.firebase.yaml",
        FIREBASE_SERVICE_ACCOUNT_FILE=str(placeholder),
        FIREBASE_PROJECT_ID="hermes-real-test",
    )
    assert result.returncode == 0, result.stderr
    document: dict[str, Any] = json.loads(result.stdout)
    return document


def secret_sources(service: dict[str, Any]) -> set[str]:
    return {entry["source"] for entry in service.get("secrets", [])}


def test_the_override_names_no_default_file_and_no_default_project() -> None:
    override = yaml.safe_load((ROOT / "compose.firebase.yaml").read_text(encoding="utf-8"))
    assert override["secrets"][MOUNT_NAME]["file"].startswith("${FIREBASE_SERVICE_ACCOUNT_FILE:?")
    assert override["services"]["api"]["environment"]["FIREBASE_PROJECT_ID"].startswith("${FIREBASE_PROJECT_ID:?")


@needs_docker
def test_the_default_stack_keeps_the_emulator_and_mounts_no_service_account(tmp_path: Path) -> None:
    result = compose_config(tmp_path, "compose.yaml")
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert MOUNT_NAME not in document.get("secrets", {})
    for name in ("api", "workers"):
        environment = document["services"][name]["environment"]
        assert environment["FIREBASE_AUTH_EMULATOR_HOST"] == "auth-emulator:9099"
        assert environment["FIREBASE_PROJECT_ID"] == "demo-hermes"
        assert MOUNT_NAME not in secret_sources(document["services"][name])


@needs_docker
def test_real_mode_mounts_the_service_account_into_the_api_only(tmp_path: Path) -> None:
    document = merged(tmp_path)
    api, workers = document["services"]["api"], document["services"]["workers"]
    assert document["secrets"][MOUNT_NAME]["file"] == str(tmp_path / "service-account.json")
    assert MOUNT_NAME in secret_sources(api)
    assert "app_db_password" in secret_sources(api)  # the base secrets are kept, not replaced
    assert MOUNT_NAME not in secret_sources(workers)
    assert api["environment"]["FIREBASE_CREDENTIALS_FILE"] == MOUNTED
    assert api["environment"]["FIREBASE_PROJECT_ID"] == "hermes-real-test"
    for service in (api, workers):
        assert service["environment"]["FIREBASE_AUTH_EMULATOR_HOST"] == ""


@needs_docker
@pytest.mark.parametrize("missing", ["FIREBASE_SERVICE_ACCOUNT_FILE", "FIREBASE_PROJECT_ID"])
def test_real_mode_refuses_to_start_without_the_file_or_the_project(tmp_path: Path, missing: str) -> None:
    placeholder = tmp_path / "service-account.json"
    placeholder.write_text("{}", encoding="utf-8")
    env = {"FIREBASE_SERVICE_ACCOUNT_FILE": str(placeholder), "FIREBASE_PROJECT_ID": "hermes-real-test"}
    del env[missing]
    result = compose_config(tmp_path, "compose.yaml", "compose.firebase.yaml", **env)
    assert result.returncode != 0
    assert f"required variable {missing} is missing a value" in result.stderr


def test_the_real_project_block_of_the_env_example_comes_after_the_values_it_overrides() -> None:
    # A repeated variable keeps its last value (compose and python-dotenv alike): uncommenting the block must win.
    lines = (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
    for name, real in (("CORS_ALLOWED_ORIGINS", "http://localhost:4200"), ("FIREBASE_PROJECT_ID", "hermes-pass-sec")):
        default = max(i for i, line in enumerate(lines) if line.startswith(f"{name}="))
        override = lines.index(f"# {name}={real}")
        assert override > default, name
