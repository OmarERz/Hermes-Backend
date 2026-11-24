"""docker/itop/secrets.sh writes the secret files of the persistent iTop (F16.1, D-042) and never replaces one."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]
PASSWORDS = ("ITOP_DB_ROOT_PASSWORD", "ITOP_DB_PASSWORD", "ITOP_ADMIN_PASSWORD")


def run(out: Path, exported: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k not in PASSWORDS}
    env |= {"COMPOSE_SECRETS_DIR": str(out), **(exported or {})}
    return subprocess.run(
        [shutil.which("bash") or "/bin/bash", str(ROOT / "docker" / "itop" / "secrets.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def test_generates_missing_passwords_once_and_keeps_them(tmp_path: Path) -> None:
    out = tmp_path / "out"
    first = run(out)
    assert first.returncode == 0, first.stderr
    values = {name: (out / name.lower()).read_text() for name in PASSWORDS}
    assert len(set(values.values())) == 3
    for value in values.values():
        assert value.startswith("Aa1-") and len(value) >= 24 and value.isprintable()
    assert "generated a random ITOP_ADMIN_PASSWORD" in first.stdout
    assert not any(value in first.stdout + first.stderr for value in values.values())  # never printed
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    assert stat.S_IMODE((out / "itop_admin_password").stat().st_mode) == 0o644

    again = run(out, {"ITOP_ADMIN_PASSWORD": "a-new-value"})
    assert again.returncode == 0, again.stderr
    assert {name: (out / name.lower()).read_text() for name in PASSWORDS} == values  # existing files win
    assert "generated" not in again.stdout


def test_an_exported_value_is_used_for_a_missing_file(tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = run(out, {"ITOP_ADMIN_PASSWORD": "Chosen-Passw0rd"})
    assert result.returncode == 0, result.stderr
    assert (out / "itop_admin_password").read_text() == "Chosen-Passw0rd"
    assert "ITOP_ADMIN_PASSWORD" not in result.stdout


def test_the_shared_webhook_token_is_created_empty_but_never_overwritten(tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = run(out)
    assert result.returncode == 0
    assert (out / "itop_webhook_token").read_text() == ""
    assert "itop_webhook_token is empty" in result.stderr
    (out / "itop_webhook_token").write_text("written-by-make-compose-secrets")
    assert run(out).returncode == 0
    assert (out / "itop_webhook_token").read_text() == "written-by-make-compose-secrets"


def test_refuses_an_output_directory_inside_the_repository() -> None:
    result = run(ROOT / "docker")
    assert result.returncode == 2
    assert "COMPOSE_SECRETS_DIR" in result.stderr
