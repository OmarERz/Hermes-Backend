"""docker/compose-secrets.sh writes one file per secret from the environment or the local env file (D-042)."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]
NAMES = (
    "POSTGRES_PASSWORD",
    "MIGRATOR_DB_PASSWORD",
    "APP_DB_PASSWORD",
    "RETENTION_DB_PASSWORD",
    "CURSOR_SIGNING_KEY",
    "ITOP_TOKEN",
)


def run(tmp_path: Path, env_file_text: str, exported: dict[str, str]) -> subprocess.CompletedProcess[str]:
    env_file = tmp_path / "local.env"
    env_file.write_text(env_file_text, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k not in NAMES}
    env |= {"ENV_FILE": str(env_file), "COMPOSE_SECRETS_DIR": str(tmp_path / "out"), **exported}
    return subprocess.run(
        [shutil.which("bash") or "/bin/bash", str(ROOT / "docker" / "compose-secrets.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def test_reads_the_env_file_without_executing_it(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    text = (
        'POSTGRES_PASSWORD="p w$(touch ' + str(marker) + ')"\n'
        "export MIGRATOR_DB_PASSWORD=m1\nAPP_DB_PASSWORD='a 2'\nRETENTION_DB_PASSWORD=r3\n"
        "CURSOR_SIGNING_KEY=c4\nITOP_TOKEN=\n"
    )
    result = run(tmp_path, text, {})
    assert result.returncode == 0, result.stderr
    out = tmp_path / "out"
    assert (out / "postgres_password").read_text() == "p w$(touch " + str(marker) + ")"
    assert (out / "migrator_db_password").read_text() == "m1"
    assert (out / "app_db_password").read_text() == "a 2"
    assert (out / "itop_token").read_text() == ""
    assert (out / "cursor_signing_key").read_text() == "c4"
    assert not marker.exists()
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    assert stat.S_IMODE((out / "app_db_password").stat().st_mode) == 0o644


def test_exported_values_win_over_the_file(tmp_path: Path) -> None:
    text = (
        "POSTGRES_PASSWORD=file\nMIGRATOR_DB_PASSWORD=m\nAPP_DB_PASSWORD=a\n"
        "RETENTION_DB_PASSWORD=r\nCURSOR_SIGNING_KEY=c\n"
    )
    result = run(tmp_path, text, {"POSTGRES_PASSWORD": "exported"})
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "out" / "postgres_password").read_text() == "exported"


def test_missing_cursor_signing_key_fails(tmp_path: Path) -> None:
    text = "POSTGRES_PASSWORD=p\nMIGRATOR_DB_PASSWORD=m\nAPP_DB_PASSWORD=a\nRETENTION_DB_PASSWORD=r\n"
    result = run(tmp_path, text, {})
    assert result.returncode == 2
    assert "CURSOR_SIGNING_KEY" in result.stderr


def test_missing_required_value_fails(tmp_path: Path) -> None:
    result = run(tmp_path, "POSTGRES_PASSWORD=x\n", {})
    assert result.returncode == 2
    assert "MIGRATOR_DB_PASSWORD" in result.stderr


def test_accepts_compose_env_file_syntax(tmp_path: Path) -> None:
    text = (
        "# comment line\n"
        "POSTGRES_PASSWORD = spaced  # trailing comment\n"
        'MIGRATOR_DB_PASSWORD="quoted # not a comment"\n'
        "APP_DB_PASSWORD='single'\n"
        "RETENTION_DB_PASSWORD=r3\n"
        "CURSOR_SIGNING_KEY=c4\n"
    )
    result = run(tmp_path, text, {})
    assert result.returncode == 0, result.stderr
    out = tmp_path / "out"
    assert (out / "postgres_password").read_text() == "spaced"
    assert (out / "migrator_db_password").read_text() == "quoted # not a comment"
    assert (out / "app_db_password").read_text() == "single"


def test_refuses_an_output_dir_inside_the_repo(tmp_path: Path) -> None:
    env = {k: v for k, v in os.environ.items() if k not in NAMES}
    env |= dict.fromkeys(NAMES[:4], "x") | {"COMPOSE_SECRETS_DIR": str(ROOT / "tests" / "leak-probe")}
    result = subprocess.run(
        [shutil.which("bash") or "/bin/bash", str(ROOT / "docker" / "compose-secrets.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    shutil.rmtree(ROOT / "tests" / "leak-probe", ignore_errors=True)
    assert result.returncode == 2
    assert "outside the repository" in result.stderr
