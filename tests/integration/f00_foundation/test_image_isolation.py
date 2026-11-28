"""Docker resources per test run: own tags only, and what a dead run left is swept (tests/harness/isolation.py)."""

from __future__ import annotations

import contextlib
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import docker
import pytest

from harness.isolation import COMPOSE_PROJECT, LABEL, LABELS, RUN_ID, built_image, run_name, sweep_dead_runs

pytestmark = pytest.mark.integration
# The backend base image, pinned by digest: already on the host for the backend and emulator builds.
BASE = "python:3.12.16-slim-bookworm@sha256:44cf1793efa7c7a476bb0f2cff81443f4a072c90c1cb127e2924933daa3e8c64"


@pytest.fixture
def client() -> Iterator[docker.DockerClient]:
    docker_client = docker.from_env()
    try:
        yield docker_client
    finally:
        docker_client.close()


def dead_pid() -> str:
    """The pid of a child that already exited: no process owns it any more."""
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait()
    return str(child.pid)


def test_a_run_removes_only_its_own_tag(tmp_path: Path, client: docker.DockerClient) -> None:
    (tmp_path / "Dockerfile").write_text(f'FROM {BASE}\nCMD ["true"]\n', encoding="utf-8")
    with built_image(tmp_path, "hermes-test-isolation-a") as first:
        with built_image(tmp_path, "hermes-test-isolation-b") as second:
            assert client.images.get(first).id == client.images.get(second).id  # same content, same id
        assert client.images.get(first).id  # the other run's tag and image survive
    with pytest.raises(docker.errors.ImageNotFound):
        client.images.get(first)


def test_the_sweep_removes_what_a_dead_run_left_and_keeps_live_runs(
    tmp_path: Path, client: docker.DockerClient
) -> None:
    # The planted run's pid is a marker that no other test session of this host reads as a dead pid (an unreadable
    # label counts as alive), so their session-start sweeps leave it alone; this sweep is told the marker is dead.
    # A real dead pid raced with the other lanes' sweeps, which could remove the orphan first.
    marker = f"planted-dead-{RUN_ID}"
    dead = {**LABELS, f"{LABEL}.pid": marker}
    orphan = client.containers.create(BASE, ["true"], labels=dead)
    mine = client.containers.create(BASE, ["true"], labels=LABELS)
    (tmp_path / "Dockerfile").write_text(f"FROM {BASE}\n", encoding="utf-8")
    left_tag = f"hermes-test-isolation-dead-{RUN_ID.split('-')[0]}:test"
    client.images.build(path=str(tmp_path), tag=left_tag, labels=dead)
    try:
        removed = sweep_dead_runs(client, alive=lambda pid: pid != marker)
        assert orphan.name in removed
        assert left_tag in removed
        assert mine.name not in removed
        with pytest.raises(docker.errors.NotFound):
            client.containers.get(orphan.id)
        with pytest.raises(docker.errors.ImageNotFound):
            client.images.get(left_tag)
        assert client.containers.get(mine.id).id == mine.id
    finally:
        for leftover in (orphan, mine):
            with contextlib.suppress(docker.errors.NotFound):
                leftover.remove(force=True)


def test_the_sweep_removes_the_compose_stack_of_a_dead_e2e_run(client: docker.DockerClient) -> None:
    project = f"hermes-e2e-{RUN_ID.split('-')[0]}-{dead_pid()}-abcdef"
    live = run_name("hermes-e2e")  # this run's own stack name: never swept while the run lives
    scope = {COMPOSE_PROJECT: project}
    network = client.networks.create(f"{project}_default", labels=scope)
    volume = client.volumes.create(f"{project}_data", labels=scope)
    orphan = client.containers.create(BASE, ["true"], labels=scope)
    mine = client.containers.create(BASE, ["true"], labels={COMPOSE_PROJECT: live})
    try:
        removed = sweep_dead_runs(client)
        assert project in removed
        assert live not in removed
        for gone in (lambda: client.containers.get(orphan.id), lambda: client.networks.get(network.id)):
            with pytest.raises(docker.errors.NotFound):
                gone()
        with pytest.raises(docker.errors.NotFound):
            client.volumes.get(volume.id)
        assert client.containers.get(mine.id).id == mine.id
    finally:
        for leftover in (orphan, mine):
            with contextlib.suppress(docker.errors.NotFound):
                leftover.remove(force=True)
        for resource in (network, volume):
            with contextlib.suppress(docker.errors.NotFound):
                resource.remove()
