"""Docker resources of a test run that never collide with, nor outlive, other runs on the same Docker host.

Several worktrees and agents run `make verify` on one Docker daemon. Every image tag, Compose project and published
port a test creates is unique to this run (the repository path hash, the process id and a random suffix), and every
container and image carries labels naming the run and its process:

* teardown untags only this run's tag, never an image by id (two runs that build the same Dockerfile share the image
  id through the build cache, and removing it by id with force breaks the other run's container: Docker 409);
* a SIGTERM (a `timeout`, an agent stopping a command) unwinds pytest like Ctrl-C, so the fixtures stop their
  containers; Ryuk stays off (tests/integration/conftest.py explains why);
* a run killed outright (SIGKILL) cannot clean up: the next run on this host removes the containers and tags whose
  process is gone (`sweep_dead_runs`), and leaves everything of a live run alone.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import secrets
import signal
import socket
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import FrameType
from typing import Final

import docker
from docker.errors import APIError, DockerException, NotFound

ROOT = Path(__file__).resolve().parents[2]
RUN_ID = f"{hashlib.sha256(str(ROOT).encode()).hexdigest()[:8]}-{os.getpid()}-{secrets.token_hex(3)}"
LABEL: Final = "dev.hermes.test"
HOST: Final = socket.gethostname()
LABELS: Final = {LABEL: "1", f"{LABEL}.run": RUN_ID, f"{LABEL}.pid": str(os.getpid()), f"{LABEL}.host": HOST}


def run_name(prefix: str) -> str:
    """A Docker-safe name unique to this run (image repository, Compose project)."""
    return f"{prefix}-{RUN_ID}".lower()


def free_port() -> int:
    """A local TCP port that was free a moment ago, for a Compose stack that publishes ports."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@contextmanager
def built_image(context: Path, prefix: str) -> Iterator[str]:
    """Build `context` under a tag of this run; on exit untag only that tag (layers shared with others stay)."""
    client = docker.from_env()
    tag = f"{run_name(prefix)}:test"
    try:
        client.images.build(path=str(context), tag=tag, rm=True, forcerm=True, labels=LABELS)
        yield tag
    finally:
        untag(client, tag)
        client.close()


def untag(client: docker.DockerClient, tag: str) -> None:
    """`docker rmi <tag>` without force: gone already, or still used by a running container, it is left alone."""
    with contextlib.suppress(NotFound, APIError):
        client.images.remove(image=tag, force=False, noprune=True)


def _alive(pid: str) -> bool:
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except (PermissionError, ValueError):
        return True  # another user's process, or a label we cannot read: never touch it
    return True


def sweep_dead_runs(client: docker.DockerClient, alive: Callable[[str], bool] = _alive) -> list[str]:
    """Remove the containers and tags left by test runs of this host whose process is gone. Returns what it removed."""
    removed: list[str] = []
    owned = {"label": [f"{LABEL}=1", f"{LABEL}.host={HOST}"]}
    for container in client.containers.list(all=True, filters=owned):
        if not alive(container.labels.get(f"{LABEL}.pid", "")):
            with contextlib.suppress(NotFound, APIError):
                container.remove(force=True)
                removed.append(container.name)
    for image in client.images.list(filters=owned):
        if not alive(image.labels.get(f"{LABEL}.pid", "")):
            for tag in image.tags:
                untag(client, tag)
                removed.append(tag)
    return removed


@contextmanager
def cleanup_on_sigterm() -> Iterator[None]:
    """Turn SIGTERM into KeyboardInterrupt while the run lasts: pytest then tears down its fixtures."""

    def interrupt(_signum: int, _frame: FrameType | None) -> None:
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, interrupt)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


@contextmanager
def isolated_run() -> Iterator[None]:
    """Session guard for the integration tests: clean what dead runs left, then trap SIGTERM for this one."""
    with contextlib.suppress(DockerException):
        client = docker.from_env()
        try:
            sweep_dead_runs(client)
        finally:
            client.close()
    with cleanup_on_sigterm():
        yield
