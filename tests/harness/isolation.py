"""Docker resources of a test run that never collide with, nor outlive, other runs on the same Docker host.

Several worktrees and agents run `make verify` on one Docker daemon. Every image tag, Compose project and published
port a test creates is unique to this run (the repository path hash, the process id and a random suffix), and every
container and image carries labels naming the run and its process:

* teardown untags only this run's tag, never an image by id (two runs that build the same Dockerfile share the image
  id through the build cache, and removing it by id with force breaks the other run's container: Docker 409);
* a SIGTERM (a `timeout`, an agent stopping a command) unwinds pytest like Ctrl-C, so the fixtures stop their
  containers; Ryuk stays off (tests/integration/conftest.py explains why);
* a run killed outright (SIGKILL) cannot clean up: the next run on this host removes the containers and tags whose
  process is gone (`sweep_dead_runs`), and leaves everything of a live run alone. Compose stacks of the e2e tests
  are found by their project name (`run_name`, which carries the pid) and removed with their networks, volumes and
  built images;
* a container publishes its ports on the loopback interface only (`on_loopback`), like the Compose files do: a test
  database or emulator never answers on the WSL or LAN address while the tests run.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import secrets
import signal
import socket
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import FrameType
from typing import Any, Final

import docker
from docker.errors import APIError, DockerException, NotFound
from testcontainers.core.container import DockerContainer

ROOT = Path(__file__).resolve().parents[2]
RUN_ID = f"{hashlib.sha256(str(ROOT).encode()).hexdigest()[:8]}-{os.getpid()}-{secrets.token_hex(3)}"
LABEL: Final = "dev.hermes.test"
HOST: Final = socket.gethostname()
LABELS: Final = {LABEL: "1", f"{LABEL}.run": RUN_ID, f"{LABEL}.pid": str(os.getpid()), f"{LABEL}.host": HOST}
COMPOSE_PROJECT: Final = "com.docker.compose.project"
PORT_RANGE: Final = (20000, 39999)  # published test ports: below the 49152+ ranges Windows may reserve (WSL)
LOOPBACK: Final = "127.0.0.1"  # the only host address a test container publishes on
# A Compose project of the e2e tests: run_name("hermes-...e2e") = prefix-<repo hash>-<pid>-<random>
E2E_PROJECT: Final = re.compile(r"^hermes-[a-z0-9-]*e2e-[0-9a-f]{8}-(\d+)-[0-9a-f]{6}$")


def run_name(prefix: str) -> str:
    """A Docker-safe name unique to this run (image repository, Compose project)."""
    return f"{prefix}-{RUN_ID}".lower()


def free_port(attempts: int = 200) -> int:
    """A local TCP port that was free a moment ago, for a Compose stack that publishes ports.

    Drawn from `PORT_RANGE`, never from the kernel's ephemeral range: Docker Desktop on WSL cannot publish the
    ports Windows reserves above 49152, which `bind(0)` hands out. Each candidate is bound once to check it.
    """
    for _ in range(attempts):
        port = secrets.randbelow(PORT_RANGE[1] - PORT_RANGE[0] + 1) + PORT_RANGE[0]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue  # taken: try another one
            return port
    raise RuntimeError(f"no free port in {PORT_RANGE} after {attempts} attempts")


def on_loopback[C: DockerContainer](container: C) -> C:
    """Publish every exposed port of `container` on 127.0.0.1 only, each on a host port Docker picks.

    Testcontainers publishes an exposed port on every interface (0.0.0.0 and ::), reachable from the network for as
    long as the tests run. docker-py takes a (host address, host port) pair for each container port, and a None port
    lets Docker pick a free one as before. Call it after the ports are exposed and before the container starts. The
    tests reach Docker on this host (GitHub runners included), so the loopback address is always theirs.
    """
    for port in list(container.ports):
        container.ports[port] = (LOOPBACK, None)  # type: ignore[assignment]  # testcontainers types only the port
    return container


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
    """Remove the containers and tags left by test runs of this host whose process is gone. Returns what it removed.

    Only the list endpoints are used (no per-item inspect), so a container or image another run removes in the
    meantime is simply gone, never an error.
    """
    removed: list[str] = []
    owned = {"label": [f"{LABEL}=1", f"{LABEL}.host={HOST}"]}
    for container in client.api.containers(all=True, filters=owned):
        if not alive((container.get("Labels") or {}).get(f"{LABEL}.pid", "")) and _remove_container(client, container):
            removed.append(_name(container))
    for image in client.api.images(filters=owned):
        if not alive((image.get("Labels") or {}).get(f"{LABEL}.pid", "")):
            for tag in _tags(image):
                untag(client, tag)
                removed.append(tag)
    removed += _sweep_dead_stacks(client, alive)
    return removed


def _name(container: dict[str, Any]) -> str:
    names = container.get("Names") or [container["Id"]]
    return str(names[0]).lstrip("/")


def _tags(image: dict[str, Any]) -> list[str]:
    """Real tags only: older daemons list an untagged image as `<none>:<none>`."""
    return [tag for tag in image.get("RepoTags") or [] if tag != "<none>:<none>"]


def _remove_container(client: docker.DockerClient, container: dict[str, Any]) -> bool:
    """True if this call removed it; gone already, or in the way of another removal, is False."""
    try:
        client.api.remove_container(container["Id"], force=True)
    except (NotFound, APIError):
        return False
    return True


def _sweep_dead_stacks(client: docker.DockerClient, alive: Callable[[str], bool]) -> list[str]:
    """The Compose stacks of e2e runs whose process is gone: containers, networks, volumes and built images."""
    dead: set[str] = set()
    for container in client.api.containers(all=True, filters={"label": COMPOSE_PROJECT}):
        match = E2E_PROJECT.match((container.get("Labels") or {}).get(COMPOSE_PROJECT, ""))
        if match and not alive(match.group(1)):
            dead.add(match.group(0))
    removed: list[str] = []
    for project in sorted(dead):
        scope = {"label": f"{COMPOSE_PROJECT}={project}"}
        for container in client.api.containers(all=True, filters=scope):
            _remove_container(client, container)
        for network in client.api.networks(filters=scope):
            with contextlib.suppress(NotFound, APIError):
                client.api.remove_network(network["Id"])
        for volume in (client.api.volumes(filters=scope) or {}).get("Volumes") or []:
            with contextlib.suppress(NotFound, APIError):
                client.api.remove_volume(volume["Name"], force=True)
        for image in client.api.images(name=f"{project}-*"):
            for tag in _tags(image):
                untag(client, tag)
        removed.append(project)
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
