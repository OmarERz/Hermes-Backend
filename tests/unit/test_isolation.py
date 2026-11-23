"""Run-unique names for the Docker resources tests create (tests/harness/isolation.py)."""

from __future__ import annotations

import os
import re
import signal
import socket

import pytest

from harness.isolation import PORT_RANGE, RUN_ID, cleanup_on_sigterm, free_port, run_name

pytestmark = pytest.mark.unit


def test_names_carry_the_run_id_and_are_docker_safe() -> None:
    name = run_name("Hermes-E2E")
    assert name == f"hermes-e2e-{RUN_ID}".lower()
    assert re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", name)
    assert run_name("a") != run_name("b")


def test_a_free_port_comes_from_the_fixed_range_below_the_reserved_ones() -> None:
    low, high = PORT_RANGE
    ports = {free_port() for _ in range(20)}
    assert all(low <= port <= high for port in ports)
    assert high < 49152


def test_a_taken_port_is_skipped_and_an_exhausted_search_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        busy = taken.getsockname()[1]
        monkeypatch.setattr("harness.isolation.PORT_RANGE", (busy, busy))
        with pytest.raises(RuntimeError, match="no free port"):
            free_port(attempts=3)


def test_sigterm_unwinds_the_run_like_ctrl_c() -> None:
    before = signal.getsignal(signal.SIGTERM)
    with pytest.raises(KeyboardInterrupt), cleanup_on_sigterm():
        os.kill(os.getpid(), signal.SIGTERM)
    assert signal.getsignal(signal.SIGTERM) == before
