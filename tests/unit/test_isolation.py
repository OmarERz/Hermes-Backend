"""Run-unique names for the Docker resources tests create (tests/harness/isolation.py)."""

from __future__ import annotations

import os
import re
import signal

import pytest

from harness.isolation import RUN_ID, cleanup_on_sigterm, free_port, run_name

pytestmark = pytest.mark.unit


def test_names_carry_the_run_id_and_are_docker_safe() -> None:
    name = run_name("Hermes-E2E")
    assert name == f"hermes-e2e-{RUN_ID}".lower()
    assert re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", name)
    assert run_name("a") != run_name("b")


def test_a_free_port_is_a_local_tcp_port() -> None:
    assert 1024 < free_port() < 65536


def test_sigterm_unwinds_the_run_like_ctrl_c() -> None:
    before = signal.getsignal(signal.SIGTERM)
    with pytest.raises(KeyboardInterrupt), cleanup_on_sigterm():
        os.kill(os.getpid(), signal.SIGTERM)
    assert signal.getsignal(signal.SIGTERM) == before
