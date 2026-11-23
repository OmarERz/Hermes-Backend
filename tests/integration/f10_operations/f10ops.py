"""Shared pieces of the operations tests: the reference time and fake connection probes."""

from __future__ import annotations

from datetime import UTC, datetime

from core.connections.probes import MSG_OK, Name, Probe, ProbeResult

T0 = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)


class FakeProbes:
    """Every service answers ok unless listed in `down`; counts the checks."""

    def __init__(self) -> None:
        self.down: set[str] = set()
        self.calls = 0

    def __call__(self, name: Name) -> Probe:
        def run() -> ProbeResult:
            self.calls += 1
            if name in self.down:
                return ProbeResult(ok=False, latency_ms=None, message="Variable faltante: X", missing_variable="X")
            return ProbeResult(ok=True, latency_ms=12, message=MSG_OK)

        return run
