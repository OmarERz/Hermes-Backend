"""Retry policy for LLM calls (docs/09 §3).

- Format or content failures: at most 2 retries, sending only the concrete errors; the same error twice in a row
  stops the retries (no third attempt).
- Transport failures (timeout, 429, 5xx): at most 3 attempts with exponential, random waits; `Retry-After` is
  respected.
- Provider down: after 5 failures in a row the circuit opens and calls pause for 10 minutes.

The model call, the validator, the clock, the sleep and the random source are arguments, so tests need no
network and no waiting.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from core.validation.violations import Violation, retry_feedback, signature


class TransportError(Exception):
    """The call did not complete (timeout, 429, 5xx). `retry_after` is the provider's wait in seconds, if any."""

    def __init__(self, message: str = "transport error", retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


@dataclass(frozen=True)
class RetryPolicy:
    format_retries: int = 2
    transport_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 30.0
    breaker_failures: int = 5
    breaker_pause: float = 600.0


class CircuitBreaker:
    """Opens after `breaker_failures` transport failures in a row; closes again after the pause."""

    def __init__(self, policy: RetryPolicy, clock: Callable[[], float]) -> None:
        self._policy = policy
        self._clock = clock
        self._failures = 0
        self._opened_at: float | None = None

    def allow(self) -> bool:
        if self._opened_at is None:
            return True
        if self._clock() - self._opened_at >= self._policy.breaker_pause:
            self._opened_at = None
            self._failures = 0
            return True
        return False

    def record_success(self) -> None:
        self._failures = 0

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self._policy.breaker_failures:
            self._opened_at = self._clock()


def transport_delay(attempt: int, retry_after: float | None, policy: RetryPolicy, rng: Callable[[], float]) -> float:
    """Wait before transport attempt `attempt + 1`: full jitter over an exponential cap, never below Retry-After."""
    cap = min(policy.max_delay, policy.base_delay * 2 ** (attempt - 1))
    asked = retry_after if retry_after is not None and math.isfinite(retry_after) else 0.0
    return float(max(rng() * cap, min(asked, policy.breaker_pause)))


@dataclass(frozen=True)
class Outcome:
    status: Literal["ok", "rejected", "transport_failed", "provider_down"]
    output: dict[str, Any] | None
    attempts: int  # calls made to the model
    violations: list[Violation] = field(default_factory=list)
    reason: str = ""  # goes to error_queue.reason when the status is not ok


@dataclass(frozen=True)
class Timing:
    """The waiting seams: `sleep(seconds)` and `rng()` in [0, 1)."""

    sleep: Callable[[float], None]
    rng: Callable[[], float]


class _Run:
    def __init__(
        self,
        call: Callable[[str | None], dict[str, Any]],
        breaker: CircuitBreaker,
        timing: Timing,
        policy: RetryPolicy,
    ) -> None:
        self.call, self.breaker, self.timing, self.policy = call, breaker, timing, policy
        self.attempts = 0

    def call_with_transport_retries(self, feedback: str | None) -> dict[str, Any] | Outcome:
        for transport_attempt in range(1, self.policy.transport_attempts + 1):
            if not self.breaker.allow():
                return Outcome("provider_down", None, self.attempts, reason="circuit open: provider unavailable")
            self.attempts += 1
            try:
                output = self.call(feedback)
            except TransportError as exc:
                self.breaker.record_failure()
                if not self.breaker.allow():
                    return Outcome("provider_down", None, self.attempts, reason="circuit open: provider unavailable")
                if transport_attempt == self.policy.transport_attempts:
                    return Outcome("transport_failed", None, self.attempts, reason=f"transport: {exc}")
                self.timing.sleep(transport_delay(transport_attempt, exc.retry_after, self.policy, self.timing.rng))
                continue
            self.breaker.record_success()
            return output
        return Outcome("transport_failed", None, self.attempts, reason="transport: no attempts allowed")


def run_validated(
    call: Callable[[str | None], dict[str, Any]],
    validate: Callable[[dict[str, Any]], list[Violation]],
    breaker: CircuitBreaker,
    timing: Timing,
    policy: RetryPolicy | None = None,
) -> Outcome:
    """Call the model until the output validates or a retry limit is reached. `call` gets the retry feedback."""
    policy = policy or RetryPolicy()
    run = _Run(call, breaker, timing, policy)
    feedback: str | None = None
    previous: frozenset[tuple[str, str, str]] | None = None
    failures = 0
    while True:
        result = run.call_with_transport_retries(feedback)
        if isinstance(result, Outcome):
            return result
        violations = validate(result)
        if not violations:
            return Outcome("ok", result, run.attempts)
        failures += 1
        current = signature(violations)
        if (previous is not None and previous & current) or failures > policy.format_retries:
            reason = "; ".join(sorted({v.rule for v in violations}))
            return Outcome("rejected", None, run.attempts, violations, reason)
        previous = current
        feedback = retry_feedback(violations)
