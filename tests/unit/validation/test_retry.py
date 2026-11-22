"""Retry policy, circuit breaker and the validated-call loop, without waiting or network."""

from __future__ import annotations

from typing import Any

from core.validation.retry import (
    CircuitBreaker,
    RetryPolicy,
    Timing,
    TransportError,
    run_validated,
    transport_delay,
)
from core.validation.violations import Violation, retry_feedback, signature


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class Harness:
    """Scripted model replies (dicts or TransportError) and scripted validation results."""

    def __init__(self, replies: list[Any], verdicts: list[list[Violation]] | None = None) -> None:
        self.replies = list(replies)
        self.verdicts = list(verdicts or [])
        self.feedbacks: list[str | None] = []
        self.sleeps: list[float] = []
        self.clock = Clock()
        self.policy = RetryPolicy()
        self.breaker = CircuitBreaker(self.policy, self.clock)

    def call(self, feedback: str | None) -> dict[str, Any]:
        self.feedbacks.append(feedback)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        assert isinstance(reply, dict)
        return reply

    def validate(self, _output: dict[str, Any]) -> list[Violation]:
        return self.verdicts.pop(0) if self.verdicts else []

    def run(self, policy: RetryPolicy | None = None) -> Any:
        return run_validated(
            self.call, self.validate, self.breaker, Timing(self.sleeps.append, lambda: 0.5), policy or self.policy
        )


def bad(rule: str = "VAL-03.quote", path: str = "cves[0].quote") -> list[Violation]:
    return [Violation(rule, path, "bad")]


def test_valid_output_on_the_first_call() -> None:
    h = Harness([{"a": 1}])
    outcome = h.run()
    assert (outcome.status, outcome.output, outcome.attempts) == ("ok", {"a": 1}, 1)
    assert h.feedbacks == [None]


def test_format_retry_sends_only_the_concrete_errors() -> None:
    h = Harness([{"n": 1}, {"n": 2}], [bad()])
    outcome = h.run()
    assert (outcome.status, outcome.attempts) == ("ok", 2)
    assert h.feedbacks == [None, "VAL-03.quote at cves[0].quote: bad"]


def test_two_retries_with_different_errors_can_still_succeed() -> None:
    h = Harness([{}, {}, {}], [bad("VAL-03.quote"), bad("VAL-03.cve_exists", "cves[0].cve")])
    assert h.run().status == "ok"
    assert len(h.feedbacks) == 3


def test_a_third_different_failure_is_rejected() -> None:
    h = Harness([{}, {}, {}, {}], [bad("A"), bad("B"), bad("C")])
    outcome = h.run()
    assert (outcome.status, outcome.attempts, outcome.output) == ("rejected", 3, None)
    assert outcome.reason == "C"
    assert len(h.replies) == 1  # no fourth call


def test_the_same_error_twice_means_no_third_attempt() -> None:
    h = Harness([{}, {}, {}], [bad(), bad()])
    outcome = h.run()
    assert (outcome.status, outcome.attempts) == ("rejected", 2)
    assert [v.rule for v in outcome.violations] == ["VAL-03.quote"]


def test_transport_failures_back_off_and_respect_retry_after() -> None:
    h = Harness([TransportError("429", retry_after=7.0), TransportError("503"), {"ok": True}])
    outcome = h.run()
    assert (outcome.status, outcome.attempts) == ("ok", 3)
    assert h.sleeps == [7.0, 1.0]  # max(0.5 * 1, 7.0) then 0.5 * 2


def test_three_transport_failures_give_up() -> None:
    h = Harness([TransportError("a"), TransportError("b"), TransportError("c")])
    outcome = h.run()
    assert (outcome.status, outcome.attempts) == ("transport_failed", 3)
    assert outcome.reason == "transport: c"
    assert len(h.sleeps) == 2


def test_no_transport_attempts_allowed_is_a_failure_not_a_crash() -> None:
    outcome = Harness([]).run(RetryPolicy(transport_attempts=0))
    assert outcome.status == "transport_failed"


def test_delay_is_capped_and_jittered() -> None:
    policy = RetryPolicy(base_delay=1.0, max_delay=10.0)
    assert transport_delay(1, None, policy, lambda: 1.0) == 1.0
    assert transport_delay(3, None, policy, lambda: 1.0) == 4.0
    assert transport_delay(10, None, policy, lambda: 1.0) == 10.0
    assert transport_delay(2, None, policy, lambda: 0.0) == 0.0
    assert transport_delay(2, 30.0, policy, lambda: 0.5) == 30.0


def test_breaker_opens_after_five_failures_and_closes_after_the_pause() -> None:
    clock = Clock()
    breaker = CircuitBreaker(RetryPolicy(), clock)
    for _ in range(4):
        breaker.record_failure()
    assert breaker.allow()
    breaker.record_failure()
    assert not breaker.allow()
    clock.now = 599.0
    assert not breaker.allow()
    clock.now = 600.0
    assert breaker.allow()
    breaker.record_failure()  # the count restarted: one failure does not reopen it
    assert breaker.allow()


def test_success_resets_the_failure_count() -> None:
    breaker = CircuitBreaker(RetryPolicy(), Clock())
    for _ in range(4):
        breaker.record_failure()
    breaker.record_success()
    for _ in range(4):
        breaker.record_failure()
    assert breaker.allow()


def test_open_breaker_stops_calls_and_reports_provider_down() -> None:
    h = Harness([{"never": "called"}])
    for _ in range(5):
        h.breaker.record_failure()
    outcome = h.run()
    assert (outcome.status, outcome.attempts) == ("provider_down", 0)
    assert h.feedbacks == []


def test_five_transport_failures_in_a_row_across_items_open_the_circuit() -> None:
    h = Harness([TransportError("x")] * 3)
    h.run()
    second = Harness([TransportError("x")] * 2)
    second.breaker = h.breaker
    second.run()
    assert not h.breaker.allow()


def test_signature_and_feedback() -> None:
    violations = [Violation("R1", "a", "m1"), Violation("R2", "b", "m2")]
    assert signature(violations) == {("R1", "a", ""), ("R2", "b", "")}
    assert retry_feedback(violations) == "R1 at a: m1\nR2 at b: m2"
    assert str(Violation("R", "", "m")) == "R at <root>: m"


def test_any_repeated_error_stops_the_retries_even_with_a_new_one_beside_it() -> None:
    h = Harness([{}, {}, {}], [[*bad("A"), *bad("B")], bad("A")])
    outcome = h.run()
    assert (outcome.status, outcome.attempts) == ("rejected", 2)


def test_retry_after_is_capped_and_non_finite_values_are_ignored() -> None:
    policy = RetryPolicy(breaker_pause=60.0)
    assert transport_delay(1, 3600.0, policy, lambda: 0.0) == 60.0
    assert transport_delay(1, float("inf"), policy, lambda: 0.0) == 0.0
    assert transport_delay(1, float("nan"), policy, lambda: 0.0) == 0.0


def test_no_sleep_after_the_failure_that_opens_the_circuit() -> None:
    h = Harness([TransportError("x")] * 3)
    for _ in range(4):
        h.breaker.record_failure()
    outcome = h.run()
    assert (outcome.status, outcome.attempts) == ("provider_down", 1)
    assert h.sleeps == []
