"""A rejected output is rejected with the rule that failed; nothing is fixed silently (VAL-05)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Violation:
    rule: str  # e.g. VAL-02.schema, VAL-03.quote
    path: str  # where in the output, e.g. cves[2].quote
    message: str
    code: str = ""  # the constraint that failed, so two different errors at one path are not the same failure

    def __str__(self) -> str:
        return f"{self.rule} at {self.path or '<root>'}: {self.message}"


def retry_feedback(violations: list[Violation]) -> str:
    """The concrete errors, and only them, that go back to the model on a format retry (docs/09 §3)."""
    return "\n".join(str(v) for v in violations)


def signature(violations: list[Violation]) -> frozenset[tuple[str, str, str]]:
    """Identity of a failure, to detect the same error twice in a row."""
    return frozenset((v.rule, v.path, v.code) for v in violations)
