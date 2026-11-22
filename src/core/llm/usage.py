"""Token usage of LLM completions (audit record L13, budget docs/09 §4)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Usage:
    """Token usage of one or more completions (audit record L13, budget docs/09 §4).

    `output` excludes reasoning tokens, which are counted apart (P-017); `cached_input` is part of `input`.
    """

    input: int = 0
    cached_input: int = 0
    output: int = 0
    reasoning: int = 0

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            input=self.input + other.input,
            cached_input=self.cached_input + other.cached_input,
            output=self.output + other.output,
            reasoning=self.reasoning + other.reasoning,
        )
