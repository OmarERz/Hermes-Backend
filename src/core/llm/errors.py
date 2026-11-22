"""Typed errors of the LLM client. Messages never contain the API key or the model's raw output."""

from __future__ import annotations


class LlmError(Exception):
    """Base class of every LLM client error."""


class LlmTransportError(LlmError):
    """Timeouts, connection errors, 429 or 5xx that persisted after the bounded retries (docs/09 §3)."""


class LlmRequestError(LlmError):
    """The provider rejected the request (4xx other than 429): retrying the same request cannot help."""


class LlmResponseError(LlmError):
    """The response did not contain exactly the expected tool call, or its arguments were not valid JSON."""


class ToolArgumentsError(LlmError):
    """The tool call arguments do not match the tool's JSON Schema (VAL-02). Carries field paths, not values."""

    def __init__(self, tool_name: str, problems: list[str]) -> None:
        super().__init__(f"tool {tool_name!r} arguments rejected: " + "; ".join(problems))
        self.tool_name = tool_name
        self.problems = problems


class ToolDefinitionError(LlmError):
    """A tool definition is not usable in DeepSeek strict mode (JUE-03) or is not found."""
