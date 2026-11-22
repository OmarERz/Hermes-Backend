"""Strict-mode LLM client over the official `openai` SDK (JUE-03, docs/09)."""

from core.llm.client import LlmClient, RetryPolicy, Timeouts, ToolCall
from core.llm.errors import (
    LlmError,
    LlmRequestError,
    LlmResponseError,
    LlmTransportError,
    ToolArgumentsError,
    ToolDefinitionError,
)
from core.llm.tools import ToolDefinition, load_tools, make_tool

__all__ = [
    "LlmClient",
    "LlmError",
    "LlmRequestError",
    "LlmResponseError",
    "LlmTransportError",
    "RetryPolicy",
    "Timeouts",
    "ToolArgumentsError",
    "ToolCall",
    "ToolDefinition",
    "ToolDefinitionError",
    "load_tools",
    "make_tool",
]
