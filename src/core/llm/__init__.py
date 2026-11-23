"""LLM backends with one contract (`ToolCaller.call_tool`, JUE-03, docs/09): the strict-mode client over the official
`openai` SDK (DeepSeek, D-029) and the Claude Code CLI with the operator's subscription (D-084)."""

from core.llm.claude_code import ClaudeCodeClient
from core.llm.client import LlmClient, RetryPolicy, Timeouts, ToolCall, ToolCaller
from core.llm.errors import (
    LlmError,
    LlmRequestError,
    LlmResponseError,
    LlmTransportError,
    ToolArgumentsError,
    ToolDefinitionError,
)
from core.llm.tools import ToolDefinition, load_tools, make_tool
from core.llm.usage import Usage

__all__ = [
    "ClaudeCodeClient",
    "LlmClient",
    "LlmError",
    "LlmRequestError",
    "LlmResponseError",
    "LlmTransportError",
    "RetryPolicy",
    "Timeouts",
    "ToolArgumentsError",
    "ToolCall",
    "ToolCaller",
    "ToolDefinition",
    "ToolDefinitionError",
    "Usage",
    "load_tools",
    "make_tool",
]
