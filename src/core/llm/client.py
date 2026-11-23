"""Thin client over the official `openai` SDK for an OpenAI-compatible API (D-029; no agent frameworks).

- One client per role (judge or analysts) with its own base URL (docs/11); the API key is a SecretStr.
- The SDK does not retry (`max_retries=0`); this module retries transport failures only (timeouts, connection
  errors, 429, 5xx) with bounded, jittered exponential backoff that honors Retry-After (docs/09 §3).
  Format and content failures are never retried here: the caller owns that policy (VAL-05).
- Strict tools (JUE-03): the model is forced to answer with a tool call whose arguments are validated against
  the tool's JSON Schema.
"""

from __future__ import annotations

import json
import logging
import random
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, cast

import httpx2
import openai
from openai.types.chat import ChatCompletionMessageParam, ChatCompletionToolParam
from pydantic import SecretStr

from core.config import Settings
from core.llm.errors import LlmRequestError, LlmResponseError, LlmTransportError, ToolArgumentsError
from core.llm.tools import ToolDefinition
from core.llm.usage import Usage
from core.textnum import retry_after_seconds

logger = logging.getLogger(__name__)

Role = Literal["judge", "analysts"]
MAX_RETRY_AFTER_SECONDS = 60.0
# Explicit output cap per call (OWASP LLM10, F12.3): DeepSeek's default without thinking is 8K tokens, verified against
# https://api-docs.deepseek.com/api/create-chat-completion/ (`max_tokens`, 1 to 393 216). A provider whose default is
# larger (thinking mode, another OpenAI-compatible API) cannot bill an unbounded answer to one call.
DEFAULT_MAX_OUTPUT_TOKENS = 8192


@dataclass(frozen=True)
class RetryPolicy:
    """Transport retries (docs/09 §3): at most `max_attempts` calls in total, exponential backoff with jitter."""

    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 30.0
    sleep: Callable[[float], None] = time.sleep
    jitter: Callable[[], float] = random.random


@dataclass(frozen=True)
class Timeouts:
    """Explicit timeouts in seconds; reasoning models can be slow to answer, so `read` is generous."""

    connect: float = 10.0
    read: float = 120.0
    write: float = 30.0
    pool: float = 10.0

    def to_httpx(self) -> httpx2.Timeout:
        return httpx2.Timeout(connect=self.connect, read=self.read, write=self.write, pool=self.pool)


@dataclass(frozen=True)
class ToolCall:
    """The tool call chosen by the model, with already validated arguments, plus what the audit needs."""

    name: str
    arguments: dict[str, Any]
    call_id: str = ""
    usage: Usage = field(default_factory=Usage)
    response_model: str | None = None


class LlmClient:
    def __init__(  # noqa: PLR0913 - keyword-only configuration of one client
        self,
        *,
        base_url: str,
        api_key: SecretStr,
        timeouts: Timeouts | None = None,
        retry: RetryPolicy | None = None,
        http_client: httpx2.Client | None = None,
        jitter: Callable[[], float] = random.random,
        max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
    ) -> None:
        if max_output_tokens < 1:
            raise ValueError("max_output_tokens must be positive")
        self._max_output_tokens = max_output_tokens
        self._retry = retry or RetryPolicy()
        self._client = openai.OpenAI(
            base_url=base_url,
            api_key=api_key.get_secret_value(),
            max_retries=0,
            timeout=(timeouts or Timeouts()).to_httpx(),
            http_client=http_client,
        )

    @classmethod
    def from_settings(cls, settings: Settings, role: Role, **kwargs: Any) -> LlmClient:
        """Build the client of a role. Fails closed when the API key is not configured."""
        if settings.deepseek_api_key is None:
            raise LlmRequestError("DEEPSEEK_API_KEY is not configured")
        url = settings.llm_base_url_judge if role == "judge" else settings.llm_base_url_analysts
        assert url is not None  # noqa: S101 - Settings defaults the analysts URL to the judge URL
        return cls(base_url=str(url), api_key=settings.deepseek_api_key, **kwargs)

    def call_tool(
        self,
        *,
        model: str,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[ToolDefinition],
        force_tool: str | None = None,
    ) -> ToolCall:
        """Run one chat completion with strict tools and return the validated tool call.

        Raises LlmTransportError (after retries), LlmRequestError, LlmResponseError or ToolArgumentsError.
        """
        by_name = {tool.name: tool for tool in tools}
        tool_choice: Any = (
            {"type": "function", "function": {"name": force_tool}} if force_tool is not None else "required"
        )
        completion = self._with_retries(
            lambda: self._client.chat.completions.create(
                model=model,
                messages=cast("list[ChatCompletionMessageParam]", list(messages)),
                tools=[cast("ChatCompletionToolParam", dict(tool.definition)) for tool in tools],
                tool_choice=tool_choice,
                max_tokens=self._max_output_tokens,
                # `required` and named tool choices return 400 while thinking is on; verified against
                # https://api-docs.deepseek.com/api/create-chat-completion/ (thinking.type = disabled).
                extra_body={"thinking": {"type": "disabled"}},
            )
        )
        usage = _usage(completion)
        try:
            return self._tool_call(completion, by_name, force_tool, usage)
        except (LlmResponseError, ToolArgumentsError) as exc:
            exc.usage = usage  # the completion was paid for even if its answer is unusable (L12)
            raise

    @staticmethod
    def _tool_call(
        completion: Any, by_name: Mapping[str, ToolDefinition], force_tool: str | None, usage: Usage
    ) -> ToolCall:
        if completion.choices and getattr(completion.choices[0], "finish_reason", None) == "length":
            # The answer hit the output cap: whatever tool call it holds is cut, never a partial result (L12).
            raise LlmResponseError("the answer was cut at the output token limit")
        calls = completion.choices[0].message.tool_calls if completion.choices else None
        if not calls or len(calls) != 1:
            raise LlmResponseError("expected exactly one tool call")
        function = getattr(calls[0], "function", None)
        tool = by_name.get(getattr(function, "name", ""))
        if function is None or tool is None or (force_tool is not None and tool.name != force_tool):
            raise LlmResponseError("the model called a tool that was not offered")
        try:
            arguments = json.loads(function.arguments)
        except json.JSONDecodeError as exc:
            raise LlmResponseError("tool call arguments are not valid JSON") from exc
        tool.validate_arguments(arguments)
        return ToolCall(
            name=tool.name,
            arguments=arguments,
            call_id=str(getattr(calls[0], "id", "") or ""),
            usage=usage,
            response_model=getattr(completion, "model", None),
        )

    def _with_retries[T](self, operation: Callable[[], T]) -> T:
        for attempt in range(1, self._retry.max_attempts + 1):
            try:
                return operation()
            except (openai.APIConnectionError, openai.RateLimitError, openai.InternalServerError) as exc:
                retry_after = _retry_after(exc)
                if attempt == self._retry.max_attempts:
                    # Only the exception type is reported: SDK messages may carry provider text.
                    raise LlmTransportError(f"LLM call failed after {attempt} attempts: {type(exc).__name__}") from None
                delay = self._backoff(attempt, retry_after)
                logger.warning("llm transport error %s, retry %d in %.1fs", type(exc).__name__, attempt, delay)
                self._retry.sleep(delay)
            except openai.APIStatusError as exc:
                raise LlmRequestError(f"LLM request rejected with status {exc.status_code}") from None
        raise AssertionError("unreachable")  # pragma: no cover

    def _backoff(self, attempt: int, retry_after: float | None) -> float:
        exponential = min(self._retry.max_delay, self._retry.base_delay * float(2 ** (attempt - 1)))
        delay = exponential * (0.5 + self._retry.jitter() / 2)
        if retry_after is not None:
            delay = max(delay, min(retry_after, MAX_RETRY_AFTER_SECONDS))
        return delay


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def _usage(completion: Any) -> Usage:
    """Read token counts defensively: OpenAI-style details or DeepSeek's prompt_cache_hit_tokens ⚠️."""
    usage = getattr(completion, "usage", None)
    if usage is None:
        return Usage()
    prompt_details = getattr(usage, "prompt_tokens_details", None)
    cached = _count(getattr(prompt_details, "cached_tokens", None)) or _count(
        getattr(usage, "prompt_cache_hit_tokens", None)
    )
    reasoning = _count(getattr(getattr(usage, "completion_tokens_details", None), "reasoning_tokens", None))
    completion_tokens = _count(getattr(usage, "completion_tokens", None))
    return Usage(
        input=_count(getattr(usage, "prompt_tokens", None)),
        cached_input=cached,
        output=max(completion_tokens - reasoning, 0),
        reasoning=reasoning,
    )


def _retry_after(exc: Exception) -> float | None:
    response = getattr(exc, "response", None)
    value = response.headers.get("retry-after") if response is not None else None
    return retry_after_seconds(None if value is None else str(value))  # HTTP-date form: the computed backoff
