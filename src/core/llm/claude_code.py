"""LLM backend over the Claude Code CLI with the operator's Claude subscription (D-084; no agent frameworks).

One `call_tool` is one non-interactive `claude -p` process, with the same contract as `LlmClient.call_tool`:

- The tool's JSON Schema goes in `--json-schema`; the CLI returns the answer as `structured_output`, which is then
  validated here against the same schema (VAL-02, `ToolDefinition.validate_arguments`). With several tools (the
  judge), the schema is a choice of `{"name": <tool>, "arguments": <its parameters>}` pairs, one per tool.
- The system messages go in a file (`--system-prompt-file`, which replaces Claude Code's own prompt) together with
  the tool descriptions; the rest of the conversation goes on stdin. The judge's earlier tool calls and their answers
  go as a JSON transcript, so text inside them cannot forge a turn.
- The model cannot act: no built-in tools (`--tools ""`), no MCP servers (`--strict-mcp-config` with no
  `--mcp-config`, claude.ai connectors off), no user or project settings (`--setting-sources ""`), safe mode (no
  CLAUDE.md, plugins, hooks or auto memory), no skills or slash commands, no saved session, in an empty temporary
  directory. A real run's init message lists only the CLI's own `StructuredOutput` tool and no MCP server.
- The child process gets a minimal environment (allow list): PATH, HOME and what the CLI needs to reach its login and
  the network. No application secret (database, Firebase, iTop, DeepSeek...) and never ANTHROPIC_API_KEY, which would
  bill an API account instead of using the subscription.
- Errors map to the client's typed errors. Only a process that ends without a JSON result is retried here (bounded
  by `RetryPolicy`): the CLI already retries API errors itself, and a timeout has already waited the whole window.
- Usage: tokens from `modelUsage` (every model call of the run). `total_cost_usd` is the CLI's API-equivalent
  estimate, which a subscription does not bill: it is logged with each call and does not feed the budget, which keeps
  pricing the tokens with the configured price table (docs/02 §4, 23 nov 2026).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from core.config import CLAUDE_MODEL_PATTERN, Settings
from core.llm.client import RetryPolicy, Role, ToolCall
from core.llm.errors import LlmError, LlmRequestError, LlmResponseError, LlmTransportError
from core.llm.tools import ToolDefinition
from core.llm.usage import Usage

logger = logging.getLogger(__name__)

EXECUTABLE = "claude"
Effort = Literal["low", "medium", "high", "xhigh", "max"]
EFFORTS: tuple[str, ...] = ("low", "medium", "high", "xhigh", "max")
DEFAULT_TIMEOUT_SECONDS = 300.0
# Variables the CLI may need, passed only when set: how to find the executable and its login (HOME or
# CLAUDE_CONFIG_DIR, or a `claude setup-token` token in CLAUDE_CODE_OAUTH_TOKEN), locale and temp dir, and the way
# out to the network (proxies, corporate CA). Nothing else of the worker's environment reaches the child.
PASSTHROUGH_ENV = (
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
    "CLAUDE_CONFIG_DIR",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "no_proxy",
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)
# Verified against https://code.claude.com/docs/en/env-vars (23 nov 2026): no auto-update, telemetry or error
# reporting from a backend process, and no claude.ai MCP connectors.
FIXED_ENV = {"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "ENABLE_CLAUDEAI_MCP_SERVERS": "false"}
MAX_DIAGNOSTIC_CHARS = 300
CLIENT_ERROR_STATUSES = range(400, 500)
RETRYABLE_CLIENT_STATUSES = frozenset({408, 429})

SINGLE_TOOL_FORMAT = (
    "\n\n## Formato de la respuesta\n"
    "Responde solo con la salida estructurada: son los argumentos de la herramienta `{name}`. {description}"
)
CHOICE_FORMAT = (
    "\n\n## Formato de la respuesta\n"
    "En cada turno llamas exactamente una herramienta. Responde solo con la salida estructurada "
    '`{{"tool_call": {{"name": <herramienta>, "arguments": <sus argumentos>}}}}`. Herramientas disponibles:\n'
    "{tools}\n"
    "Si el mensaje del usuario es una lista JSON, es la conversación hasta ahora, en orden: los mensajes del sistema "
    '(`"role": "user"`), tus llamadas anteriores (`"role": "assistant"`) y la respuesta del sistema a cada una '
    '(`"role": "tool"`). Decide solo la siguiente llamada.'
)

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


class _NoResult(Exception):  # noqa: N818 - internal retry signal, never leaves this module
    """The process ended without a JSON result (crash, CLI error message): retried within the policy."""

    def __init__(self, returncode: int) -> None:
        super().__init__(returncode)
        self.returncode = returncode


@dataclass(frozen=True)
class _Prompt:
    """One CLI call: the schema of its structured output, the system prompt file and stdin."""

    schema: dict[str, Any]
    system: str
    user: str
    offered: Mapping[str, ToolDefinition]
    single: ToolDefinition | None  # one tool: the structured output is its arguments


def child_environment(environ: Mapping[str, str]) -> dict[str, str]:
    """The child's environment: the allow list plus the fixed switches; never an application secret."""
    env = {name: environ[name] for name in PASSTHROUGH_ENV if environ.get(name)}
    env.update(FIXED_ENV)
    return env


def command(executable: str, *, schema: Mapping[str, Any], system_file: Path, model: str, effort: str) -> list[str]:
    """The `claude -p` argument list. Every flag was checked against `claude --help` (2.1.330) and
    https://code.claude.com/docs/en/cli-reference on 23 nov 2026."""
    return [
        executable,
        "-p",
        "--output-format",
        "json",
        "--json-schema",
        json.dumps(schema, ensure_ascii=False, separators=(",", ":")),
        "--system-prompt-file",
        str(system_file),
        "--model",
        model,
        "--effort",
        effort,
        "--tools",
        "",
        "--strict-mcp-config",
        "--setting-sources",
        "",
        "--safe-mode",
        "--disable-slash-commands",
        "--no-session-persistence",
    ]


class ClaudeCodeClient:
    """`call_tool` over `claude -p`; one client per role (its model alias), safe to share between threads."""

    def __init__(  # noqa: PLR0913 - keyword-only configuration of one client
        self,
        *,
        model: str,
        effort: str = "medium",
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        executable: str | None = None,
        retry: RetryPolicy | None = None,
        environ: Mapping[str, str] | None = None,
        runner: Runner = subprocess.run,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not re.fullmatch(CLAUDE_MODEL_PATTERN, model):
            raise ValueError("model must be a Claude Code model alias or name")
        if effort not in EFFORTS:
            raise ValueError(f"effort must be one of {', '.join(EFFORTS)}")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        source = os.environ if environ is None else environ
        resolved = executable or shutil.which(EXECUTABLE, path=source.get("PATH"))
        if resolved is None:
            raise LlmRequestError("the claude CLI is not on PATH")
        self.model = model
        self._effort = effort
        self._timeout = timeout
        self._executable = resolved
        self._retry = retry or RetryPolicy()
        self._env = child_environment(source)
        self._runner = runner
        self._clock = clock

    @classmethod
    def from_settings(cls, settings: Settings, role: Role, **kwargs: Any) -> ClaudeCodeClient:
        """The client of a role. Fails closed (LlmRequestError) when the CLI is not on PATH."""
        model = settings.claude_code_model_judge if role == "judge" else settings.claude_code_model_analysts
        return cls(
            model=model,
            effort=settings.claude_code_effort,
            timeout=float(settings.claude_code_timeout_seconds),
            **kwargs,
        )

    def call_tool(
        self,
        *,
        model: str,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[ToolDefinition],
        force_tool: str | None = None,
    ) -> ToolCall:
        """Run one CLI call and return the validated tool call.

        `model` is the caller's model setting (the database keeps the DeepSeek ids): this backend answers with its
        role's alias and reports the model the CLI used as `response_model`. Raises LlmTransportError,
        LlmRequestError, LlmResponseError or ToolArgumentsError, like `LlmClient.call_tool`.
        """
        del model  # the role's alias decides (CLAUDE_CODE_MODEL_JUDGE / CLAUDE_CODE_MODEL_ANALYSTS)
        prompt = _prompt(messages, tools, force_tool)
        started = self._clock()
        result = self._with_retries(prompt)
        usage = _usage(result)
        returned = _returned_model(result)
        status = "ok"
        try:
            _check(result)
            name, arguments = _arguments(result, prompt)
            prompt.offered[name].validate_arguments(arguments)
        except LlmError as exc:
            exc.usage = usage  # tokens the subscription spent on an unusable answer still count (L12)
            status = type(exc).__name__
            raise
        finally:
            _log_call(
                self.model, returned, result, usage, latency_ms=int((self._clock() - started) * 1000), status=status
            )
        return ToolCall(
            name=name, arguments=arguments, call_id=f"call_{uuid.uuid4().hex}", usage=usage, response_model=returned
        )

    # --- process ---------------------------------------------------------------------------------------------
    def _with_retries(self, prompt: _Prompt) -> dict[str, Any]:
        for attempt in range(1, self._retry.max_attempts + 1):
            try:
                return self._run(prompt)
            except _NoResult as exc:
                if attempt == self._retry.max_attempts:
                    raise LlmTransportError(
                        f"claude CLI gave no JSON result after {attempt} attempts (exit code {exc.returncode})"
                    ) from None
                delay = self._backoff(attempt)
                logger.warning(
                    "claude CLI gave no JSON result (exit code %d), retry %d in %.1fs", exc.returncode, attempt, delay
                )
                self._retry.sleep(delay)
        raise AssertionError("unreachable")  # pragma: no cover

    def _run(self, prompt: _Prompt) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="hermes-claude-") as tmp:
            root = Path(tmp)
            system_file = root / "system_prompt.txt"
            system_file.write_text(prompt.system, encoding="utf-8")
            workdir = root / "work"  # empty: nothing to discover, nothing to read
            workdir.mkdir()
            argv = command(
                self._executable, schema=prompt.schema, system_file=system_file, model=self.model, effort=self._effort
            )
            try:
                completed = self._runner(
                    argv,
                    input=prompt.user,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    cwd=workdir,
                    env=self._env,
                    timeout=self._timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                raise LlmTransportError(f"claude CLI call timed out after {self._timeout:.0f}s") from None
            except OSError as exc:
                raise LlmRequestError(f"claude CLI could not be started: {type(exc).__name__}") from None
        result = _parse(completed.stdout)
        if result is None:
            # The CLI's own diagnostics (stderr), never the model's answer, which only comes inside the JSON result.
            logger.warning("claude CLI stderr: %s", (completed.stderr or "").strip()[:MAX_DIAGNOSTIC_CHARS])
            raise _NoResult(completed.returncode)
        return result

    def _backoff(self, attempt: int) -> float:
        exponential = min(self._retry.max_delay, self._retry.base_delay * float(2 ** (attempt - 1)))
        return exponential * (0.5 + self._retry.jitter() / 2)


# --- request ---------------------------------------------------------------------------------------------------
def _prompt(messages: Sequence[Mapping[str, Any]], tools: Sequence[ToolDefinition], force_tool: str | None) -> _Prompt:
    offered = {tool.name: tool for tool in tools if force_tool is None or tool.name == force_tool}
    if not offered:
        raise LlmRequestError("no tool to call: the forced tool was not offered")
    system = "\n\n".join(str(m.get("content") or "") for m in messages if m.get("role") == "system")
    if len(offered) == 1:
        (tool,) = offered.values()
        schema = dict(tool.parameters)
        system += SINGLE_TOOL_FORMAT.format(name=tool.name, description=_description(tool))
        single: ToolDefinition | None = tool
    else:
        schema = _choice_schema(list(offered.values()))
        listing = "\n".join(f"- `{tool.name}`: {_description(tool)}" for tool in offered.values())
        system += CHOICE_FORMAT.format(tools=listing)
        single = None
    user = _conversation([m for m in messages if m.get("role") != "system"])
    return _Prompt(schema=schema, system=system, user=user, offered=offered, single=single)


def _description(tool: ToolDefinition) -> str:
    return str(tool.definition["function"].get("description") or "").strip()


def _choice_schema(tools: Sequence[ToolDefinition]) -> dict[str, Any]:
    """One structured output for several tools: a pair of the tool's name and arguments valid for that tool."""
    pairs = [
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "arguments"],
            "properties": {"name": {"type": "string", "enum": [tool.name]}, "arguments": dict(tool.parameters)},
        }
        for tool in tools
    ]
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["tool_call"],
        "properties": {"tool_call": {"anyOf": pairs}},
    }


def _conversation(messages: Sequence[Mapping[str, Any]]) -> str:
    """stdin: the user messages as they are; once tool calls exist, the whole conversation as a JSON list."""
    if all(m.get("role") == "user" for m in messages):
        return "\n\n".join(str(m.get("content") or "") for m in messages)
    names: dict[str, str] = {}
    turns: list[dict[str, Any]] = []
    for message in messages:
        role = message.get("role")
        if role == "assistant":
            if message.get("content"):
                turns.append({"role": "assistant", "content": str(message["content"])})
            for call in message.get("tool_calls") or []:
                function = call.get("function") or {}
                name = str(function.get("name") or "")
                names[str(call.get("id") or "")] = name
                turns.append(
                    {"role": "assistant", "tool_call": {"name": name, "arguments": _json(function.get("arguments"))}}
                )
        elif role == "tool":
            name = names.get(str(message.get("tool_call_id") or ""), "")
            turns.append({"role": "tool", "name": name, "content": _json(message.get("content"))})
        else:
            turns.append({"role": "user", "content": str(message.get("content") or "")})
    return json.dumps(turns, ensure_ascii=False, indent=1)


def _json(value: Any) -> Any:
    """A JSON string as its value (arguments and tool answers are JSON text); anything else as text."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


# --- response --------------------------------------------------------------------------------------------------
def _parse(stdout: str | None) -> dict[str, Any] | None:
    """The CLI's JSON result (`--output-format json` prints one object); None when there is none."""
    text = (stdout or "").strip()
    candidates = [text, *reversed(text.splitlines())] if text else []
    for candidate in candidates:
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("type") == "result":
            return value
    return None


def _check(result: Mapping[str, Any]) -> None:
    """Map an error result to a typed error. Fields per the Agent SDK's SDKResultMessage (verified 23 nov 2026)."""
    subtype = result.get("subtype")
    if subtype == "error_max_structured_output_retries":
        raise LlmResponseError("the model gave no answer valid for the tool schema")
    if result.get("is_error") is not True and subtype == "success":
        return
    status = result.get("api_error_status")
    if isinstance(status, int) and not isinstance(status, bool):
        if status in CLIENT_ERROR_STATUSES and status not in RETRYABLE_CLIENT_STATUSES:
            raise LlmRequestError(f"claude CLI request rejected with status {status}")
        raise LlmTransportError(f"claude CLI call failed with status {status}")
    if result.get("stop_reason") == "refusal":
        raise LlmResponseError("the model refused to answer")
    raise LlmTransportError(f"claude CLI call failed: {subtype if isinstance(subtype, str) else 'error'}")


def _arguments(result: Mapping[str, Any], prompt: _Prompt) -> tuple[str, dict[str, Any]]:
    output = result.get("structured_output")
    if output is None:
        raise LlmResponseError("the result carries no structured output")
    if prompt.single is not None:
        if not isinstance(output, dict):
            raise LlmResponseError("the structured output is not a JSON object")
        return prompt.single.name, output
    call = output.get("tool_call") if isinstance(output, dict) else None
    name = call.get("name") if isinstance(call, dict) else None
    arguments = call.get("arguments") if isinstance(call, dict) else None
    if not isinstance(name, str) or name not in prompt.offered:
        raise LlmResponseError("the model called a tool that was not offered")
    if not isinstance(arguments, dict):
        raise LlmResponseError("tool call arguments are not a JSON object")
    return name, arguments


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def _usage(result: Mapping[str, Any]) -> Usage:
    """Tokens of every model call of the run (`modelUsage`), or of the main loop (`usage`) when absent.

    Usage.input includes the cached input (cache reads and cache writes are input tokens); thinking tokens are part
    of the output tokens and are counted apart as reasoning, like DeepSeek's (P-017).
    """
    per_model = result.get("modelUsage")
    rows = [row for row in per_model.values() if isinstance(row, dict)] if isinstance(per_model, dict) else []
    if rows:
        fresh = sum(_count(row.get("inputTokens")) for row in rows)
        read = sum(_count(row.get("cacheReadInputTokens")) for row in rows)
        written = sum(_count(row.get("cacheCreationInputTokens")) for row in rows)
        output = sum(_count(row.get("outputTokens")) for row in rows)
        thinking = sum(_count(row.get("thinkingTokens")) for row in rows)
    else:
        usage = result.get("usage")
        main = usage if isinstance(usage, dict) else {}
        fresh = _count(main.get("input_tokens"))
        read = _count(main.get("cache_read_input_tokens"))
        written = _count(main.get("cache_creation_input_tokens"))
        output = _count(main.get("output_tokens"))
        thinking = 0
    reasoning = min(thinking, output)
    return Usage(input=fresh + read + written, cached_input=read, output=output - reasoning, reasoning=reasoning)


def _returned_model(result: Mapping[str, Any]) -> str | None:
    """The model that answered: the one with the most output tokens in `modelUsage`."""
    per_model = result.get("modelUsage")
    if not isinstance(per_model, dict):
        return None
    rows = [(name, row) for name, row in per_model.items() if isinstance(name, str) and isinstance(row, dict)]
    if not rows:
        return None
    return max(rows, key=lambda item: _count(item[1].get("outputTokens")))[0]


def _log_call(  # noqa: PLR0913 - one structured log line per call
    alias: str, returned: str | None, result: Mapping[str, Any], usage: Usage, *, latency_ms: int, status: str
) -> None:
    """Latency, tokens and the CLI's cost estimate of each call (the model's answer is never logged)."""
    cost = result.get("total_cost_usd")
    errors = result.get("errors")
    logger.info(
        "claude-code call: model=%s returned=%s status=%s latency_ms=%d turns=%s usage input=%d cached=%d output=%d "
        "reasoning=%d cli_cost_usd=%s (API-equivalent estimate, not billed on a subscription)",
        alias,
        returned,
        status,
        latency_ms,
        result.get("num_turns"),
        usage.input,
        usage.cached_input,
        usage.output,
        usage.reasoning,
        cost if isinstance(cost, int | float) and not isinstance(cost, bool) else None,
    )
    if status != "ok":
        # CLI and API diagnostics only (error subtype, HTTP status, the CLI's error list); never structured_output.
        logger.warning(
            "claude-code call failed: subtype=%s api_error_status=%s stop_reason=%s terminal_reason=%s errors=%s",
            result.get("subtype"),
            result.get("api_error_status"),
            result.get("stop_reason"),
            result.get("terminal_reason"),
            str(errors)[:MAX_DIAGNOSTIC_CHARS] if isinstance(errors, list) else None,
        )


__all__ = ["EFFORTS", "ClaudeCodeClient", "Effort", "child_environment", "command"]
