"""LLM calls that honour the worker's stop signal (#170).

An analyst call or a judge turn can take a minute. `StoppableCaller` checks the signal before every call, so a cycle
that analyses one story or group after another stops at the next call. `stoppable_runner` replaces `subprocess.run`
for `ClaudeCodeClient`: it polls the signal while the CLI runs and kills the CLI when the worker is asked to stop,
so the worker neither waits for the answer nor leaves the CLI running (and spending the subscription) after it exits.
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from core.llm.client import ToolCall, ToolCaller
from core.llm.tools import ToolDefinition
from core.shutdown import ShutdownRequested, StopSignal

POLL_SECONDS = 0.25


@dataclass(frozen=True)
class StoppableCaller:
    """A `ToolCaller` that checks the worker's stop signal before each call, then delegates."""

    inner: ToolCaller
    stop: StopSignal

    def call_tool(
        self,
        *,
        model: str,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[ToolDefinition],
        force_tool: str | None = None,
    ) -> ToolCall:
        self.stop.check()
        return self.inner.call_tool(model=model, messages=messages, tools=tools, force_tool=force_tool)


def stoppable_runner(
    stop: StopSignal, *, poll_seconds: float = POLL_SECONDS, clock: Callable[[], float] = time.monotonic
) -> Callable[..., subprocess.CompletedProcess[str]]:
    """A `subprocess.run` replacement (the keywords `ClaudeCodeClient` passes) that kills the child on stop.

    Raises ShutdownRequested when the signal is set before or while the child runs, and `subprocess.TimeoutExpired`
    when `timeout` passes, like `subprocess.run`; the child is killed and reaped in both cases.
    """

    def run(
        argv: Sequence[str],
        *,
        input: str | None = None,  # noqa: A002 - the subprocess.run keyword
        timeout: float | None = None,
        capture_output: bool = False,
        check: bool = False,
        **popen: Any,
    ) -> subprocess.CompletedProcess[str]:
        del check  # the client reads the exit code itself
        stop.check()
        pipes: dict[str, Any] = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE} if capture_output else {}
        deadline = None if timeout is None else clock() + timeout
        with subprocess.Popen(list(argv), stdin=subprocess.PIPE, **pipes, **popen) as process:  # noqa: S603
            pending = input
            while True:
                wait = poll_seconds if deadline is None else max(0.0, min(poll_seconds, deadline - clock()))
                try:
                    stdout, stderr = process.communicate(pending, timeout=wait)
                    break
                except subprocess.TimeoutExpired:
                    pending = None  # already handed over: communicate() resumes the same exchange
                    if stop.event.is_set():
                        _kill(process)
                        raise ShutdownRequested("the worker is stopping") from None
                    if deadline is not None and clock() >= deadline:
                        _kill(process)
                        raise subprocess.TimeoutExpired(list(argv), timeout or 0.0) from None
        return subprocess.CompletedProcess(list(argv), process.returncode, stdout, stderr)

    return run


def _kill(process: subprocess.Popen[Any]) -> None:
    process.kill()
    process.communicate()
