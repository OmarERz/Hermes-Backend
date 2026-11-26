"""LLM calls that honour the worker's stop signal (#170).

An analyst call or a judge turn can take a minute. `StoppableCaller` checks the signal before every call, so a cycle
that analyses one story or group after another stops at the next call. `stoppable_runner` replaces `subprocess.run`
for `ClaudeCodeClient`: a watcher thread polls the signal while the CLI runs and kills the CLI when the worker is
asked to stop, so the worker neither waits for the answer nor leaves the CLI running (and spending the subscription)
after it exits.
"""

from __future__ import annotations

import subprocess
import threading
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
    stop: StopSignal, *, poll_seconds: float = POLL_SECONDS
) -> Callable[..., subprocess.CompletedProcess[str]]:
    """A `subprocess.run` replacement (the keywords `ClaudeCodeClient` passes) that kills the child on stop.

    The child is driven by one `communicate(input, timeout)` call, exactly like `subprocess.run`, so a prompt larger
    than the pipe buffer is written whole and stdin is closed (a second `communicate` call cannot resume writing the
    input). A watcher thread polls the signal and kills the child when the worker is asked to stop. Raises
    ShutdownRequested when the signal is set before or while the child runs, and `subprocess.TimeoutExpired` when
    `timeout` passes; the child is killed and reaped in both cases.
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
        with subprocess.Popen(list(argv), stdin=subprocess.PIPE, **pipes, **popen) as process:  # noqa: S603
            done, stopped = threading.Event(), threading.Event()

            def watch() -> None:
                while not done.wait(poll_seconds):
                    if stop.event.is_set():
                        stopped.set()
                        process.kill()  # communicate() below then returns: the pipes close with the child
                        return

            watcher = threading.Thread(target=watch, name="claude-cli-stop", daemon=True)
            watcher.start()
            try:
                stdout, stderr = process.communicate(input, timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                raise
            finally:
                done.set()
                watcher.join()
            if stopped.is_set():
                raise ShutdownRequested("the worker is stopping")
        return subprocess.CompletedProcess(list(argv), process.returncode, stdout, stderr)

    return run
