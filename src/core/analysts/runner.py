"""One analyst call with validation, retries and its audit record (docs/09 §1 and §3, L13).

The model call, the validators, the clock and the waits are arguments, so tests run with the deterministic LLM
double and never touch the network or spend tokens. Format and content failures are retried at most twice with only
the concrete errors (`core.validation.retry`); transport failures are already retried inside the LLM client, so
here one attempt is made.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy.orm import Session

from core.analysts.prompt import PromptVersions, retry_message
from core.db import models as m
from core.db.ids import new_id
from core.llm.client import LlmClient
from core.llm.errors import LlmError, LlmRequestError, LlmResponseError, LlmTransportError, ToolArgumentsError
from core.llm.tools import ToolDefinition
from core.llm.usage import Usage
from core.validation.retry import (
    CircuitBreaker,
    FormatError,
    Outcome,
    RetryPolicy,
    Timing,
    TransportError,
    run_validated,
)
from core.validation.violations import Violation

# TODO(P-015): USD per million tokens of the analyst model (DeepSeek flash); not verified against the price list.
PRICE_INPUT = Decimal("0.28")
PRICE_CACHED = Decimal("0.028")
PRICE_OUTPUT = Decimal("0.42")
MILLION = Decimal(1_000_000)
ANALYST_RETRY = RetryPolicy(transport_attempts=1)  # the client already retried transport failures


def cost_usd(usage: Usage) -> Decimal:
    """Cost of the tokens used: cached input at the cached price, reasoning tokens as output."""
    fresh = max(0, usage.input - usage.cached_input)
    total = (
        PRICE_INPUT * fresh + PRICE_CACHED * usage.cached_input + PRICE_OUTPUT * (usage.output + usage.reasoning)
    ) / MILLION
    return total.quantize(Decimal("0.000001"))


@dataclass(frozen=True)
class Request:
    """What one analyst call needs: the model, the tool, the fixed system prompt and the delimited data message."""

    model: str
    tool: ToolDefinition
    system: str
    user: str
    validate: Callable[[dict[str, Any]], list[Violation]]


@dataclass(frozen=True)
class Seams:
    """The waiting seams and the shared circuit breaker of a run."""

    breaker: CircuitBreaker
    timing: Timing
    clock: Callable[[], float] = time.monotonic


@dataclass(frozen=True)
class RunResult:
    outcome: Outcome | None  # None when the provider rejected the request itself
    usage: Usage
    latency_ms: int
    failure: str | None  # why there is no output: the rule ids, "transport", "request" or "provider_down"


def default_seams() -> Seams:
    return Seams(breaker=CircuitBreaker(ANALYST_RETRY, time.monotonic), timing=Timing(time.sleep, random.random))


def run_analyst(client: LlmClient, request: Request, seams: Seams) -> RunResult:
    """Call the model until its output validates or the retry policy gives up; the tokens of every call count."""
    usage = Usage()
    started = seams.clock()

    def call(feedback: str | None) -> dict[str, Any]:
        nonlocal usage
        messages: list[dict[str, str]] = [
            {"role": "system", "content": request.system},
            {"role": "user", "content": request.user},
        ]
        if feedback is not None:
            messages.append({"role": "user", "content": retry_message(feedback)})
        try:
            result = client.call_tool(
                model=request.model, messages=messages, tools=[request.tool], force_tool=request.tool.name
            )
        except LlmTransportError as exc:
            usage += exc.usage
            raise TransportError("llm transport failure") from exc
        except (LlmResponseError, ToolArgumentsError) as exc:
            usage += exc.usage
            raise FormatError(str(exc)) from exc
        usage += result.usage
        return result.arguments

    try:
        outcome = run_validated(call, request.validate, seams.breaker, seams.timing, ANALYST_RETRY)
    except LlmRequestError:
        return RunResult(None, usage, _ms(seams, started), "request")
    except LlmError as exc:  # any other client error is a request-level failure; the tokens still count
        usage += exc.usage
        return RunResult(None, usage, _ms(seams, started), "request")
    failure = None if outcome.status == "ok" else (outcome.reason or outcome.status)
    return RunResult(outcome, usage, _ms(seams, started), failure)


def _ms(seams: Seams, started: float) -> int:
    return int((seams.clock() - started) * 1000)


@dataclass(frozen=True)
class ReviewInfo:
    """What identifies an analyst run in its audit record."""

    agent: str
    request: Request
    versions: PromptVersions
    input_ref: str


def record_review(session: Session, info: ReviewInfo, result: RunResult, now: datetime) -> m.LlmReview:
    """Write the `llm_review` of an analyst run, successful or not (the tokens were paid either way)."""
    outcome = result.outcome
    versions, request = info.versions, info.request
    review = m.LlmReview(
        id=new_id(),
        agent=info.agent,
        model=request.model,
        response_model={"requested": request.model},
        prompt_version=versions.prompt_version,
        prompt_hash=versions.prompt_hash,
        schema_version=versions.schema_version,
        schema_hash=versions.schema_hash,
        parameters={"thinking": "disabled", "tool": request.tool.name},
        input_ref=info.input_ref,
        calls=[{"attempts": outcome.attempts if outcome else 0, "failure": result.failure}],
        status="applied" if result.failure is None else "rejected",
        attempts=outcome.attempts if outcome else 1,
        tokens_input=result.usage.input,
        tokens_cached=result.usage.cached_input,
        tokens_output=result.usage.output,
        tokens_reasoning=result.usage.reasoning,
        cost_usd=cost_usd(result.usage),
        latency_ms=result.latency_ms,
        ladder_level=0,
        created_at=now,
    )
    session.add(review)
    session.flush()
    return review
