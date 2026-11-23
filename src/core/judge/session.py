"""Mode 1 review loop (docs/07 §3-§4): strict tools, code-validated calls, limits, retries, budget and fallback.

One `JudgeSession` reviews one package in one independent conversation. The model answers each turn with one
tool call; code executes it and answers with `accepted`/`rejected` plus the broken rule. Limits (JUE-02): at most
`max_calls` tool calls and `max_rejections` rejected reasons, after which the review closes with the reasons
accepted so far (`partial_review`). An answer that breaks the tool's format is retried with only the error and is
logged in `calls` as an `error` with rule VAL-02; it does not count as a tool call. Any provider failure, or format
errors beyond the retry policy, falls back to `final = base` with `no_judge_review` (L11, EVA-04). The judge never
touches iTop or Slack (L8).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import date
from decimal import Decimal
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol

from core.judge.budget import DailyBudget, ModelPrice, complexity, token_cap
from core.judge.catalog import MORE_CRITICAL_ASSET, JudgeSettings, ReasonCatalog, SensitivityProfile
from core.judge.mitigation import MitigationResult, validate_mitigation
from core.judge.package import ReviewPackage
from core.judge.prompt import MODE1_TOOLS, PROMPT_VERSION, PromptVersions, system_prompt, user_message, versions
from core.judge.rules import AcceptedReason, ReasonProposal, RuleContext, check_reason

if TYPE_CHECKING:
    from core.judge.mode2 import AlertDecision

from core.llm import (
    LlmError,
    LlmResponseError,
    LlmTransportError,
    ToolArgumentsError,
    ToolCall,
    ToolDefinition,
    Usage,
    load_tools,
)

MAX_SUMMARY_CHARS = 1500
ToolResult = tuple[dict[str, Any], str | None, str | None]  # answer to the model, broken rule, reason
LADDER_SUGGESTION = 2  # docs/07 §8 level 2: adjustments are shown as a suggestion, not applied (TODO(P-006))
LADDER_OFF = 3  # level 3: final = base


class ReviewStatus(StrEnum):
    APPLIED = "applied"
    SUGGESTION = "suggestion"
    PARTIAL_REVIEW = "partial_review"
    JUDGE_DISAGREEMENT = "judge_disagreement"
    NO_JUDGE_REVIEW = "no_judge_review"


class Failure(StrEnum):
    TRANSPORT = "transport"
    REQUEST = "request"
    FORMAT = "format"
    BUDGET = "budget"
    LADDER = "ladder"
    LIMIT = "limit"


class ToolCaller(Protocol):
    def call_tool(
        self,
        *,
        model: str,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[ToolDefinition],
        force_tool: str | None = None,
    ) -> ToolCall: ...


@dataclass(frozen=True)
class CallRecord:
    """One entry of `calls` in the audit record (schemas/audit_record.schema.json)."""

    n: int
    tool: str
    args: Mapping[str, Any]
    result: str  # ok · accepted · rejected · error
    rule: str | None = None
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "n": self.n,
            "tool": self.tool,
            "args": dict(self.args),
            "result": self.result,
            "rule": self.rule,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ReasonRecord:
    """A proposed reason and what code decided (one `judge_reason` row)."""

    seq: int
    code: str
    points: int  # applied points if accepted, proposed points otherwise
    evidence_id: str
    quote: str
    status: str  # accepted · rejected · withdrawn
    rule: str | None = None
    ci_id: str | None = None
    reason_id: str | None = None


@dataclass(frozen=True)
class ReviewOutcome:
    status: ReviewStatus
    adjustment: int | None  # group adjustment; None means no judge review (final = base)
    ci_adjustments: Mapping[str, int]
    reasons: tuple[ReasonRecord, ...]
    calls: tuple[CallRecord, ...]
    summary: str | None
    mitigation: MitigationResult
    usage: Usage
    cost_usd: Decimal
    latency_ms: int
    attempts: int
    model: str
    response_model: str | None
    versions: PromptVersions
    parameters: Mapping[str, Any]
    ladder_level: int
    failure: Failure | None = None
    out_of_range: bool = False
    cites_suspicious: bool = False
    mode: str = "scoring"  # llm_review.mode: scoring (mode 1) or dismissals (mode 2)
    alert: AlertDecision | None = None  # mode 2: the validated alert, if the judge proposed one
    dismissal: str | None = None  # mode 2: the reason the news does not apply, if dismissed


def _never_active(_cve: str) -> bool:
    return False


@dataclass(frozen=True)
class JudgeEnvironment:
    """Everything a review depends on besides the model and the package (the test seams of docs/planes/f6.md)."""

    catalog: ReasonCatalog
    profile: SensitivityProfile
    settings: JudgeSettings
    today: date
    daily_budget: DailyBudget  # required: a wiring mistake must not silently disable L12
    price: ModelPrice  # required: cost_usd feeds the daily budget (llm_usage_daily)
    active_cve: Callable[[str], bool] = _never_active
    ladder_level: int = 0
    clock: Callable[[], float] = time.monotonic


@dataclass(frozen=True)
class Decision:
    adjustment: int | None
    ci_adjustments: Mapping[str, int]
    summary: str | None
    mitigation: MitigationResult
    out_of_range: bool = False
    cites_suspicious: bool = False


_NO_DECISION = Decision(None, {}, None, MitigationResult.absent())
MAX_STORED_POINTS = 1000  # rejected proposals keep their points (smallint column); the raw value stays in calls


@dataclass
class _State:
    accepted: list[AcceptedReason] = field(default_factory=list)
    records: list[ReasonRecord] = field(default_factory=list)
    calls: list[CallRecord] = field(default_factory=list)  # tool calls and format errors, in order (F6.1 #70)
    tool_calls: int = 0  # JUE-02 counts only the tool calls code executed, not the format errors
    rejections: int = 0
    finalized: tuple[str, MitigationResult] | None = None


class JudgeSession:
    """Mode 1 (scoring). Subclasses change the tools, the prompt, the handlers and how the review closes."""

    MODE = "scoring"
    PROMPT_VERSION = PROMPT_VERSION
    TOOL_NAMES: tuple[str, ...] = MODE1_TOOLS

    def __init__(
        self,
        caller: ToolCaller,
        package: ReviewPackage,
        env: JudgeEnvironment,
        tools: Mapping[str, ToolDefinition] | None = None,
    ) -> None:
        self._caller = caller
        self._package = package
        self._env = env
        self._settings = env.settings
        self._ctx = RuleContext(package, env.catalog, env.profile, env.today, env.active_cve)
        all_tools = tools or load_tools()
        self._tools = [all_tools[name] for name in self.TOOL_NAMES]
        self._system = self._system_prompt()
        self._versions = versions(self._system, prompt_version=self.PROMPT_VERSION)
        self._cap = token_cap(package, env.settings.token_caps)
        self._usage = Usage()
        self._attempts = 0
        self._response_model: str | None = None
        self._state = _State()
        self._started = 0.0

    # --- hooks for other modes -------------------------------------------------------------------------------
    def _system_prompt(self) -> str:
        return system_prompt(self._env.catalog, self._env.profile, self._env.settings)

    def _handlers(self) -> Mapping[str, Callable[[Mapping[str, Any]], ToolResult]]:
        return {
            "read_element": self._read_element,
            "propose_reason": self._propose_reason,
            "withdraw_reason": self._withdraw_reason,
            "finalize_review": self._finalize_review,
        }

    def _finished(self) -> bool:
        return self._state.finalized is not None

    # --- public ----------------------------------------------------------------------------------------------
    def run(self) -> ReviewOutcome:
        self._started = self._env.clock()
        if self._env.ladder_level >= LADDER_OFF:
            return self._fallback(Failure.LADDER)
        if not self._env.daily_budget.allows(critical=self._package.is_critical):
            return self._fallback(Failure.BUDGET)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self._system},
            {"role": "user", "content": user_message(self._package.compact_view())},
        ]
        return self._loop(messages)

    # --- loop ------------------------------------------------------------------------------------------------
    def _loop(self, messages: list[dict[str, Any]]) -> ReviewOutcome:
        format_failures = 0
        last_error: str | None = None
        last_turn_tokens = 0
        state = self._state
        while True:
            if state.tool_calls >= self._settings.max_calls or state.rejections >= self._settings.max_rejections:
                return self._close(self._partial_status(), Failure.LIMIT)
            if self._attempts and not self._can_afford(last_turn_tokens):  # every turn after the first, even retries
                return self._close(self._partial_status(), Failure.BUDGET)
            try:
                call = self._caller.call_tool(model=self._settings.model, messages=messages, tools=self._tools)
            except (ToolArgumentsError, LlmResponseError) as exc:
                self._attempts += 1
                self._usage = self._usage + exc.usage
                last_turn_tokens = exc.usage.input + exc.usage.output + exc.usage.reasoning
                format_failures += 1
                error = str(exc)
                self._record_format_error(exc, error)
                if format_failures > self._settings.format_retries or error == last_error:
                    return self._fallback(Failure.FORMAT)
                last_error = error
                messages.append({"role": "user", "content": f"Respuesta no válida: {error}. Llama una herramienta."})
                continue
            except LlmTransportError:
                return self._fallback(Failure.TRANSPORT)
            except LlmError:  # LlmRequestError and any other client error
                return self._fallback(Failure.REQUEST)
            self._attempts += 1
            self._usage = self._usage + call.usage
            self._response_model = call.response_model or self._response_model
            last_turn_tokens = call.usage.input + call.usage.output + call.usage.reasoning
            result = self._dispatch(call)
            if self._finished():
                return self._close(self._finished_status(), None)
            messages.append(_assistant(call))
            messages.append(
                {"role": "tool", "tool_call_id": call.call_id, "content": json.dumps(result, ensure_ascii=False)}
            )

    def _can_afford(self, last_turn_tokens: int) -> bool:
        """Checked between turns: the next turn (estimated as the last one) must fit the cap and the day."""
        used = self._usage.input + self._usage.output + self._usage.reasoning
        fits = used + last_turn_tokens <= self._cap
        pending = self._env.price.cost(self._usage)  # this review is stored only when it closes
        return fits and self._env.daily_budget.allows(critical=self._package.is_critical, pending_usd=pending)

    def _partial_status(self) -> ReviewStatus:
        """Ladder level 2 shows any adjustment as a suggestion, partial or not (docs/07 §8)."""
        return ReviewStatus.SUGGESTION if self._env.ladder_level >= LADDER_SUGGESTION else ReviewStatus.PARTIAL_REVIEW

    def _finished_status(self) -> ReviewStatus:
        return ReviewStatus.SUGGESTION if self._env.ladder_level >= LADDER_SUGGESTION else ReviewStatus.APPLIED

    def _record_format_error(self, exc: LlmError, error: str) -> None:
        """F6.1 #70: an answer that broke the tool's format is an `error` entry of `calls` with rule VAL-02, so the
        audit shows every invalid answer (the model's raw output is never stored: only the error, with field paths)."""
        tool = exc.tool_name if isinstance(exc, ToolArgumentsError) else ""
        self._state.calls.append(CallRecord(len(self._state.calls) + 1, tool, {}, "error", "VAL-02", error))

    # --- tools -----------------------------------------------------------------------------------------------
    def _dispatch(self, call: ToolCall) -> dict[str, Any]:
        result, rule, reason = self._handlers()[call.name](call.arguments)
        self._state.tool_calls += 1
        self._state.calls.append(
            CallRecord(len(self._state.calls) + 1, call.name, call.arguments, str(result["result"]), rule, reason)
        )
        return result

    def _read_element(self, args: Mapping[str, Any]) -> ToolResult:
        element = self._package.elements.get(str(args["element_id"]))
        if element is None:
            reason = "El elemento no existe en este paquete."
            return {"result": "error", "rule": "L5.element", "reason": reason}, "L5.element", reason
        return {"result": "ok", "element_id": element.element_id, "text": element.text}, None, None

    def _propose_reason(self, args: Mapping[str, Any]) -> ToolResult:
        state = self._state
        seq = len(state.records) + 1
        if type(args["points"]) is not int:  # E8: 1e1 parses as 10.0, which JSON Schema still calls an integer
            return self._rejected(args, seq, "L7.points", "Los puntos deben ser un entero.")
        proposal = ReasonProposal.from_arguments(args)
        verdict = check_reason(proposal, state.accepted, self._ctx)
        if not verdict.accepted:
            return self._rejected(args, seq, str(verdict.rule), str(verdict.reason))
        reason_id = f"r{seq}"
        state.accepted.append(
            AcceptedReason(
                reason_id=reason_id,
                code=proposal.reason_code,
                proposed_points=proposal.points,
                points=verdict.points,
                evidence_id=proposal.evidence_id,
                quote=proposal.quote,
                ci_id=verdict.ci_id,
                out_of_range=verdict.out_of_range,
                cites_suspicious=verdict.cites_suspicious,
            )
        )
        state.records.append(
            ReasonRecord(
                seq,
                proposal.reason_code,
                verdict.points,
                proposal.evidence_id,
                proposal.quote,
                "accepted",
                ci_id=verdict.ci_id,
                reason_id=reason_id,
            )
        )
        result = {"result": "accepted", "proposed_reason_id": reason_id, "applied_points": verdict.points}
        return result, None, None

    def _rejected(self, args: Mapping[str, Any], seq: int, rule: str, reason: str) -> ToolResult:
        state = self._state
        state.rejections += 1
        points = args["points"]
        code = str(args["reason_code"])
        cited = self._package.elements.get(str(args["evidence_id"]))
        state.records.append(
            ReasonRecord(
                seq,
                code,
                max(-MAX_STORED_POINTS, min(MAX_STORED_POINTS, points)) if type(points) is int else 0,
                str(args["evidence_id"]),
                str(args["quote"]),
                "rejected",
                rule=rule,
                # judge_reason needs the asset of a more_critical_asset row, even a rejected one
                ci_id=cited.ci_id if cited is not None and code == MORE_CRITICAL_ASSET else None,
            )
        )
        return {"result": "rejected", "rule": rule, "reason": reason}, rule, reason

    def _withdraw_reason(self, args: Mapping[str, Any]) -> ToolResult:
        state = self._state
        reason_id = str(args["proposed_reason_id"])
        match = next((r for r in state.accepted if r.reason_id == reason_id), None)
        if match is None:
            reason = "No hay un motivo aceptado con ese identificador."
            return {"result": "error", "rule": "L4", "reason": reason}, "L4", reason
        state.accepted.remove(match)
        state.records = [
            replace(record, status="withdrawn") if record.reason_id == reason_id else record for record in state.records
        ]
        return {"result": "ok", "withdrawn": reason_id}, None, None

    def _finalize_review(self, args: Mapping[str, Any]) -> ToolResult:
        summary = str(args["summary"]).strip()
        if not summary or len(summary) > MAX_SUMMARY_CHARS:
            reason = "El resumen debe tener entre 1 y 3 frases."
            return {"result": "error", "rule": "VAL-02", "reason": reason}, "VAL-02", reason
        mitigation = validate_mitigation(args["mitigation_steps"], self._package)
        self._state.finalized = (summary, mitigation)
        return {"result": "ok"}, mitigation.rule, None

    # --- outcomes --------------------------------------------------------------------------------------------
    def _close(self, status: ReviewStatus, failure: Failure | None) -> ReviewOutcome:
        state = self._state
        group = sum(r.points for r in state.accepted if r.ci_id is None)
        per_ci: dict[str, int] = {}
        for reason in state.accepted:
            if reason.ci_id is not None:
                per_ci[reason.ci_id] = per_ci.get(reason.ci_id, 0) + reason.points
        summary, mitigation = state.finalized or (None, MitigationResult.absent())
        decision = Decision(
            adjustment=group,
            ci_adjustments=per_ci,
            summary=summary,
            mitigation=mitigation,
            out_of_range=any(r.out_of_range for r in state.accepted),
            cites_suspicious=any(r.cites_suspicious for r in state.accepted),
        )
        return self._outcome(status, failure, decision)

    def _fallback(self, failure: Failure) -> ReviewOutcome:
        """L11 / EVA-04: final = base, no drafted mitigation (JUE-MIT-09)."""
        return self._outcome(ReviewStatus.NO_JUDGE_REVIEW, failure, _NO_DECISION)

    def _outcome(self, status: ReviewStatus, failure: Failure | None, decision: Decision) -> ReviewOutcome:
        return self._base_outcome(status, failure, decision)

    def _base_outcome(self, status: ReviewStatus, failure: Failure | None, decision: Decision) -> ReviewOutcome:
        return ReviewOutcome(
            status=status,
            adjustment=decision.adjustment,
            ci_adjustments=decision.ci_adjustments,
            reasons=tuple(self._state.records),
            calls=tuple(self._state.calls),
            summary=decision.summary,
            mitigation=decision.mitigation,
            usage=self._usage,
            cost_usd=self._env.price.cost(self._usage),
            latency_ms=max(0, round((self._env.clock() - self._started) * 1000)),
            attempts=self._attempts,
            model=self._settings.model,
            response_model=self._response_model,
            versions=self._versions,
            parameters={
                "max_calls": self._settings.max_calls,
                "max_rejections": self._settings.max_rejections,
                "reasoning_mode": False,  # TODO(P-017): only with the complex budget
                "budget_class": complexity(self._package),
                "token_cap": self._cap,
                "profile": self._env.profile.name.value,
            },
            ladder_level=self._env.ladder_level,
            failure=failure,
            out_of_range=decision.out_of_range,
            cites_suspicious=decision.cites_suspicious,
            mode=self.MODE,
        )


def _assistant(call: ToolCall) -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": call.call_id,
                "type": "function",
                "function": {"name": call.name, "arguments": json.dumps(call.arguments, ensure_ascii=False)},
            }
        ],
    }
