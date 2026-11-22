"""Deterministic double of an OpenAI-compatible chat completions API (DeepSeek, CAL-03/CAL-04).

It is an httpx transport: pass `double.client()` as `http_client=` to the `openai` SDK client and no byte leaves
the machine. Responses are recorded tool-call (or text) completions grouped by case name; each request consumes
the next response of the active case, and a request with no response left is answered with HTTP 500 and counted
in `unexpected_calls`, so a test can assert that the code made no extra calls.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import httpx

FIXTURES: Final = Path(__file__).resolve().parents[1] / "fixtures" / "llm"
CHAT_PATH_SUFFIX: Final = "/chat/completions"

Completion = dict[str, Any]


def tool_call_completion(
    name: str, arguments: Mapping[str, Any], *, call_id: str = "call_1", model: str = "double-model"
) -> Completion:
    """A completion in which the model calls one tool (the arguments are serialized to a JSON string)."""
    return _completion(
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {"id": call_id, "type": "function", "function": {"name": name, "arguments": json.dumps(arguments)}}
            ],
        },
        "tool_calls",
        model,
    )


def text_completion(text: str, *, model: str = "double-model") -> Completion:
    return _completion({"role": "assistant", "content": text}, "stop", model)


def _completion(message: Completion, finish_reason: str, model: str) -> Completion:
    return {
        "id": "chatcmpl-double",
        "object": "chat.completion",
        "created": 1760000000,
        "model": model,
        "choices": [{"index": 0, "finish_reason": finish_reason, "message": message}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


@dataclass(frozen=True)
class RecordedRequest:
    """One request received: the case that answered it, the JSON body and the model asked for."""

    case: str | None
    body: Completion

    @property
    def model(self) -> str | None:
        model = self.body.get("model")
        return str(model) if model is not None else None


@dataclass
class LlmDouble:
    cases: dict[str, list[Completion]] = field(default_factory=dict)
    active: str | None = None
    requests: list[RecordedRequest] = field(default_factory=list)
    unexpected_calls: int = 0
    _cursor: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.transport = httpx.MockTransport(self._handle)

    @classmethod
    def from_fixtures(cls, directory: Path = FIXTURES) -> LlmDouble:
        """Load every `*.json` file of recorded responses: `{"case": name, "responses": [completion, ...]}`."""
        double = cls()
        for path in sorted(directory.glob("*.json")):
            recorded = json.loads(path.read_text(encoding="utf-8"))
            double.add_case(recorded["case"], recorded["responses"])
        return double

    def add_case(self, name: str, responses: Sequence[Completion]) -> None:
        self.cases[name] = list(responses)
        self._cursor[name] = 0

    def use(self, name: str) -> None:
        """Select the case that answers the next requests, restarting it from its first response."""
        if name not in self.cases:
            raise KeyError(f"unknown LLM double case: {name!r}")
        self.active = name
        self._cursor[name] = 0

    def client(self) -> httpx.Client:
        return httpx.Client(transport=self.transport, base_url="http://llm.test/v1", timeout=httpx.Timeout(5.0))

    @property
    def call_count(self) -> int:
        return len(self.requests)

    def assert_calls(self, expected: int) -> None:
        assert len(self.requests) == expected, f"expected {expected} LLM calls, got {len(self.requests)}"
        assert self.unexpected_calls == 0, f"{self.unexpected_calls} call(s) had no recorded response left"

    def _handle(self, request: httpx.Request) -> httpx.Response:
        if not request.url.path.endswith(CHAT_PATH_SUFFIX):
            return httpx.Response(404, json={"error": {"message": "not found"}})
        self.requests.append(RecordedRequest(self.active, json.loads(request.content)))
        if self.active is None:
            self.unexpected_calls += 1
            return httpx.Response(500, json={"error": {"message": "no case selected in the LLM double"}})
        responses = self.cases[self.active]
        index = self._cursor[self.active]
        if index >= len(responses):
            self.unexpected_calls += 1
            return httpx.Response(500, json={"error": {"message": f"case {self.active!r} has no response left"}})
        self._cursor[self.active] = index + 1
        return httpx.Response(200, json=responses[index])
