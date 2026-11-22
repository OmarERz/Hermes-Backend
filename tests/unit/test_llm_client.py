"""Strict-mode LLM client against a deterministic fake transport (no network, no tokens)."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx2
import pytest
from pydantic import SecretStr

from core.config import Settings
from core.llm import (
    LlmClient,
    LlmRequestError,
    LlmResponseError,
    LlmTransportError,
    RetryPolicy,
    ToolArgumentsError,
    ToolDefinition,
    ToolDefinitionError,
    load_tools,
    make_tool,
)
from core.llm.tools import SCHEMAS_DIR_ENV, check_strict_compatible, default_schemas_dir

pytestmark = pytest.mark.unit

API_KEY = "unit-test-key-" + "a" * 16  # low-entropy fake value
URL = "https://llm.example.test/beta"

DEFINITION: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "submit_result",
        "description": "Submit a result.",
        "strict": True,
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "required": ["verdict", "score"],
            "properties": {"verdict": {"type": "string", "enum": ["yes", "no"]}, "score": {"type": "integer"}},
        },
    },
}
TOOL = make_tool(DEFINITION)


def completion(name: str = "submit_result", arguments: str = '{"verdict": "yes", "score": 3}') -> dict[str, Any]:
    """A recorded-style chat completion with one tool call."""
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 1,
        "model": "test-model",
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {"id": "call_1", "type": "function", "function": {"name": name, "arguments": arguments}}
                    ],
                },
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


class Server:
    """Fake provider: answers from a script of handlers, one per request, and records the requests."""

    def __init__(self, *script: Callable[[httpx2.Request], httpx2.Response]) -> None:
        self.script = list(script)
        self.requests: list[httpx2.Request] = []
        self.sleeps: list[float] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        return self.script.pop(0)(request)

    def client(self, *, attempts: int = 3) -> LlmClient:
        retry = RetryPolicy(max_attempts=attempts, sleep=self.sleeps.append, jitter=lambda: 1.0)
        return LlmClient(
            base_url=URL,
            api_key=SecretStr(API_KEY),
            retry=retry,
            http_client=httpx2.Client(transport=httpx2.MockTransport(self)),
        )


def ok(body: dict[str, Any] | None = None) -> Callable[[httpx2.Request], httpx2.Response]:
    return lambda _r: httpx2.Response(200, json=body or completion())


def status(code: int, headers: dict[str, str] | None = None, text: str = "{}") -> Callable[[Any], httpx2.Response]:
    return lambda _r: httpx2.Response(code, headers=headers, text=text)


def call(client: LlmClient, force: str | None = None) -> Any:
    return client.call_tool(
        model="test-model", messages=[{"role": "user", "content": "hi"}], tools=[TOOL], force_tool=force
    )


def test_shipped_tools_load_and_are_strict_compatible() -> None:
    tools = load_tools()
    assert {"submit_news_analysis", "submit_cve_analysis", "read_element", "finalize_review"} <= set(tools)
    assert len(tools) == 8
    assert all(t.definition["function"]["strict"] is True for t in tools.values())


def test_call_sends_strict_tools_and_returns_validated_arguments() -> None:
    server = Server(ok())
    result = call(server.client(), force="submit_result")
    assert (result.name, result.arguments) == ("submit_result", {"verdict": "yes", "score": 3})
    request = server.requests[0]
    body = json.loads(request.content)
    assert str(request.url) == f"{URL}/chat/completions"
    assert request.headers["authorization"] == f"Bearer {API_KEY}"
    assert body["model"] == "test-model"
    assert body["tools"][0]["function"]["strict"] is True
    assert body["tools"][0]["function"]["parameters"]["additionalProperties"] is False
    assert body["tool_choice"] == {"type": "function", "function": {"name": "submit_result"}}
    assert body["thinking"] == {"type": "disabled"}  # forced tool choices fail with thinking on


def test_tool_choice_defaults_to_required() -> None:
    server = Server(ok())
    call(server.client())
    body = json.loads(server.requests[0].content)
    assert body["tool_choice"] == "required"
    assert body["thinking"] == {"type": "disabled"}


def test_arguments_that_do_not_match_the_schema_raise_without_echoing_values() -> None:
    server = Server(ok(completion(arguments='{"verdict": "SECRET-VALUE", "score": 1.5, "extra": 1}')))
    with pytest.raises(ToolArgumentsError) as caught:
        call(server.client())
    assert caught.value.tool_name == "submit_result"
    assert "verdict: enum" in caught.value.problems
    assert "SECRET-VALUE" not in str(caught.value)


@pytest.mark.parametrize(
    "body",
    [
        completion(arguments="not json"),
        completion(name="other_tool"),
        {**completion(), "choices": []},
        {
            **completion(),
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "x"}}],
        },
    ],
    ids=["bad-json", "unknown-tool", "no-choices", "no-tool-call"],
)
def test_unexpected_responses_raise_response_error(body: dict[str, Any]) -> None:
    with pytest.raises(LlmResponseError):
        call(Server(ok(body)).client())


def test_forced_tool_mismatch_and_multiple_calls_are_rejected() -> None:
    other = make_tool({**DEFINITION, "function": {**DEFINITION["function"], "name": "other_tool"}})
    server = Server(ok(completion(name="other_tool")))
    with pytest.raises(LlmResponseError):
        server.client().call_tool(model="m", messages=[], tools=[TOOL, other], force_tool="submit_result")
    two = completion()
    two["choices"][0]["message"]["tool_calls"] *= 2
    with pytest.raises(LlmResponseError):
        call(Server(ok(two)).client())


def test_transport_errors_are_retried_with_backoff_and_retry_after() -> None:
    server = Server(status(500), status(429, {"retry-after": "7"}), ok())
    assert call(server.client()).arguments["score"] == 3
    assert len(server.requests) == 3
    assert server.sleeps == [1.0, 7.0]


def test_connection_error_is_retried_then_reported_after_bounded_attempts() -> None:
    def boom(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("refused", request=request)

    server = Server(boom, boom, boom)
    with pytest.raises(LlmTransportError, match="3 attempts"):
        call(server.client())
    assert len(server.requests) == 3
    assert len(server.sleeps) == 2


def test_retry_after_is_capped_and_ignores_http_dates() -> None:
    server = Server(
        status(429, {"retry-after": "9999"}), status(503, {"retry-after": "Wed, 21 Oct 2026 07:28:00 GMT"}), ok()
    )
    call(server.client())
    assert server.sleeps == [60.0, 2.0]


def test_client_errors_are_not_retried() -> None:
    server = Server(status(400, text='{"error": {"message": "bad request"}}'))
    with pytest.raises(LlmRequestError, match="status 400"):
        call(server.client())
    assert len(server.requests) == 1


def test_api_key_never_appears_in_exceptions_or_logs(caplog: pytest.LogCaptureFixture) -> None:
    echo = status(401, text=json.dumps({"error": {"message": f"Incorrect API key provided: {API_KEY}"}}))
    server = Server(echo, status(500, text=API_KEY), status(500, text=API_KEY), status(500, text=API_KEY))
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(LlmRequestError) as rejected:
            call(server.client())
        with pytest.raises(LlmTransportError) as failed:
            call(server.client())
    for text in (str(rejected.value), repr(rejected.value), str(failed.value), repr(failed.value), caplog.text):
        assert API_KEY not in text


def test_from_settings_uses_role_base_url_and_requires_a_key() -> None:
    base: dict[str, Any] = {
        "_env_file": None,
        "database_url": SecretStr("postgresql://a:b@db/h"),
        "firebase_project_id": "p",
        "cursor_signing_key": SecretStr("k" * 40),
    }
    with pytest.raises(LlmRequestError, match="not configured"):
        LlmClient.from_settings(Settings(**base), "judge")  # type: ignore[arg-type]
    settings = Settings(  # type: ignore[call-arg]
        **base, deepseek_api_key=SecretStr(API_KEY), llm_base_url_analysts="http://localhost:11434/v1"
    )
    judge = LlmClient.from_settings(settings, "judge")
    analysts = LlmClient.from_settings(settings, "analysts")
    assert str(judge._client.base_url) == "https://api.deepseek.com/beta/"
    assert str(analysts._client.base_url) == "http://localhost:11434/v1/"
    assert judge._client.max_retries == 0


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d["function"].update(strict=False), "strict: true"),
        (lambda d: d["function"]["parameters"].update(additionalProperties=True), "additionalProperties"),
        (lambda d: d["function"]["parameters"]["required"].pop(), "required"),
        (lambda d: d["function"]["parameters"]["properties"]["verdict"].update(maxLength=3), "maxLength"),
        (lambda d: d["function"]["parameters"]["properties"]["score"].update(minItems=1), "minItems"),
        (lambda d: d.update(type="other"), "function tool"),
    ],
)
def test_make_tool_rejects_definitions_strict_mode_cannot_take(
    mutate: Callable[[dict[str, Any]], Any], message: str
) -> None:
    definition = json.loads(json.dumps(DEFINITION))
    mutate(definition)
    with pytest.raises(ToolDefinitionError, match=message):
        make_tool(definition)


def test_nested_objects_and_lists_are_checked() -> None:
    nested = {"type": "array", "items": {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"]}}
    with pytest.raises(ToolDefinitionError, match="additionalProperties"):
        check_strict_compatible("t", {"anyOf": [nested]})


def test_load_tools_rejects_missing_and_duplicate_files(tmp_path: Any) -> None:
    with pytest.raises(ToolDefinitionError, match="not found"):
        load_tools(tmp_path)
    (tmp_path / "judge_tools.json").write_text(json.dumps([DEFINITION, DEFINITION]))
    with pytest.raises(ToolDefinitionError, match="duplicate"):
        load_tools(tmp_path)


def test_tool_definition_exposes_parameters() -> None:
    assert isinstance(TOOL, ToolDefinition)
    assert TOOL.parameters["required"] == ["verdict", "score"]


def test_schemas_dir_resolves_from_the_environment_or_the_source_tree(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    monkeypatch.delenv(SCHEMAS_DIR_ENV, raising=False)
    assert (default_schemas_dir() / "judge_tools.json").is_file()
    monkeypatch.setenv(SCHEMAS_DIR_ENV, str(tmp_path))
    assert default_schemas_dir() == tmp_path
    with pytest.raises(ToolDefinitionError, match="not found"):
        load_tools()  # resolved through the environment, like in the image
    (tmp_path / "judge_tools.json").write_text(json.dumps([DEFINITION]))
    assert set(load_tools()) == {"submit_result"}


def test_production_image_ships_the_schemas() -> None:
    """The image installs the project with --no-editable, so schemas/ must be copied and pointed to explicitly."""
    dockerfile = (Path(__file__).resolve().parents[2] / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY --chown=root:root schemas ./schemas" in dockerfile
    assert "SCHEMAS_DIR=/app/schemas" in dockerfile
