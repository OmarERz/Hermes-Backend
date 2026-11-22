from __future__ import annotations

import json

import pytest
from openai import APIStatusError, OpenAI

from doubles.llm import LlmDouble, text_completion, tool_call_completion


def sdk(double: LlmDouble) -> OpenAI:
    return OpenAI(api_key="not-a-real-key", base_url="http://llm.test/v1", http_client=double.client(), max_retries=0)


def ask(client: OpenAI) -> object:
    return client.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])


def test_openai_sdk_receives_the_recorded_tool_call() -> None:
    double = LlmDouble()
    double.add_case("verdict", [tool_call_completion("submit_verdict", {"verdict": "confirm"})])
    double.use("verdict")
    completion = sdk(double).chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])
    call = completion.choices[0].message.tool_calls[0]  # type: ignore[index]
    assert call.function.name == "submit_verdict"
    assert json.loads(call.function.arguments) == {"verdict": "confirm"}
    double.assert_calls(1)
    assert double.requests[0].model == "m"
    assert double.requests[0].case == "verdict"


def test_responses_are_consumed_in_order_and_extra_calls_are_flagged() -> None:
    double = LlmDouble()
    double.add_case("two", [text_completion("one"), text_completion("two")])
    double.use("two")
    client = sdk(double)
    ask(client)
    ask(client)
    double.assert_calls(2)
    with pytest.raises(APIStatusError):
        ask(client)
    assert double.unexpected_calls == 1
    with pytest.raises(AssertionError):
        double.assert_calls(3)


def test_no_case_selected_is_an_error() -> None:
    double = LlmDouble()
    with pytest.raises(APIStatusError):
        ask(sdk(double))
    assert double.unexpected_calls == 1


def test_use_restarts_a_case_and_rejects_unknown_ones() -> None:
    double = LlmDouble()
    double.add_case("one", [text_completion("x")])
    double.use("one")
    ask(sdk(double))
    double.use("one")
    ask(sdk(double))
    double.assert_calls(2)
    with pytest.raises(KeyError):
        double.use("missing")


def test_recorded_fixtures_load() -> None:
    double = LlmDouble.from_fixtures()
    double.use("judge_tool_call")
    completion = ask(sdk(double))
    assert completion.choices[0].message.tool_calls[0].function.name == "submit_verdict"  # type: ignore[attr-defined]
    assert completion.usage.total_tokens == 150  # type: ignore[attr-defined]


def test_unknown_path_is_404() -> None:
    with LlmDouble().client() as client:
        assert client.post("/embeddings", json={}).status_code == 404
