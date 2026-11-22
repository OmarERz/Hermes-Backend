"""The strict client returns the tool call id, the response model and the token usage the judge audits (L13)."""

from __future__ import annotations

from typing import Any

import pytest

from core.llm import Usage, load_tools
from doubles.llm import LlmDouble, tool_call_completion
from harness.judge import double_llm_client

pytestmark = pytest.mark.unit
TOOLS = [load_tools()["read_element"]]


def call(completion: dict[str, Any]) -> Any:
    double = LlmDouble()
    double.add_case("c", [completion])
    double.use("c")
    return double_llm_client(double).call_tool(model="m", messages=[{"role": "user", "content": "x"}], tools=TOOLS)


def test_openai_style_usage_details() -> None:
    completion = tool_call_completion("read_element", {"element_id": "cve-1"}, call_id="call_9", model="deepseek-x")
    completion["usage"] = {
        "prompt_tokens": 100,
        "completion_tokens": 30,
        "total_tokens": 130,
        "prompt_tokens_details": {"cached_tokens": 60},
        "completion_tokens_details": {"reasoning_tokens": 10},
    }
    result = call(completion)
    assert result.call_id == "call_9"
    assert result.response_model == "deepseek-x"
    assert result.usage == Usage(input=100, cached_input=60, output=20, reasoning=10)


def test_deepseek_cache_hit_field_and_missing_usage() -> None:
    completion = tool_call_completion("read_element", {"element_id": "cve-1"})
    completion["usage"] = {
        "prompt_tokens": 50,
        "completion_tokens": 5,
        "total_tokens": 55,
        "prompt_cache_hit_tokens": 20,
    }
    assert call(completion).usage == Usage(input=50, cached_input=20, output=5, reasoning=0)
    no_usage = tool_call_completion("read_element", {"element_id": "cve-1"})
    del no_usage["usage"]
    assert call(no_usage).usage == Usage()


def test_usage_adds_up() -> None:
    assert Usage(1, 2, 3, 4) + Usage(10, 20, 30, 40) == Usage(11, 22, 33, 44)
