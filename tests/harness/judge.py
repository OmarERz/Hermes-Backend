"""Synthetic review packages for the judge tests (schemas/review_package.schema.json; no third-party text)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from pydantic import SecretStr

from core.llm import LlmClient, RetryPolicy
from doubles.llm import LlmDouble

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "judge"


def finding_package(**overrides: Any) -> dict[str, Any]:
    """A fresh finding package (two CIs, one CVE element, an N3 and an N2 news item); top-level keys can be
    replaced through keyword arguments."""
    content: dict[str, Any] = json.loads((FIXTURES / "finding_package.json").read_text(encoding="utf-8"))
    content.update(copy.deepcopy(overrides))
    return content


def double_llm_client(double: LlmDouble) -> LlmClient:
    """The real strict-mode client wired to the deterministic LLM double (no network, one attempt per call)."""
    return LlmClient(
        base_url="http://llm.test/v1",
        api_key=SecretStr("unit-test-key-" + "b" * 16),
        http_client=double.client(),  # an httpx client; the SDK accepts it at runtime
        retry=RetryPolicy(max_attempts=1, sleep=lambda _s: None),
    )
