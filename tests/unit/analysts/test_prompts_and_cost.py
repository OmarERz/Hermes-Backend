"""Prompt construction and token cost of the analysts."""

from __future__ import annotations

from decimal import Decimal

from core.analysts import prompt
from core.analysts.runner import cost_usd
from core.llm.usage import Usage


def test_the_news_message_delimits_the_data_with_a_random_token_per_request() -> None:
    first = prompt.news_user_message("s1", "thn", "2026-11-22", "Title", "Body text")
    second = prompt.news_user_message("s1", "thn", "2026-11-22", "Title", "Body text")
    assert "En news_id devuelve exactamente: s1" in first
    assert first != second  # the delimiter token changes, so a text cannot close it by guessing
    token = first.split("<<<NOTICIA ")[1].split(">>>")[0]
    assert f"<<<FIN {token}>>>" in first


def test_long_text_is_cut_and_the_system_prompt_holds_no_external_content() -> None:
    message = prompt.news_user_message("s1", "thn", "d", "T", "Z" * (prompt.MAX_ARTICLE_CHARS + 500))
    assert message.count("Z") == prompt.MAX_ARTICLE_CHARS
    assert "<<<" not in prompt.NEWS_SYSTEM.replace("<<<NOTICIA ...>>>", "").replace("<<<FIN ...>>>", "")
    assert "<<<CVE" in prompt.cve_user_message("CVE-2026-1", "material")


def test_the_retry_message_carries_only_the_errors() -> None:
    assert "VAL-03.quote at q: bad" in prompt.retry_message("VAL-03.quote at q: bad")


def test_versions_are_hashes_of_the_fixed_prompt() -> None:
    first = prompt.fingerprint("v1", "system", "1", "h")
    assert first == prompt.fingerprint("v1", "system", "1", "h")
    assert first.prompt_hash != prompt.fingerprint("v1", "system 2", "1", "h").prompt_hash


def test_cost_counts_cached_input_at_its_own_price_and_reasoning_as_output() -> None:
    assert cost_usd(Usage()) == Decimal("0")
    usage = Usage(input=1_000_000, cached_input=500_000, output=100_000, reasoning=100_000)
    assert cost_usd(usage) == Decimal("0.14") + Decimal("0.014") + Decimal("0.084")
