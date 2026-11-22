"""Keyword matching rules without a database."""

from __future__ import annotations

import pytest

from core.ingestion.keywords import KeywordSet, name_variants


def test_name_variants_strip_trailing_versions() -> None:
    assert name_variants("OpenSSL 3.0.7") == {"openssl 3.0.7", "openssl"}
    assert name_variants("Apache_HTTP_Server v2.4") == {"apache http server v2.4", "apache http server"}
    assert name_variants("Go") == set()  # too short to be a useful term
    assert name_variants("nginx") == {"nginx"}


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("A flaw in OpenSSL was fixed", True),
        ("openssl-based tooling", True),  # a hyphen is a boundary
        ("Fixes in mopenssl and opensslx", False),
        ("Globex Corp confirmed an incident", True),
        ("Clínica privada afectada", True),
        ("Nothing relevant happened", False),
        ("See cve-2026-10001 for details", True),
    ],
)
def test_matching(text: str, expected: bool) -> None:
    keywords = KeywordSet(terms=frozenset({"openssl", "globex corp", "clínica"}), cves=frozenset({"CVE-2026-10001"}))
    assert keywords.matches(text) is expected


def test_empty_sets_match_nothing() -> None:
    assert not KeywordSet(frozenset(), frozenset()).matches("OpenSSL CVE-2026-10001")
