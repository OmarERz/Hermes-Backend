"""Identifiers and versions: digits of other scripts are never digits (F12.5)."""

from __future__ import annotations

import unicodedata

from hypothesis import assume, given
from hypothesis import strategies as st

from core.ingestion.entities import extract_cves
from core.inventory.version import normalize_version
from core.judge.rules import CVE_ID as JUDGE_CVE
from core.stix.export import CVE_ID as STIX_CVE
from core.vulndata.records import CVE_ID, CWE_ID

OTHER = "\u0660\u0661\u0662\u0663\u0664\u0966\u0967\u0968\u0e50\u0e51\uff10\uff11\uff12\uff13\u00b2\u00b3\u2460"
other_digits = st.text(alphabet=OTHER, min_size=1, max_size=7)
ascii_digits = st.text(alphabet="0123456789", min_size=4, max_size=7)
mixed = st.tuples(ascii_digits, st.integers(min_value=0, max_value=7), st.sampled_from(OTHER)).map(
    lambda t: t[0][: t[1]] + t[2] + t[0][t[1] :]  # a number with one foreign digit somewhere inside it, even last
)


@given(ascii_digits, ascii_digits)
def test_ascii_cve_identifiers_are_accepted_everywhere(year: str, number: str) -> None:
    cve = f"CVE-{year[:4]}-{number}"
    assert CVE_ID.match(cve) and STIX_CVE.match(cve) and JUDGE_CVE.findall(cve) == [cve]
    assert extract_cves(f"see {cve} now") == {cve}


@given(mixed, ascii_digits, st.sampled_from(["year", "number"]))
def test_other_scripts_never_make_a_cve_identifier(bad: str, good: str, where: str) -> None:
    cve = f"CVE-{bad[:4]}-{good}" if where == "year" else f"CVE-{good[:4]}-{bad}"
    assume(where != "year" or not bad[:4].isascii())  # the foreign digit must fall inside the year
    assert not CVE_ID.match(cve) and not STIX_CVE.match(cve)
    assert extract_cves(f"see {cve} now") == frozenset()
    if where == "number" and any(unicodedata.category(c) == "Nd" and not c.isascii() for c in bad):
        assert JUDGE_CVE.findall(cve) == []  # the ASCII prefix of a longer number is not another CVE
    assert JUDGE_CVE.findall("chain with CVE-2024-3400_PoC") == ["CVE-2024-3400"]


@given(ascii_digits, st.sampled_from(["\n", "\r\n", " ", "\x00"]))
def test_a_trailing_character_never_slips_past_the_anchor(number: str, tail: str) -> None:
    assert not CVE_ID.match(f"CVE-2026-{number}{tail}") and not CWE_ID.match(f"CWE-{number}{tail}")
    assert not STIX_CVE.match(f"CVE-2026-{number}{tail}")


@given(ascii_digits, other_digits)
def test_cwe_identifiers_use_ascii_digits_only(good: str, bad: str) -> None:
    assert CWE_ID.match(f"CWE-{good}")
    assert not CWE_ID.match(f"CWE-{bad}") and not CWE_ID.match(f"CWE-{good}{bad}")


@given(ascii_digits, other_digits)
def test_only_an_ascii_epoch_is_stripped_from_an_inventory_version(epoch: str, bad: str) -> None:
    stripped = normalize_version(f"{epoch}:1.2.3")
    assert stripped is not None and stripped.version == "1.2.3"
    kept = normalize_version(f"{bad}:1.2.3")
    assert kept is None or kept.version.startswith(bad)


@given(st.sampled_from(["el", "fc"]), st.sampled_from(OTHER))
def test_a_distribution_tag_with_a_foreign_digit_is_not_a_distribution_revision(tag: str, digit: str) -> None:
    kept = normalize_version(f"1.2.3-1.{tag}{digit}")
    assert kept is not None and kept.version == f"1.2.3-1.{tag}{digit}"
    stripped = normalize_version(f"1.2.3-1.{tag}9")
    assert stripped is not None and stripped.version == "1.2.3"
