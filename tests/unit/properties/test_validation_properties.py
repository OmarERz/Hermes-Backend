"""Properties of the validation layer (VAL-02, VAL-03): limits hold, hostile values are never echoed."""

from __future__ import annotations

from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from core.scoring.cvss import parse_cvss31
from core.validation.content import (
    CVE_FORMAT,
    _mentions_cve,
    check_cve,
    check_cvss_vector,
    check_quote,
    cve_candidates,
    normalize_text,
    quote_in_text,
)
from core.validation.schema import (
    DEFAULT_MAX_CHARS,
    DEFAULT_MAX_ITEMS,
    MAX_CHARS_BY_FIELD,
    MAX_DEPTH,
    MAX_ITEMS_BY_FIELD,
    ToolSchema,
)
from core.validation.schema import validate_schema as validate

TOOL = {
    "type": "function",
    "function": {
        "name": "submit_test",
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "required": ["summary", "event_types"],
            "properties": {
                "summary": {"type": "string"},
                "notes": {"type": "string"},
                "event_types": {"type": "array", "items": {"type": "string"}},
                "tags": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
}
SCHEMA = ToolSchema.from_tool(TOOL, "1")
MARKER = "ZZSECRETMARKERZZ"  # in values: no value is ever copied
KEY_MARKER = "ZZ!SECRET!MARKER"  # in keys: only plain names (letters, digits, _) may be shown, anything else is `<key>`
json_values = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=False), st.text(max_size=30)),
    lambda children: st.one_of(
        st.lists(children, max_size=4), st.dictionaries(st.text(max_size=12), children, max_size=4)
    ),
    max_leaves=25,
)


@given(json_values)
def test_validation_never_raises_whatever_the_model_returns(output: Any) -> None:
    violations = validate(output, SCHEMA)
    assert isinstance(violations, list)


@given(st.dictionaries(st.text(max_size=12), st.text(max_size=20), max_size=5), st.text(max_size=5))
def test_hostile_keys_and_values_are_never_copied_into_the_feedback(extra: dict[str, str], noise: str) -> None:
    hostile = {f"{KEY_MARKER}{k}": f"{MARKER}{v}{noise}" for k, v in extra.items()}
    output = {"summary": MARKER * 200, "event_types": [MARKER * 100] * 300, **hostile}
    violations = validate(output, SCHEMA)
    assert violations
    for violation in violations:
        assert MARKER not in str(violation) and MARKER not in violation.code
        assert "!" not in str(violation) and "!" not in violation.code


@given(st.integers(min_value=0, max_value=3000))
def test_a_string_is_accepted_up_to_its_limit_and_refused_beyond(length: int) -> None:
    for field, cap in [("summary", MAX_CHARS_BY_FIELD["summary"]), ("notes", MAX_CHARS_BY_FIELD["notes"])]:
        violations = validate({"summary": "x", "event_types": [], field: "y" * length}, SCHEMA)
        over = [v for v in violations if v.code == "max_chars"]
        assert bool(over) is (length > cap)


@given(st.integers(min_value=0, max_value=400))
def test_a_list_is_accepted_up_to_its_limit_and_refused_beyond(count: int) -> None:
    short = validate({"summary": "x", "event_types": ["a"] * count}, SCHEMA)
    assert bool([v for v in short if v.code == "max_items"]) is (count > MAX_ITEMS_BY_FIELD["event_types"])
    other = validate({"summary": "x", "event_types": [], "tags": ["a"] * count}, SCHEMA)
    assert bool([v for v in other if v.code == "max_items"]) is (count > DEFAULT_MAX_ITEMS)


@given(st.integers(min_value=0, max_value=DEFAULT_MAX_CHARS + 50))
def test_an_unlisted_field_uses_the_default_limits(length: int) -> None:
    violations = validate({"summary": "x", "event_types": [], "tags": ["z" * length]}, SCHEMA)
    assert bool([v for v in violations if v.code == "max_chars"]) is (length > DEFAULT_MAX_CHARS)


@given(st.integers(min_value=1, max_value=60))
def test_a_structure_nested_deeper_than_the_limit_is_refused_without_recursing_over_it(depth: int) -> None:
    value: Any = "leaf"
    for _ in range(depth):
        value = {"x": value}
    violations = validate({"summary": "x", "event_types": [], "notes": value}, SCHEMA)
    if depth + 1 > MAX_DEPTH:
        assert [v.code for v in violations] == ["depth"]
    else:
        assert "depth" not in [v.code for v in violations]


@given(st.text(max_size=300))
def test_normalizing_text_is_idempotent_and_leaves_no_double_spaces(text: str) -> None:
    once = normalize_text(text)
    assert normalize_text(once) == once
    assert "  " not in once and once == once.strip()


@given(st.text(max_size=100), st.text(min_size=1, max_size=40), st.text(max_size=100))
def test_a_quote_copied_from_the_text_is_accepted_whatever_the_whitespace(before: str, quote: str, after: str) -> None:
    text = f"{before}{quote}{after}"
    if normalize_text(quote):
        assert quote_in_text(quote, text)
        assert check_quote(quote, text, "q") == []
        assert quote_in_text(" ".join(quote.split()), text)


@given(st.text(min_size=1, max_size=30), st.text(max_size=100))
def test_a_quote_that_is_not_in_the_text_is_refused(quote: str, text: str) -> None:
    if normalize_text(quote) not in normalize_text(text):
        assert check_quote(quote, text, "q")


@given(st.text(max_size=40))
def test_only_ascii_cve_identifiers_pass_the_format_check(value: str) -> None:
    accepted = not check_cve(value, "cve", lambda _cve: True)
    if accepted:
        year, number = value.split("-")[1:]
        assert value.startswith("CVE-") and (year + number).isascii() and (year + number).isdigit()
        assert len(year) == 4 and 4 <= len(number) <= 7


@given(st.integers(min_value=1999, max_value=2099), st.integers(min_value=0, max_value=9_999_999))
def test_well_formed_identifiers_pass(year: int, number: int) -> None:
    assert check_cve(f"CVE-{year}-{number:04d}", "cve", lambda _cve: True) == []


vectors = st.builds(
    lambda values: "CVSS:3.1/" + "/".join(f"{k}:{v}" for k, v in values.items()),
    st.fixed_dictionaries(
        {
            "AV": st.sampled_from("NALP"),
            "AC": st.sampled_from("LH"),
            "PR": st.sampled_from("NLH"),
            "UI": st.sampled_from("NR"),
            "S": st.sampled_from("UC"),
            "C": st.sampled_from("NLH"),
            "I": st.sampled_from("NLH"),
            "A": st.sampled_from("NLH"),
        }
    ),
)


@given(vectors, st.data())
def test_the_syntax_check_and_the_calculator_accept_the_same_31_vectors(vector: str, data: st.DataObject) -> None:
    assert check_cvss_vector(vector, "v") == [] and parse_cvss31(vector) is not None
    cut = data.draw(st.integers(min_value=0, max_value=len(vector)))
    mutated = vector[:cut] + data.draw(st.sampled_from(["", "/", "X", ":", "/Z:N", "/AV:N"])) + vector[cut:]
    assert (check_cvss_vector(mutated, "v") == []) == (parse_cvss31(mutated) is not None) or mutated == ""


other_digits = st.text(
    alphabet="\u0660\u0661\u0662\u0663\u0966\u0967\u0968\u0969\uff10\uff11\uff12\uff13", min_size=4, max_size=7
)


@given(other_digits, other_digits, st.sampled_from(["year", "number", "both"]))
def test_digits_of_other_scripts_never_make_a_cve_identifier(year: str, number: str, where: str) -> None:
    ascii_year, ascii_number = "2026", "1234"
    parts = {
        "year": (year[:4].ljust(4, "\u0660"), ascii_number),
        "number": (ascii_year, number),
        "both": (year[:4].ljust(4, "\u0660"), number),
    }[where]
    assert check_cve("CVE-" + "-".join(parts), "cve", lambda _cve: True)


def test_arabic_indic_digits_are_not_a_cve_identifier() -> None:
    assert check_cve("CVE-\u0662\u0660\u0662\u0666-\u0661\u0662\u0663\u0664", "cve", lambda _cve: True)


_CVE_PIECES = st.lists(
    st.one_of(
        st.sampled_from(["CVE-", "cve-", "CVE" + chr(0x2011), "-", chr(0x2013), " ", "\n", "x", "9"]),
        st.text(alphabet="0123456789", min_size=1, max_size=9),
        st.text(max_size=3),
    ),
    max_size=12,
)


@given(_CVE_PIECES, st.data())
def test_every_cve_a_verbatim_quote_can_name_is_a_candidate(pieces: list[str], data: st.DataObject) -> None:
    """F12.2 #105: the analysts look up only `cve_candidates(text)` before the call; that is enough because any CVE
    a verbatim quote of the text names (as VAL-03.cve_in_quote reads it) is among them."""
    text = "".join(pieces)
    start = data.draw(st.integers(0, len(text)))
    quote = text[start : data.draw(st.integers(start, len(text)))]
    found = cve_candidates(text)
    plain = normalize_text(quote).translate({ord(c): "-" for c in "\u2010\u2011\u2012\u2013\u2014\u2212"}).upper()
    for size in range(4, 8):
        for index in range(len(plain)):
            cve = plain[index : index + 9 + size]
            if CVE_FORMAT.fullmatch(cve) and _mentions_cve(quote, cve):
                assert cve in found
