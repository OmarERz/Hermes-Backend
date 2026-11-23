"""Properties of CPE 2.3 names (formatting and parsing) and of the mapping validation."""

from __future__ import annotations

import contextlib
import string

from hypothesis import assume, given
from hypothesis import strategies as st

from core.cpe.candidates import clean_query, cpe_uri, parse_cpe_name
from core.cpe.mapping import MappingError, MappingInput, validate

NVD_ALPHABET = string.ascii_lowercase + string.digits + "._~+:-"
names = st.text(alphabet=NVD_ALPHABET, min_size=1, max_size=30).filter(lambda s: s not in {"-", "*"})
visible = st.characters(min_codepoint=32, max_codepoint=0x10FFFF, blacklist_categories=("Cs",))
anything = st.characters(blacklist_categories=("Cs",))  # control characters and line breaks included
printable = st.text(alphabet=visible, min_size=1, max_size=30).filter(lambda s: s not in {"-", "*"})


@given(names, names)
def test_nvd_names_round_trip(vendor: str, product: str) -> None:
    assert parse_cpe_name(cpe_uri(vendor, product)) == (vendor, product)


@given(printable, printable)
def test_any_printable_name_round_trips_through_the_escaping(vendor: str, product: str) -> None:
    """The colon, the backslash and every other special character are escaped and restored exactly."""
    assert parse_cpe_name(cpe_uri(vendor, product)) == (vendor, product)


@given(names, names)
def test_the_uri_has_the_fixed_shape(vendor: str, product: str) -> None:
    uri = cpe_uri(vendor, product)
    assert uri.startswith("cpe:2.3:a:") and uri.endswith(":*:*:*:*:*:*:*:*")
    assert "\n" not in uri


@given(st.text(max_size=120))
def test_parsing_arbitrary_text_never_raises(text: str) -> None:
    result = parse_cpe_name(text)
    assert result is None or all(part not in {"", "*", "-"} for part in result)


@given(st.text(max_size=200))
def test_clean_query_either_rejects_or_returns_a_tidy_query(raw: str) -> None:
    try:
        query = clean_query(raw)
    except ValueError:
        return
    assert query == " ".join(query.split()) and 1 <= len(query) <= 100
    assert all(ord(ch) >= 32 for ch in query)
    assert clean_query(query) == query


mapped = st.from_regex(r"[a-z0-9][a-z0-9._~+:\-]{0,30}", fullmatch=True)


@given(mapped, mapped)
def test_valid_mappings_validate_and_are_stable(vendor: str, product: str) -> None:
    once = validate(MappingInput(vendor, product, None, None))
    assert validate(once) == once


@given(st.text(max_size=40), st.text(max_size=40))
def test_validation_never_raises_anything_but_mapping_error(vendor: str, product: str) -> None:
    with contextlib.suppress(MappingError):
        validate(MappingInput(vendor, product, vendor, product))


@given(st.text(alphabet=anything, min_size=1, max_size=20), st.text(alphabet=anything, min_size=1, max_size=20))
def test_even_names_with_control_characters_round_trip(vendor: str, product: str) -> None:
    assume(vendor not in {"-", "*"} and product not in {"-", "*"})
    assert parse_cpe_name(cpe_uri(vendor, product)) == (vendor, product)
