"""Plain text to iTop rich text (F12.3, ASVS V1.2.1): markup stays literal, line breaks survive, sizes fit."""

from __future__ import annotations

import html
import re

import pytest
from hypothesis import given
from hypothesis import strategies as st

from core.itop.rich_text import (
    DESCRIPTION_MAX_BYTES,
    HTML_FIELDS,
    TRUNCATION_NOTE,
    encode_html_fields,
    fit_plain_text_to_html,
    html_size,
    plain_text_to_html,
)

# iTop's wiki reference syntax (WIKI_OBJECT_REGEXP of core/attributedef.class.inc.php, 3.2.2, ungreedy).
WIKI_OBJECT = re.compile(r"\[\[(.+?):(.+?)(\|(.+?))?\]\]")


def decode(encoded: str) -> str:
    """What a person reads in iTop: the text with the line breaks and the wiki breaks undone."""
    return html.unescape(encoded.replace("<span></span>", "").replace("<br>", "\n"))


def test_markup_is_escaped_and_line_breaks_become_br() -> None:
    assert plain_text_to_html("<img src=\"x\">\n& 'y'") == "&lt;img src=&quot;x&quot;&gt;<br>&amp; &#x27;y&#x27;"


def test_windows_and_old_mac_line_breaks_are_kept_too() -> None:
    assert plain_text_to_html("a\r\nb\rc") == "a<br>b<br>c"


def test_plain_text_without_special_characters_is_unchanged() -> None:
    assert plain_text_to_html("Ref. Hermes: 0190-ab [hermes:0190ab]") == "Ref. Hermes: 0190-ab [hermes:0190ab]"


@pytest.mark.parametrize("text", ["[[Person:admin|Parche urgente]]", "x [[[UserRequest:1]]] y", "[[a:b]][[c:d]]"])
def test_wiki_references_are_broken_so_itop_shows_them_literally(text: str) -> None:
    encoded = plain_text_to_html(text)
    assert "[[" not in encoded
    assert not WIKI_OBJECT.search(encoded)
    assert decode(encoded) == text


def test_only_the_html_fields_of_a_ticket_are_encoded() -> None:
    fields = {"title": "<t>", "description": "<d>", "public_log": "<p>", "private_log": "<q>", "urgency": "3"}
    assert encode_html_fields(fields) == {
        "title": "<t>",  # an iTop string attribute: iTop escapes it itself
        "description": "&lt;d&gt;",
        "public_log": "&lt;p&gt;",
        "private_log": "&lt;q&gt;",
        "urgency": "3",
    }
    assert fields["description"] == "<d>"  # the caller's dict is not modified
    assert sorted(HTML_FIELDS) == ["description", "private_log", "public_log"]


def test_non_text_values_pass_through() -> None:
    links = [{"functionalci_id": "1"}]
    assert encode_html_fields({"description": None, "functionalcis_list": links}) == {
        "description": None,
        "functionalcis_list": links,
    }


def test_html_size_is_the_utf8_length_itop_stores() -> None:
    assert html_size("abc") == len("abc")
    assert html_size("á") == len("á".encode())


def test_an_oversized_description_keeps_its_last_line_and_says_it_was_cut() -> None:
    marker = "Ref. Hermes: 0190a1b2-0000-7000-8000-000000000001"
    text = "\n".join(f"- CI {i} <expuesto> · dueño Ñandú" for i in range(5000)) + f"\n\n{marker}"

    encoded = encode_html_fields({"description": text})["description"]

    assert html_size(encoded) <= DESCRIPTION_MAX_BYTES
    assert encoded.endswith(f"<br>{html.escape(TRUNCATION_NOTE)}<br>{marker}")
    assert decode(encoded).startswith("- CI 0 <expuesto> · dueño Ñandú\n- CI 1")


def test_a_description_that_fits_is_never_cut() -> None:
    text = "a" * 1000 + "\nRef. Hermes: x"
    assert fit_plain_text_to_html(text, max_bytes=len(plain_text_to_html(text))) == plain_text_to_html(text)


def test_a_single_line_that_cannot_fit_is_refused() -> None:
    with pytest.raises(ValueError, match="does not fit"):
        fit_plain_text_to_html("x" * 50, max_bytes=10)


@given(st.text())
def test_no_tag_or_wiki_reference_survives_and_the_text_round_trips(text: str) -> None:
    encoded = plain_text_to_html(text)
    assert "<" not in encoded.replace("<br>", "").replace("<span></span>", "")
    assert '"' not in encoded and "'" not in encoded and "[[" not in encoded
    assert decode(encoded) == text.replace("\r\n", "\n").replace("\r", "\n")
