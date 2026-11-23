"""Plain text → iTop rich text (ASVS 5.0 V1.2.1: encode output for the context that interprets it).

iTop 3.2.2 keeps a ticket's `description` as HTML (`AttributeText` with `<format>html</format>`) and adds every
case-log entry written through REST as HTML too (`ormCaseLog::AddLogEntry` stores `format: html`). Its sanitizer
(`HTMLDOMSanitizer`) removes scripts but keeps links (`a href`) and remote images (`img src` http, https, data), and
when it shows that HTML it also turns wiki references (`[[Class:name|label]]`) into links to iTop objects
(`AttributeText::RenderWikiHtml`, wiki only for HTML).

What Hermes writes there is plain text built from names and text it does not control (CI and team names from
iTop, news sources and URLs, the judge's mitigation draft, the comment of a user's feedback). Sent as is, a
`<a href=…>`, an `<img src=…>` or a `[[…]]` inside any of them would become a live link, a tracking image or a link
to another iTop object, and the line breaks would collapse into one paragraph. So every such field is HTML-escaped,
`[[` is broken with an empty `<span>` (an entity would not survive iTop's DOM round trip), and line breaks become
`<br>`: the text reads in iTop exactly as it was written, and markup in it stays literal.

The description is a MySQL `TEXT` column (65 535 bytes, `AttributeText::GetMaxSize`) and escaping makes text a bit
longer (`<br>` for each line break, entities for `<`, `>` and `&`). The ticket builder keeps every TIC-08 section and
shortens the CI list to fit (`core.tickets.content.description`); as a last resort, a description that still does not
fit is cut here before its last line (the `Ref. Hermes` marker the outbox relies on) with a note saying so, so the
ticket is still created and still found again on a retry.
"""

from __future__ import annotations

import html
import re
from typing import Any, Final

# UserRequest fields iTop interprets as HTML (verified in the 3.2.2 data model, itop-tickets).
HTML_FIELDS: Final = frozenset({"description", "public_log", "private_log"})
# `AttributeText::GetMaxSize()` is 65 535 bytes (UTF-8); the margin is for the separators iTop may add.
DESCRIPTION_MAX_BYTES: Final = 65_000
# TODO(P-009): ticket texts are Spanish only until the output language reaches the ticket templates (D-060).
TRUNCATION_NOTE: Final = "[…] Texto recortado: no cabe completo en iTop; el detalle está en Hermes."
_WIKI_OPENING: Final = re.compile(r"\[(?=\[)")
_BREAK: Final = "<span></span>"


def plain_text_to_html(text: str) -> str:
    """Escape `&`, `<`, `>`, `"` and `'`, break every `[[` and keep each line break as `<br>`."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "<br>".join(_WIKI_OPENING.sub("[" + _BREAK, html.escape(line, quote=True)) for line in lines)


def html_size(encoded: str) -> int:
    """Bytes the encoded text takes in iTop: its UTF-8 length. iTop's sanitizer saves the HTML of the body in UTF-8 and
    turns `&#x27;` and `&quot;` back into one character (checked with PHP's DOMDocument in the 3.2.2 image), so what
    it stores is never longer than what is sent."""
    return len(encoded.encode("utf-8"))


def encoded_size(text: str) -> int:
    """`html_size` of a plain text once encoded."""
    return html_size(plain_text_to_html(text))


def fit_plain_text_to_html(text: str, max_bytes: int = DESCRIPTION_MAX_BYTES) -> str:
    """Encode `text`; when it does not fit, cut what comes before its last line and add `TRUNCATION_NOTE`."""
    encoded = plain_text_to_html(text)
    if html_size(encoded) <= max_bytes:
        return encoded
    head, _, last = text.rpartition("\n")

    def build(keep: int) -> str:
        return plain_text_to_html(f"{head[:keep].rstrip()}…\n{TRUNCATION_NOTE}\n{last}")

    low, high = 0, len(head)
    while low < high:  # the longest head that still fits
        middle = (low + high + 1) // 2
        if html_size(build(middle)) <= max_bytes:
            low = middle
        else:
            high = middle - 1
    fitted = build(low)
    if html_size(fitted) > max_bytes:
        raise ValueError("the last line of the text alone does not fit in iTop")
    return fitted


def encode_html_fields(fields: dict[str, Any]) -> dict[str, Any]:
    """A copy of a UserRequest's fields with every plain-text HTML field encoded; other fields are untouched."""
    encoded: dict[str, Any] = {}
    for name, value in fields.items():
        if name in HTML_FIELDS and isinstance(value, str):
            encoded[name] = fit_plain_text_to_html(value) if name == "description" else plain_text_to_html(value)
        else:
            encoded[name] = value
    return encoded
