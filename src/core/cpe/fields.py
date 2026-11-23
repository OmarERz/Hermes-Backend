"""The fields of a CPE 2.3 name (the one place that splits and unescapes them).

A backslash escapes the next character, so `\\:` stays inside its field and the colon that follows an escaped
backslash (`\\:`) ends it. NVD's criteria strings and our own `cpe_uri` follow the same rule.
"""

from __future__ import annotations

import re
from typing import Final

_ESCAPED: Final = re.compile(r"\\(.)", re.DOTALL)


def split_cpe_fields(name: str) -> list[str]:
    """Split a CPE name at its unescaped colons; the escapes stay in the fields (see `unescape_cpe`)."""
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in name:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def unescape_cpe(field: str) -> str:
    """The text of one field without its escapes (including an escaped line break)."""
    return _ESCAPED.sub(r"\1", field)
