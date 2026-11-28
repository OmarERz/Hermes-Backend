"""The fields of a CPE 2.3 name (the one place that splits and unescapes them).

A backslash escapes the next character: an escaped colon stays inside its field, while a colon that follows an
escaped backslash (two backslashes, then the colon) ends it.
NVD's criteria strings and our own `cpe_uri` follow the same rule.
"""

from __future__ import annotations

import re
from typing import Final

_ESCAPED: Final = re.compile(r"\\(.)", re.DOTALL)
CPE_PARTS: Final = frozenset({"a", "o", "h"})  # application, operating system, hardware (CPE 2.3, D-107)
DEFAULT_PART: Final = "a"  # how a name is rebuilt when no part is stored


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
