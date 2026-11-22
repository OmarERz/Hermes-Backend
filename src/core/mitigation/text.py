"""Cleaning of external text before it reaches a sentence or a link: it is data, never instructions."""

from __future__ import annotations

import re
from typing import Final
from urllib.parse import urlsplit

CONTROL: Final = re.compile(r"[\x00-\x1f\x7f]+")
MAX_TEXT: Final = 400


def clean_text(raw: object, limit: int = MAX_TEXT) -> str:
    """One line, no control characters, at most `limit` characters (an ellipsis marks a cut)."""
    text = " ".join(CONTROL.sub(" ", str(raw)).split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def safe_url(raw: object) -> str | None:
    """The URL when it is plain http(s) with a host and no spaces, else None."""
    text = str(raw).strip()
    parts = urlsplit(text)
    if parts.scheme not in {"http", "https"} or not parts.hostname or CONTROL.search(text) or " " in text:
        return None
    return text
