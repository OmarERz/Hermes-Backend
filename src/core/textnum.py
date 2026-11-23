"""Numbers read from text that someone else wrote (headers, keys, JSON strings).

`str.isdigit()` is true for superscripts and digits of other scripts, and `int()` rejects some of them (`int("²")`
raises) and accepts others (`int("٣")` is 3), so neither is a safe test of "this is a number". These helpers accept
ASCII digits only.
"""

from __future__ import annotations

from typing import Final

ASCII_DIGITS: Final = frozenset("0123456789")
MAX_RETRY_AFTER_CHARS: Final = 20
MAX_DIGITS: Final = 4000  # `int()` refuses more than 4300 digits; nothing we read is anywhere near this long


def ascii_int(text: str | None) -> int | None:
    """The integer written with ASCII digits only (no sign, no spaces); None for anything else. Never raises."""
    if not text or len(text) > MAX_DIGITS or not set(text) <= ASCII_DIGITS:
        return None
    return int(text)


def retry_after_seconds(raw: str | None, maximum: float | None = None) -> float | None:
    """Seconds of a `Retry-After` header in its delta form (ASCII digits, optional fraction), capped at `maximum`.

    The HTTP-date form, `nan`, `inf`, negative numbers, other scripts' digits and anything else give None: the caller
    falls back to its own backoff, and a hostile server can never make it sleep on a non-number.
    """
    text = (raw or "").strip()
    if len(text) > MAX_RETRY_AFTER_CHARS:
        return None  # no real delay needs that many digits; a longer one would overflow to `inf`
    head, _, tail = text.partition(".")
    if not set(head) <= ASCII_DIGITS or not set(tail) <= ASCII_DIGITS or not head:
        return None
    if "." in text and not tail:
        return None
    seconds = float(text)
    return seconds if maximum is None else min(seconds, maximum)
