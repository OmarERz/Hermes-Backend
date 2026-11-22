"""Safe construction of OQL (iTop's query language), adapted from the prototype. Never paste raw values."""

from __future__ import annotations

from collections.abc import Iterable

FIRST_PRINTABLE = 32


def quote(value: object) -> str:
    """`value` as an OQL string literal: `it\\'s`. Control characters are refused."""
    text = str(value)
    if any(ord(ch) < FIRST_PRINTABLE for ch in text):
        raise ValueError("control characters are not allowed in OQL values")
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def quote_list(values: Iterable[object]) -> str:
    items = [quote(v) for v in values]
    if not items:
        raise ValueError("an IN () list needs at least one value")
    return ", ".join(items)


def require_identifier(name: str) -> str:
    if not name or not all(ch.isascii() and (ch.isalnum() or ch == "_") for ch in name):
        raise ValueError(f"invalid class or field name: {name!r}")
    return name


def select(class_name: str, *conditions: str) -> str:
    """`SELECT Class [WHERE a AND b]`; each condition comes from `eq` or `in_`."""
    query = f"SELECT {require_identifier(class_name)}"
    return query + (" WHERE " + " AND ".join(conditions) if conditions else "")


def eq(field: str, value: object) -> str:
    return f"{require_identifier(field)} = {quote(value)}"


def in_(field: str, values: Iterable[object], *, negate: bool = False) -> str:
    return f"{require_identifier(field)} {'NOT IN' if negate else 'IN'} ({quote_list(values)})"
