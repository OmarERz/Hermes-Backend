"""Tolerant version comparison (ESC-13): `1.2.10 > 1.2.9`, `2.0.0-rc1 < 2.0.0`, `1.0 == 1.0.0`.

Versions that cannot be placed on that scale (no leading number, unknown words) return None: the scan records a
comparison error and does not guess. A release is a run of numbers; after it come an optional pre-release label
(`alpha`, `beta`, `rc`...) or post-release label (`post`, `sp`), each with its own number. A range bound may also be a
CVE JSON 5 wildcard line (`6.1.*`, CNA `lessThanOrEqual`): it stands for every version of that line, so a version is
before it, inside it or after it.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Final, NamedTuple

TOKEN: Final = re.compile(r"[0-9]+|[a-z]+")  # ASCII digits only: `\d` would also take Arabic-Indic and full-width ones
SEPARATORS: Final = re.compile(r"[.\-_+~]")
PRE_RELEASE: Final = {
    "dev": 0, "snapshot": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "preview": 3, "pre": 3, "rc": 4, "c": 4,
}  # fmt: skip
POST_RELEASE: Final = frozenset({"post", "p", "sp", "patch"})
MAX_LENGTH: Final = 100
DIGITS: Final = "0123456789"
# OpenSSL letter releases only: one letter, or `z` and one letter after it (`1.1.1w`, `1.1.1zd`, `1.0.2zm`); never a
# word such as `fips` or `beta1`
LETTER_RELEASE: Final = re.compile(r"([0-9]+(?:\.[0-9]+)*)(z?[a-z])")
WILDCARD: Final = "x"  # `1.2x` names a line, not one version
# A whole line as a range bound: `6.1.*` (CVE JSON 5) or `2.4.x`; a lone `*` is no bound at all (an open side)
WILDCARD_LINE: Final = re.compile(r"v?([0-9]+(?:\.[0-9]+)*)\.[*x]")


class Version(NamedTuple):
    release: tuple[int, ...]
    stage: int  # 0 pre-release, 1 release, 2 post-release
    rank: int  # order among pre-release labels
    number: int


def _comparable_text(raw: str) -> str:
    return raw.strip().lower().removeprefix("v").split("+", 1)[0]  # build metadata has no precedence (SemVer)


def parse_version(raw: str) -> Version | None:
    text = _comparable_text(raw)
    if not text or len(text) > MAX_LENGTH or text[0] not in DIGITS:
        return None
    tokens = [t for part in SEPARATORS.split(text) for t in TOKEN.findall(part)]
    if "".join(tokens) != SEPARATORS.sub("", text):
        return None  # characters that are neither words nor numbers
    release: list[int] = []
    index = 0
    while index < len(tokens) and tokens[index][0] in DIGITS:
        release.append(int(tokens[index]))
        index += 1
    while release and release[-1] == 0:
        release.pop()
    return _with_suffix(tuple(release), tokens[index:])


def _with_suffix(release: tuple[int, ...], rest: list[str]) -> Version | None:
    if not rest:
        return Version(release, 1, 0, 0)
    label, tail = rest[0], rest[1:]
    if tail and not (len(tail) == 1 and tail[0].isdigit()):
        return None  # more than "label number" after the release: not a shape we know
    number = int(tail[0]) if tail else 0
    if label in PRE_RELEASE:
        return Version(release, 0, PRE_RELEASE[label], number)
    if label in POST_RELEASE:
        return Version(release, 2, 0, number)
    return None


def compare_versions(left: str, right: str) -> int | None:
    """-1, 0 or 1; None when either version cannot be compared."""
    a, b = parse_version(left), parse_version(right)
    if a is None or b is None:
        return None
    return (a > b) - (a < b)


def release_of(raw: str) -> tuple[int, ...] | None:
    """The release numbers of a version, also for an OpenSSL letter release off the scale (`1.1.1zd` -> (1, 1, 1));
    None for any other version the comparator cannot read (`3.0.23-fips`, `3.0.22fips`, `1.2.x`, `1.2x`, `latest`)."""
    parsed = parse_version(raw)
    if parsed is not None:
        return parsed.release
    text = _comparable_text(raw)
    letters = LETTER_RELEASE.fullmatch(text) if len(text) <= MAX_LENGTH else None
    if letters is None or letters.group(2) == WILDCARD:
        return None
    base = parse_version(letters.group(1))
    return base.release if base is not None else None


def known_order(left: str, right: str) -> int | None:
    """-1, 0 or 1 when the comparator's scale decides the order without guessing; None otherwise (ESC-13).

    `compare_versions` first. A letter release it cannot read (`1.1.1zd`) is still ordered against another release,
    because the release numbers come first on the scale whatever the letters mean (`3.0.18 > 1.1.1zd`,
    `1.1.1zd > 1.0.2`), and the same text is the same version (`1.1.1w` = `V1.1.1w`). Against its own release it
    stays unknown (`1.1.1w` ? `1.1.1zd`, `1.1.1` ? `1.1.1w`): the letters could sort before or after."""
    order = compare_versions(left, right)
    if order is not None:
        return order
    if _comparable_text(left) == _comparable_text(right):
        return 0
    a, b = release_of(left), release_of(right)
    if a is None or b is None or a == b:
        return None
    return (a > b) - (a < b)


def wildcard_line(bound: str) -> tuple[int, ...] | None:
    """The release numbers a wildcard bound names (`6.1.*` -> (6, 1)); None for any other bound."""
    text = bound.strip().lower()
    match = WILDCARD_LINE.fullmatch(text) if len(text) <= MAX_LENGTH else None
    return tuple(int(number) for number in match.group(1).split(".")) if match else None


def bound_order(version: str, bound: str, order: Callable[[str, str], int | None] | None = None) -> int | None:
    """-1, 0 or 1: the version before, at or after a range bound; None when it cannot be told (ESC-13).

    A wildcard bound is its whole line: 0 for any version of it (`6.1.192` against `6.1.*`), so an inclusive end
    `<= 6.1.*` keeps the line and an exclusive start `> 6.1.*` begins after it. Any other bound uses `order`
    (`compare_versions` by default; the judge passes `known_order`)."""
    line = wildcard_line(bound)
    if line is None:
        return (order or compare_versions)(version, bound)
    parsed = parse_version(version)
    if parsed is None:
        return None
    head = (parsed.release + (0,) * len(line))[: len(line)]
    return (head > line) - (head < line)


def in_range(
    version: str,
    start: str | None,
    start_inclusive: bool | None,
    end: str | None,
    end_inclusive: bool | None,
) -> bool | None:
    """Is `version` inside the range? A range without bounds covers every version. None = cannot tell.

    A version that cannot be read is None even for a range without bounds: it is never confirmed blind (ESC-12).
    """
    if parse_version(version) is None:
        return None
    if start is not None:
        order = bound_order(version, start)
        if order is None:
            return None
        if order < 0 or (order == 0 and not start_inclusive):
            return False
    if end is not None:
        order = bound_order(version, end)
        if order is None:
            return None
        if order > 0 or (order == 0 and not end_inclusive):
            return False
    return True
