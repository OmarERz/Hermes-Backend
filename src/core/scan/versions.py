"""Tolerant version comparison (ESC-13): `1.2.10 > 1.2.9`, `2.0.0-rc1 < 2.0.0`, `1.0 == 1.0.0`.

Versions that cannot be placed on that scale (no leading number, unknown words) return None: the scan records a
comparison error and does not guess. A release is a run of numbers; after it come an optional pre-release label
(`alpha`, `beta`, `rc`...) or post-release label (`post`, `sp`), each with its own number.
"""

from __future__ import annotations

import re
from typing import Final, NamedTuple

TOKEN: Final = re.compile(r"\d+|[a-z]+")
SEPARATORS: Final = re.compile(r"[.\-_+~]")
PRE_RELEASE: Final = {
    "dev": 0, "snapshot": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "preview": 3, "pre": 3, "rc": 4, "c": 4,
}  # fmt: skip
POST_RELEASE: Final = frozenset({"post", "p", "sp", "patch"})
MAX_LENGTH: Final = 100


class Version(NamedTuple):
    release: tuple[int, ...]
    stage: int  # 0 pre-release, 1 release, 2 post-release
    rank: int  # order among pre-release labels
    number: int


def parse_version(raw: str) -> Version | None:
    text = raw.strip().lower().removeprefix("v").split("+", 1)[0]  # build metadata has no precedence (SemVer)
    if not text or len(text) > MAX_LENGTH or not text[0].isdigit():
        return None
    tokens = [t for part in SEPARATORS.split(text) for t in TOKEN.findall(part)]
    if "".join(tokens) != SEPARATORS.sub("", text):
        return None  # characters that are neither words nor numbers
    release: list[int] = []
    index = 0
    while index < len(tokens) and tokens[index].isdigit():
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
        order = compare_versions(version, start)
        if order is None:
            return None
        if order < 0 or (order == 0 and not start_inclusive):
            return False
    if end is not None:
        order = compare_versions(version, end)
        if order is None:
            return None
        if order > 0 or (order == 0 and not end_inclusive):
            return False
    return True
