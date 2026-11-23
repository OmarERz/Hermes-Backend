"""Validation of the mitigation drafted in `finalize_review` (D-017, docs/07 §13 JUE-MIT-01 to JUE-MIT-06).

All or nothing (JUE-MIT-05): one failing step discards the whole draft and records the broken rule; the
data-based mitigation (docs/06 §5) is always shown anyway. Length and count limits the strict mode cannot
express are checked here too (VAL-02).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from core.judge.package import ElementKind, ReviewPackage, SourceLevel, normalize_text

MAX_STEPS = 20
MAX_ACTION_CHARS = 1000
MIN_QUOTE_CHARS = 12
MAX_QUOTE_CHARS = 1000

# JUE-MIT-03: traceable facts. URLs (with or without scheme, bare hosts), commands in backticks, versions (dotted,
# v-prefixed, or a number after a version word) and file paths must appear in the quote as the same whole fact.
_URL = re.compile(r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://[^\s`'\"<>()]+")  # any scheme, any case
_HOST = re.compile(r"(?<![\w@/.-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?:/[^\s`'\"<>()]*)?")
_COMMAND = re.compile(r"`([^`\n]+)`")
_VERSION = re.compile(r"(?<![\w.])[vV]?(\d+(?:\.\d+)+(?:[-+][0-9A-Za-z][0-9A-Za-z.]*)?)")
_VERSION_WORD = re.compile(r"(?i:\b(?:versi[oó]n|version|release|build|v)\s*)(\d+)\b(?!\.\d)")
_PATH = re.compile(r"(?<![\w:/.])(?:~|\.{1,2})?/(?:[\w.-]+/)*[\w.-]+")
_TRAILING = ".,;:"


class MitigationStatus(StrEnum):
    ACCEPTED = "accepted"
    DISCARDED = "discarded"
    ABSENT = "absent"


@dataclass(frozen=True)
class MitigationStep:
    order: int
    ci_id: str | None  # None: applies to every CI of the group
    action: str
    element_id: str
    quote: str


@dataclass(frozen=True)
class MitigationResult:
    status: MitigationStatus
    steps: tuple[MitigationStep, ...] = ()
    rule: str | None = None  # JUE-MIT-xx or VAL-02 when discarded

    @classmethod
    def absent(cls) -> MitigationResult:
        return cls(MitigationStatus.ABSENT)


class _DiscardError(Exception):
    """Internal control flow: one failing step discards the draft. Never escapes this module."""

    def __init__(self, rule: str) -> None:
        super().__init__(rule)
        self.rule = rule


def validate_mitigation(raw_steps: Sequence[Mapping[str, Any]], package: ReviewPackage) -> MitigationResult:
    if not raw_steps:
        return MitigationResult.absent()
    try:
        steps = tuple(_step(raw, package) for raw in raw_steps)
        _check_order(steps)
    except _DiscardError as discard:
        return MitigationResult(MitigationStatus.DISCARDED, rule=discard.rule)
    return MitigationResult(MitigationStatus.ACCEPTED, steps=tuple(sorted(steps, key=lambda s: s.order)))


def _step(raw: Mapping[str, Any], package: ReviewPackage) -> MitigationStep:
    action = str(raw["action"]).strip()
    quote = normalize_text(str(raw["quote"]))
    if not action or len(action) > MAX_ACTION_CHARS or len(quote) > MAX_QUOTE_CHARS:
        raise _DiscardError("VAL-02")
    element = package.elements.get(str(raw["element_id"]))
    if element is None or element.kind is ElementKind.CI or element.suspicious:  # SEG-03: never from a suspect
        raise _DiscardError("JUE-MIT-01")
    if len(quote) < MIN_QUOTE_CHARS or not element.contains(quote):
        raise _DiscardError("JUE-MIT-02")
    # JUE-MIT-01: only N1 data. In the CVE element, analyst output (conditions, components, inferred CVSS) is N4;
    # a news item counts only if its source is N1 (vendor advisory).
    if element.quote_level(quote) is not SourceLevel.N1:
        raise _DiscardError("JUE-MIT-01")
    if not all(appears_as_fact(fact, quote) for fact in traceable_facts(action)):
        raise _DiscardError("JUE-MIT-03")
    ci_id = str(raw["ci_id"]).strip()
    if ci_id and ci_id not in package.ci_ids:
        raise _DiscardError("JUE-MIT-04")
    return MitigationStep(
        order=int(raw["order"]), ci_id=ci_id or None, action=action, element_id=element.element_id, quote=quote
    )


def _check_order(steps: Sequence[MitigationStep]) -> None:
    if len(steps) > MAX_STEPS:
        raise _DiscardError("VAL-02")
    if sorted(step.order for step in steps) != list(range(1, len(steps) + 1)):
        raise _DiscardError("JUE-MIT-06")


def appears_as_fact(fact: str, quote: str) -> bool:
    """The same whole fact is in the quote: '2.4.6' does not match '2.4.60', nor a URL a longer URL."""
    pattern = rf"(?<![\w./-]){re.escape(fact)}(?![\w/-]|\.\w)"
    return re.search(pattern, quote) is not None


def traceable_facts(action: str) -> list[str]:
    """Versions, URLs, backticked commands and file paths written in an action (JUE-MIT-03)."""
    text = normalize_text(action)
    facts = [url.rstrip(_TRAILING) for url in _URL.findall(text)]
    facts += [normalize_text(command) for command in _COMMAND.findall(text)]
    without_urls = _URL.sub(" ", text)
    facts += [host.rstrip(_TRAILING) for host in _HOST.findall(without_urls)]
    without_hosts = _HOST.sub(" ", without_urls)
    facts += [version.rstrip(_TRAILING) for version in _VERSION.findall(without_hosts)]
    facts += _VERSION_WORD.findall(without_hosts)
    facts += [path.rstrip(_TRAILING) for path in _PATH.findall(without_hosts)]
    return [fact for fact in facts if fact]
