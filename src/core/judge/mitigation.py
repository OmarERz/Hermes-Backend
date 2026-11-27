"""Validation of the mitigation drafted in `finalize_review` (D-017, docs/07 §13 JUE-MIT-01 to JUE-MIT-06).

All or nothing (JUE-MIT-05): one failing step discards the whole draft and records the broken rule; the
data-based mitigation (docs/06 §5) is always shown anyway. Length and count limits the strict mode cannot
express are checked here too (VAL-02).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
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
_ADDRESS_CHAR = r"[^\s`'\"<>()]"
# A bracket or typographic quote that opens right before an address closes around it, not inside it.
_CLOSERS = {"[": "]", "{": "}", "\u201c": "\u201d", "\u2018": "\u2019", "\u00ab": "\u00bb"}
_URL = re.compile(rf"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://{_ADDRESS_CHAR}+")  # any scheme, any case
# Dotted names are read whole, with any port, path or query ('vendor.example.invalid2', never 'vendor.example';
# 'docs.example.org:8443/?id=3', 'docs.example.org/'). Action and quote classify them the same way: a version when
# it is a qualified version below ('3.0.23.post1', 'v3.0.0rc1') or has no two letters in a row ('1.1.1w', 'e.g');
# otherwise a host ('3.0.23.example', '1password.com').
_DOTTED_NAME = rf"(?P<name>(?>[\w+~-]+(?:\.[\w+~-]+)+))(?::\d+)?(?:/{_ADDRESS_CHAR}*|[?#]{_ADDRESS_CHAR}+)?"
_HOST = re.compile(rf"(?<![\w@/.-]){_DOTTED_NAME}")
_LETTERS = re.compile(r"[^\W\d_]{2}")  # 'e.g' and 'U.S.A' are not hosts
_COMMAND = re.compile(r"`([^`\n]+)`")
# A branch (#176) names a release line, not one version: a wildcard ('3.0.x', '3.*') or a dotted number next to a
# branch word ('la rama 3.0', 'the 3.0 branch'). It becomes the fact '3.0.x', where x stands for one or more numbers:
# the quote backs it with one of its versions ('3.0.23', '3.0.11-1~deb12u2'), its wildcard or, for a dotted line,
# the line itself ('3.0'). Any other version token, read whole ('3.0.0-rc1', '1.1.1w', '3.0.x-rc1'), is a version
# fact and has to appear whole in the quote.
_BRANCH_WORD = r"(?:ramas?|series?|l[ií]neas?|branch(?:es)?|lines?)"
_MAJOR_WORD = r"(?:ramas?|series?|branch(?:es)?)"  # 'la rama 4', 'la serie 4'; not 'línea 42' of a file
_NUMBER_END = r"(?![\w+~*-]|\.[\w*])"
_OPEN_QUOTE = r"[\u00ab\u201c\u2018\"']?"  # 'la rama «3.0»'
_CLOSE_QUOTE = r"[\u00bb\u201d\u2019\"']?"
_NAMED_BRANCH = re.compile(
    rf"(?i:\b{_BRANCH_WORD}\s+){_OPEN_QUOTE}[vV]?(\d+(?:\.\d+)+){_NUMBER_END}"
    rf"|(?i:\b{_MAJOR_WORD}\s+){_OPEN_QUOTE}[vV]?(\d+){_NUMBER_END}"
    rf"|(?<![\w.])[vV]?(\d+(?:\.\d+)+){_CLOSE_QUOTE}(?i:\s+{_BRANCH_WORD}\b)"
    rf"|(?<![\w.])[vV]?(\d+){_CLOSE_QUOTE}(?i:\s+(?:rama|serie|branch)\b)"  # 'the 4 branch', not '3 branches'
)
_VERSION = re.compile(r"(?<![\w.])[vV]?(\d+(?:\.(?:\d+|[xX*]))+(?:[0-9A-Za-z_+~*-]|\.(?=[0-9A-Za-z*]))*)")
_WILDCARD = re.compile(r"(\d+(?:\.\d+)*)\.[xX*]")
_VERSION_WORD = re.compile(r"(?i:\b(?:versi[oó]n|version|release|build|v)\s*)(\d+)\b(?!\.\d)")
_PATH = re.compile(r"(?<![\w:/.])(?:~|\.{1,2})?/(?:[\w.-]+/)*[\w.-]+")
_TRAILING = ".,;:"
# A version or branch token in the quote ends where a longer version would go on: '3.0.23' is not in '3.0.23.1',
# '3.0.23-1', '3.0.23+deb', '3.0.23~rc1' or '3.0.23*'. It may carry a 'v' prefix ('v3.0.23').
_VERSION_START = r"(?<![\w./+~-])[vV]?"
_VERSION_END = r"(?![\w/+~*-]|\.[\w*])"
# Version suffixes: '1.1.1w', '-rc1', '+deb12u1', '-1~deb12u2', '-1.el9_2', '.post1', '.Final'.
_SUFFIX = r"(?:[A-Za-z][0-9A-Za-z]*)?+(?:[-+~._][0-9A-Za-z]+)*+"
# URLs and host names in a quote are not versions ('docs.example.org?id=3.0.23', '3.0.23.example'), so version
# evidence is searched without them. A dotted name stays when it is a version: numbered labels and at most one final
# qualifier with a digit or from the usual words that are no domain endings ('3.0.23.post1', '2.4.57-5.el9',
# '2.17.1.redhat-00001', 'v3.0.0rc1', '5.4.24.Final'; not '3.0.23.dev' or '3.0.23.ga').
_QUOTE_NAME = re.compile(rf"(?<![\w/.-]){_DOTTED_NAME}")
# Possessive: a label never gives digits back, so a failing name is rejected in linear time (no ReDoS).
_NUMBERED_LABEL = r"\d++[0-9A-Za-z]*+(?:[-+~_][0-9A-Za-z]++)*+"
_QUALIFIER = (
    r"(?:(?=[0-9A-Za-z+~_-]*\d)[A-Za-z][0-9A-Za-z]*+(?:[-+~_][0-9A-Za-z]++)*+"
    r"|(?i:final|release|alpha|beta|rc|pre|snapshot|lts|stable))"
)
_QUALIFIED_VERSION = re.compile(rf"[vV]?{_NUMBERED_LABEL}(?:\.{_NUMBERED_LABEL})*(?:\.{_QUALIFIER})?")
# Right after an explicit version word, the qualifiers that are also domain endings count: 'version 3.0.23.post'.
_VERSION_CONTEXT = re.compile(r"(?i:\b(?:versi[oó]n|version|release)\s+)$")
_CONTEXT_QUALIFIED = re.compile(rf"[vV]?{_NUMBERED_LABEL}(?:\.{_NUMBERED_LABEL})*\.(?i:post|dev|ga)")
_GAP = "\x00"  # what a read fact leaves behind: no later pattern reads across it ('versión 3.0.23 64-bit')


class FactKind(StrEnum):
    URL = "url"
    COMMAND = "command"
    HOST = "host"
    BRANCH = "branch"
    VERSION = "version"
    PATH = "path"


@dataclass(frozen=True)
class TraceableFact:
    """A fact written in an action that its quote must back (JUE-MIT-03). A branch is written '3.0.x'."""

    kind: FactKind
    text: str

    def in_quote(self, quote: str) -> bool:
        if self.kind is FactKind.BRANCH:
            # A whole token: one version of the line, with any suffix ('3.0.23', '3.0.23.1', '3.0.11-1~deb12u2',
            # '1.1.1w' for 1.1.x), its bare wildcard ('3.0.x') or the dotted line itself ('3.0', '3.0-rc1'); never
            # '13.0.1', '3.01', '3.0.x-rc1', a host name ('3.0.23.support.example') or, for the 3.x line, a bare '3'.
            # Atomic: no backtracking to a prefix.
            line = self.text.removesuffix(".x")
            itself = r"|(?:[-+~_][0-9A-Za-z]+)*+" if "." in line else ""
            tail = rf"(?>(?:\.\d+)++{_SUFFIX}|\.[xX*]{itself})"
            pattern = rf"{_VERSION_START}{re.escape(line)}{tail}{_VERSION_END}"
            return re.search(pattern, _without_hosts(quote)) is not None
        if self.kind is FactKind.VERSION:
            pattern = rf"{_VERSION_START}{re.escape(self.text)}{_VERSION_END}"
            return re.search(pattern, _without_hosts(quote)) is not None
        # Addresses are compared whole, as the same pattern reads them on both sides: 'docs.example.org/' is not
        # backed by 'docs.example.org/?x=1', nor 'https://a.example/x' by 'https://a.example/x?y=1'.
        if self.kind is FactKind.HOST:
            return any(_is_address(match) and _address(match) == self.text for match in _QUOTE_NAME.finditer(quote))
        if self.kind is FactKind.URL:
            return any(_address(match) == self.text for match in _URL.finditer(quote))
        return appears_as_fact(self.text, quote)


def _is_address(match: re.Match[str]) -> bool:
    """Whether a dotted name is an address rather than a version, by the same rule in the action and the quote."""
    address, name = match.group(0), match.group("name")
    if address != name:  # with a port, path or query it is an address ('1.2.3.4:8443/?id=3.0.23')
        return True
    if _LETTERS.search(name) is None or _QUALIFIED_VERSION.fullmatch(name) is not None:
        return False
    explicit = _VERSION_CONTEXT.search(match.string, 0, match.start()) is not None
    return not (explicit and _CONTEXT_QUALIFIED.fullmatch(name))


def _without_hosts(quote: str) -> str:
    return _QUOTE_NAME.sub(lambda match: _GAP if _is_address(match) else match.group(0), _URL.sub(_GAP, quote))


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
    if not all(fact.in_quote(quote) for fact in traceable_facts(action)):
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


def traceable_facts(action: str) -> list[TraceableFact]:
    """Versions, branches, URLs, backticked commands and file paths written in an action (JUE-MIT-03)."""
    text = normalize_text(action)
    facts = _facts(FactKind.URL, (_address(match) for match in _URL.finditer(text)))
    facts += _facts(FactKind.COMMAND, (normalize_text(command) for command in _COMMAND.findall(text)))
    without_urls = _URL.sub(" ", text)
    hosts, without_hosts = _split_hosts(without_urls)
    facts += _facts(FactKind.HOST, hosts)
    named = (next(number for number in groups if number) for groups in _NAMED_BRANCH.findall(without_hosts))
    facts += _facts(FactKind.BRANCH, (f"{number}.x" for number in named))
    without_branches = _NAMED_BRANCH.sub(_GAP, without_hosts)
    facts += [_version_fact(token) for token in _VERSION.findall(without_branches)]
    facts += _facts(FactKind.VERSION, _VERSION_WORD.findall(_VERSION.sub(_GAP, without_branches)))
    facts += _facts(FactKind.PATH, (path.rstrip(_TRAILING) for path in _PATH.findall(without_hosts)))
    return facts


def _address(match: re.Match[str]) -> str:
    """The address a match read, without the punctuation that ends the sentence and without the closing mark of a
    bracket or quote opened right before it: '[https://vendor.example/advisory]' and '“https://…”' lose it, while
    'https://[2001:db8::1234]', 'docs.example.org/advisory]' and a typographic apostrophe inside a path keep theirs."""
    address = match.group(0).rstrip(_TRAILING)
    opener = match.string[match.start() - 1] if match.start() else ""
    closer = _CLOSERS.get(opener)
    if closer and address.endswith(closer) and (closer not in "]}" or address.count(closer) > address.count(opener)):
        address = address[: -len(closer)].rstrip(_TRAILING)
    return address


def _split_hosts(text: str) -> tuple[list[str], str]:
    """The host names of an action, each read whole, and the text without them."""
    hosts: list[str] = []

    def take(match: re.Match[str]) -> str:
        if not _is_address(match):
            return match.group(0)
        hosts.append(_address(match))
        return " "

    return hosts, _HOST.sub(take, text)


def _version_fact(token: str) -> TraceableFact:
    """A version token read whole: a bare wildcard is a branch ('3.0.X' -> '3.0.x'), anything else a version."""
    wildcard = _WILDCARD.fullmatch(token)
    if wildcard is not None:
        return TraceableFact(FactKind.BRANCH, f"{wildcard.group(1)}.x")
    return TraceableFact(FactKind.VERSION, token)


def _facts(kind: FactKind, texts: Iterable[str]) -> list[TraceableFact]:
    return [TraceableFact(kind, text) for text in texts if text]
