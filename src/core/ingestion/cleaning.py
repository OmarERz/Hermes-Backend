"""Cleaning of external text before it is stored or shown to an LLM (SEG-01) and injection marking (SEG-03).

Removes HTML, scripts, hidden text (hidden attributes, CSS that hides, white or zero-size text), zero-width and
control characters and long base64 blocks; normalizes Unicode and truncates. The result is plain text. A text
that carries instructions aimed at an AI is **marked** suspicious, never discarded (SEG-03). Detection also
looks at the hidden text: instructions hidden from readers are the stronger signal.
"""

from __future__ import annotations

import html as html_lib
import re
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser

MAX_CLEAN_CHARS = 60_000

# Elements whose content is never visible article text.
_DROPPED_TAGS = frozenset({"script", "style", "noscript", "template", "iframe", "object", "embed", "svg", "head"})
_VOID_TAGS = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
)
_BLOCK_TAGS = frozenset(
    {
        "p",
        "div",
        "br",
        "li",
        "ul",
        "ol",
        "tr",
        "table",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "blockquote",
        "pre",
        "section",
    }
)
_HIDING_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:[a-z%]*)?\s*(?:;|$)|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)"
    r"|(?:^|;)\s*color\s*:\s*(?:#fff(?:fff)?|white|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))\s*(?:;|$)"
    r"|text-indent\s*:\s*-\d{3,}|(?:left|top)\s*:\s*-\d{4,}",
    re.IGNORECASE,
)

_STYLE_BLOCK = re.compile(r"<style\b[^>]*>(.*?)</style\s*>", re.IGNORECASE | re.DOTALL)
_CSS_RULE = re.compile(r"([^{}@]+)\{([^{}]*)\}")
_SIMPLE_SELECTOR = re.compile(r"^([a-z][a-z0-9]*)?(?:([.#])([\w-]+))?$", re.IGNORECASE)

_INVISIBLE_CHARS = dict.fromkeys(
    [*range(0x200B, 0x2010), *range(0x202A, 0x202F), *range(0x2060, 0x2065), 0xFEFF, 0x00AD, 0x180E, 0x061C]
)
_BASE64_BLOCK = re.compile(r"[A-Za-z0-9+/_-]{120,}={0,2}")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_SPACES = re.compile(r"[ \t\f\r]+")  # NFKC already turned no-break spaces into spaces
_BLANK_LINES = re.compile(r"\n\s*\n+")

_INJECTION_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    for pattern in (
        r"\bignor(?:e|ing)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all)\b[^.\n]{0,30}\b(?:instructions?|prompts?|rules?)\b",
        r"\bdisregard\b[^.\n]{0,40}\b(?:instructions?|prompts?|rules?|guidelines)\b",
        r"\bforget\b[^.\n]{0,30}\b(?:instructions?|everything|previous)\b",
        r"\bignora\b[^.\n]{0,40}\b(?:instrucciones|indicaciones|reglas)\b",
        r"^\s*(?:system|assistant|developer)\s*:",
        r"<\|?(?:im_start|im_end|system|assistant)\|?>|\[/?INST\]|<<SYS>>",
        r"\b(?:new|updated|override)\s+(?:system\s+)?instructions?\b",
        r"\byou\s+are\s+(?:now\s+)?(?:an?\s+)?(?:ai|assistant|language\s+model|llm|chatbot)\b",
        r"\b(?:dear|attention|note\s+to)\s+(?:ai|llm|assistant|language\s+model|model)\b",
        r"\b(?:reveal|print|show|repeat)\b[^.\n]{0,20}\b(?:system\s+prompt|your\s+instructions)\b",
        r"\b(?:do\s+not|don't|never)\s+(?:flag|report|mention|alert|escalate)\b[^.\n]{0,40}\b(?:this|vulnerabilit|cve)",
        r"\b(?:rate|score|classify|mark)\s+this\b[^.\n]{0,30}\b(?:as\s+)?(?:low|harmless|benign|not\s+exploited)\b",
    )
)


@dataclass(frozen=True)
class CleanedText:
    text: str
    is_suspicious: bool


@dataclass(frozen=True)
class _HiddenSelectors:
    """Simple selectors (tag, .class, #id) that page style sheets hide; the last compound of a selector counts."""

    tags: frozenset[str] = frozenset()
    classes: frozenset[str] = frozenset()
    ids: frozenset[str] = frozenset()


def _hidden_selectors(html: str) -> _HiddenSelectors:
    tags: set[str] = set()
    classes: set[str] = set()
    ids: set[str] = set()
    for block in _STYLE_BLOCK.findall(html):
        for selectors, declarations in _CSS_RULE.findall(block):
            if not _HIDING_STYLE.search(declarations):
                continue
            for selector in selectors.split(","):
                parts = selector.replace(">", " ").replace("+", " ").replace("~", " ").split()
                match = _SIMPLE_SELECTOR.match(parts[-1]) if parts else None
                if match is None:
                    continue
                tag, kind, name = match.groups()
                if kind == "." and not tag:
                    classes.add(name.lower())
                elif kind == "#" and not tag:
                    ids.add(name.lower())
                elif tag and not kind:
                    tags.add(tag.lower())
    return _HiddenSelectors(frozenset(tags), frozenset(classes), frozenset(ids))


class _VisibleTextParser(HTMLParser):
    """Collects visible and hidden text apart; hidden covers dropped tags and hiding attributes or CSS."""

    def __init__(self, css_hidden: _HiddenSelectors | None = None) -> None:
        super().__init__(convert_charrefs=True)
        self._css = css_hidden or _HiddenSelectors()
        self.visible: list[str] = []
        self.hidden: list[str] = []
        self.markup: list[str] = []  # visible content as attribute-free HTML, for the article extractor
        self._stack: list[tuple[str, bool]] = []
        self._hidden_depth = 0

    def _hides(self, tag: str, attrs: list[tuple[str, str | None]]) -> bool:
        if tag in _DROPPED_TAGS or tag in self._css.tags:
            return True
        for name, value in attrs:
            if name == "class" and value and self._css.classes.intersection(value.lower().split()):
                return True
            if name == "id" and value and value.lower() in self._css.ids:
                return True
            if name == "hidden" or (name == "aria-hidden" and (value or "").lower() == "true"):
                return True
            if name == "style" and value and _HIDING_STYLE.search(value):
                return True
        return False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _BLOCK_TAGS:
            self.visible.append("\n")
        if tag in _VOID_TAGS:
            if not self._hidden_depth:
                self.markup.append(f"<{tag}>")
            return
        hides = self._hides(tag, attrs)
        self._stack.append((tag, hides))
        if hides:
            self._hidden_depth += 1
        if not self._hidden_depth:
            self.markup.append(f"<{tag}>")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _BLOCK_TAGS:
            self.visible.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in _BLOCK_TAGS:
            self.visible.append("\n")
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index][0] == tag:
                was_visible = not self._hidden_depth
                for _, hides in self._stack[index:]:
                    if hides:
                        self._hidden_depth -= 1
                del self._stack[index:]
                if was_visible:
                    self.markup.append(f"</{tag}>")
                return

    def handle_data(self, data: str) -> None:
        if self._hidden_depth:
            self.hidden.append(data)
        else:
            self.visible.append(data)
            self.markup.append(html_lib.escape(data))


def _normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(_INVISIBLE_CHARS)
    text = _CONTROL_CHARS.sub(" ", text)
    text = _BASE64_BLOCK.sub(" ", text)
    text = _SPACES.sub(" ", text)
    lines = (line.strip() for line in text.split("\n"))
    return _BLANK_LINES.sub("\n\n", "\n".join(lines)).strip()


def has_injection_markers(text: str) -> bool:
    """True when `text` (already normalized) carries instructions aimed at an AI (SEG-03)."""
    return any(pattern.search(text) for pattern in _INJECTION_PATTERNS)


def clean_html(html: str, max_chars: int = MAX_CLEAN_CHARS) -> CleanedText:
    """Plain visible text of an HTML fragment or page, with the hidden text kept only for detection."""
    parser = _VisibleTextParser(_hidden_selectors(html))
    parser.feed(html)
    parser.close()
    visible = _normalize("".join(parser.visible))
    hidden = _normalize(" ".join(parser.hidden))
    suspicious = has_injection_markers(visible) or has_injection_markers(hidden)
    return CleanedText(text=visible[:max_chars], is_suspicious=suspicious)


def visible_markup(html: str) -> str:
    """The page without scripts, hidden elements and attributes: input for the main-content extractor."""
    parser = _VisibleTextParser(_hidden_selectors(html))
    parser.feed(html)
    parser.close()
    return "".join(parser.markup)


def clean_plain(text: str, max_chars: int = MAX_CLEAN_CHARS) -> CleanedText:
    """Same normalization for text that is not HTML (titles, CSV and JSON fields)."""
    normalized = _normalize(text)
    return CleanedText(text=normalized[:max_chars], is_suspicious=has_injection_markers(normalized))
