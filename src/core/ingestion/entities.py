"""Entities the dedup layers can read before the news analyst runs (ING-05).

The analyst (F3) is the source of victims, actors and event types, but it only runs on stories, after dedup. Until
then the code uses deterministic extraction: CVE identifiers by pattern and a coarse event hint by keywords.
`EntityProvider` is the seam where analyst entities plug in (layers 4 and 5).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# First match wins: an exploited vulnerability that also has a patch is an exploitation story.
_EVENT_HINTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ransomware", re.compile(r"\bransom(?:ware)?\b|\bextorsi[oó]n\b", re.IGNORECASE)),
    (
        "exploitation",
        re.compile(
            r"\bexploit(?:ed|ation|ing)?\b|\bzero[- ]?day\b|\b0[- ]?day\b|\bin the wild\b"
            r"|\bexplota(?:ci[oó]n|d[ao]s?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "patch",
        re.compile(
            r"\bpatch(?:ed|es)?\b|\bsecurity update\b|\bhotfix\b|\bparche\b|\bactualizaci[oó]n\b", re.IGNORECASE
        ),
    ),
)
DEFAULT_EVENT_HINT = "disclosure"


@dataclass(frozen=True)
class ArticleEntities:
    cves: frozenset[str]
    event_hint: str
    victim: str | None = None
    actor: str | None = None


EntityProvider = Callable[[str, str | None], ArticleEntities]


def extract_cves(text: str) -> frozenset[str]:
    return frozenset(match.upper() for match in _CVE.findall(text))


def event_hint(text: str) -> str:
    for name, pattern in _EVENT_HINTS:
        if pattern.search(text):
            return name
    return DEFAULT_EVENT_HINT


def regex_entities(title: str, text: str | None) -> ArticleEntities:
    """Default provider: CVEs and the event hint from the title and text; no victim or actor."""
    combined = f"{title}\n{text or ''}"
    return ArticleEntities(cves=extract_cves(combined), event_hint=event_hint(combined))


def same_event(a: ArticleEntities, b: ArticleEntities) -> bool:
    """Layer 2: the same non-empty set of CVEs and the same type of event."""
    return bool(a.cves) and a.cves == b.cves and a.event_hint == b.event_hint


def same_attack(a: ArticleEntities, b: ArticleEntities) -> bool:
    """Layer 4: same victim and same actor, for attacks without CVE."""
    return bool(a.victim and a.actor) and (a.victim, a.actor) == (b.victim, b.actor)


def entities_agree(a: ArticleEntities, b: ArticleEntities) -> bool:
    """Layer 5 (gray zone): the same attack, or the same non-empty CVE set, whatever the event hint says."""
    return same_attack(a, b) or (bool(a.cves) and a.cves == b.cves)
