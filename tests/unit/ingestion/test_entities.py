"""CVE extraction, event hints and the entity rules of dedup layers 2, 4 and 5."""

from __future__ import annotations

import pytest

from core.ingestion.entities import (
    ArticleEntities,
    entities_agree,
    event_hint,
    extract_cves,
    regex_entities,
    same_attack,
    same_event,
)


def test_cves_are_found_normalized_and_deduplicated() -> None:
    text = "Fixes cve-2026-1234 and CVE-2026-1234, plus CVE-2025-99999; CVE-26-1 is not valid."
    assert extract_cves(text) == {"CVE-2026-1234", "CVE-2025-99999"}
    assert extract_cves("nothing here") == frozenset()


@pytest.mark.parametrize(
    ("text", "hint"),
    [
        ("A ransomware gang hits a hospital", "ransomware"),
        ("Actively exploited zero-day gets a patch", "exploitation"),
        ("Vendor ships a security update for the flaw", "patch"),
        ("Researchers describe a new flaw", "disclosure"),
        ("Hay explotación activa del fallo", "exploitation"),
    ],
)
def test_event_hint(text: str, hint: str) -> None:
    assert event_hint(text) == hint


def test_regex_entities_use_title_and_text() -> None:
    entities = regex_entities("Title CVE-2026-0001", "Attackers exploit it")
    assert entities.cves == {"CVE-2026-0001"}
    assert entities.event_hint == "exploitation"
    entities = regex_entities("Title CVE-2026-0001", None)
    assert entities == ArticleEntities(cves=frozenset({"CVE-2026-0001"}), event_hint="disclosure")


def test_layer_rules() -> None:
    a = ArticleEntities(frozenset({"CVE-2026-0001"}), "exploitation")
    b = ArticleEntities(frozenset({"CVE-2026-0001"}), "exploitation")
    c = ArticleEntities(frozenset({"CVE-2026-0001"}), "patch")
    d = ArticleEntities(frozenset({"CVE-2026-0001", "CVE-2026-0002"}), "exploitation")
    empty = ArticleEntities(frozenset(), "disclosure")
    assert same_event(a, b)
    assert not same_event(a, c)
    assert not same_event(a, d)
    assert not same_event(empty, empty)
    assert not entities_agree(a, c)  # regex entities alone never settle a gray-zone pair
    assert not entities_agree(empty, empty)

    x = ArticleEntities(frozenset(), "disclosure", victim="acme", actor="lockbit")
    y = ArticleEntities(frozenset(), "ransomware", victim="acme", actor="lockbit")
    z = ArticleEntities(frozenset(), "ransomware", victim="acme", actor=None)
    assert same_attack(x, y)
    assert entities_agree(x, y)
    assert not same_attack(z, z)
    assert not same_attack(x, ArticleEntities(frozenset(), "x", victim="other", actor="lockbit"))


def test_attack_layers_need_analyst_entities_and_respect_cves() -> None:
    with_cve = ArticleEntities(frozenset({"CVE-2026-0001"}), "exploitation", victim="acme", actor="lockbit")
    other_cve = ArticleEntities(frozenset({"CVE-2026-0002"}), "exploitation", victim="acme", actor="lockbit")
    no_cve = ArticleEntities(frozenset(), "exploitation", victim="acme", actor="lockbit")
    assert not same_attack(with_cve, with_cve)  # layer 4 is for attacks without CVE
    assert not same_attack(with_cve, no_cve)
    assert not entities_agree(with_cve, other_cve)  # different CVE sets: different facts
    assert entities_agree(with_cve, no_cve)  # one side names no CVE: the victim and actor decide
    assert entities_agree(with_cve, with_cve)
    plain = regex_entities("t", "CVE-2026-0001 exploited")
    assert not entities_agree(plain, plain)  # no analyst entities: nothing agrees
