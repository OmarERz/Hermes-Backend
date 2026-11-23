"""Drafted mitigation validation (docs/07 §13 JUE-MIT-01 to 06) and adversarial cases E21, E22."""

from __future__ import annotations

from typing import Any

import pytest

from core.judge.mitigation import MitigationStatus, appears_as_fact, traceable_facts, validate_mitigation
from core.judge.package import ReviewPackage
from harness.judge import finding_package

pytestmark = pytest.mark.unit

FIX_QUOTE = "A heap overflow in Example HTTP Server before 2.4.60 allows remote attackers"
TEMP_QUOTE = "Successful exploitation requires the mod_proxy module to be enabled."


def package(content: dict[str, Any] | None = None) -> ReviewPackage:
    return ReviewPackage.from_content(content or finding_package())


def step(order: int = 1, **overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "order": order,
        "ci_id": "",
        "action": "Actualizar Example HTTP Server a 2.4.60 o posterior.",
        "element_id": "cve-1",
        "quote": FIX_QUOTE,
    }
    values.update(overrides)
    return values


def test_empty_draft_is_absent() -> None:
    result = validate_mitigation([], package())
    assert result.status is MitigationStatus.ABSENT
    assert result.steps == ()
    assert result.rule is None


def test_valid_draft_is_accepted_and_sorted() -> None:
    temp = step(2, action="Deshabilitar el módulo mod_proxy de forma temporal.", quote=TEMP_QUOTE, ci_id="CI-2")
    result = validate_mitigation([temp, step(1)], package())
    assert result.status is MitigationStatus.ACCEPTED
    assert [s.order for s in result.steps] == [1, 2]
    assert result.steps[0].ci_id is None
    assert result.steps[1].ci_id == "CI-2"
    assert result.steps[1].element_id == "cve-1"


def test_e21_news_is_never_a_mitigation_source() -> None:
    news_step = step(
        action="Desactivar la protección del servidor.",
        element_id="news-1",
        quote="Researchers observed mass exploitation of CVE-2026-1111",
    )
    result = validate_mitigation([step(1), {**news_step, "order": 2}], package())
    assert result.status is MitigationStatus.DISCARDED
    assert result.rule == "JUE-MIT-01"
    assert result.steps == ()


def test_n1_news_and_ci_elements() -> None:
    content = finding_package()
    content["news"][0]["source_level"] = "N1"
    n1 = step(element_id="news-1", action="Revisar el aviso.", quote="Researchers observed mass exploitation")
    assert validate_mitigation([n1], package(content)).status is MitigationStatus.ACCEPTED
    ci = step(element_id="ci-2", action="Revisar el servidor.", quote="Este servidor procesa los pagos")
    assert validate_mitigation([ci], package()).rule == "JUE-MIT-01"
    missing = step(element_id="nope")
    assert validate_mitigation([missing], package()).rule == "JUE-MIT-01"


def test_quote_must_be_verbatim() -> None:
    assert validate_mitigation([step(quote="A heap overflow in some server")], package()).rule == "JUE-MIT-02"
    assert validate_mitigation([step(quote="heap")], package()).rule == "JUE-MIT-02"


def test_e22_invented_version_discards_the_whole_draft() -> None:
    result = validate_mitigation([step(action="Actualizar a 3.0.99 de inmediato.")], package())
    assert result.status is MitigationStatus.DISCARDED
    assert result.rule == "JUE-MIT-03"


@pytest.mark.parametrize(
    "action",
    [
        "Consultar https://evil.example.test/fix para el parche.",
        "Ejecutar `apachectl -k graceful` tras el cambio.",
        "Editar /etc/httpd/conf/httpd.conf y reiniciar.",
    ],
)
def test_untraceable_urls_commands_and_paths_are_rejected(action: str) -> None:
    assert validate_mitigation([step(action=action)], package()).rule == "JUE-MIT-03"


def test_analyst_parts_of_the_cve_element_are_not_a_source() -> None:
    conditions = step(action="Revisar si mod_proxy está activo.", quote='conditions: [{"text": "mod_proxy enabled"}]')
    assert validate_mitigation([conditions], package()).rule == "JUE-MIT-01"


@pytest.mark.parametrize(
    "action",
    ["Actualizar a 2.4.6 de inmediato.", "Actualizar a 2.4 o posterior.", "Ver https://vendor.example.test/adv."],
)
def test_facts_must_match_whole_not_as_a_prefix(action: str) -> None:
    content = finding_package()
    content["cve_data"]["description"] += " Advisory: https://vendor.example.test/advisories/2026-1111."
    quote = "before 2.4.60 allows remote attackers to execute code via crafted headers. Successful"
    url_quote = "Advisory: https://vendor.example.test/advisories/2026-1111."
    for q in (quote, url_quote):
        assert validate_mitigation([step(action=action, quote=q)], package(content)).rule == "JUE-MIT-03"


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("Actualizar a v2.4.99 de inmediato.", ["2.4.99"]),
        ("Actualizar a la versión 126.", ["126"]),
        ("Descargar el parche de evil.example.com/fix.sh", ["evil.example.com/fix.sh"]),
        ("Ver www.evil.test/p", ["www.evil.test/p"]),
        ("Seguir el paso 1 del aviso.", []),
        ("Descargar ftp://evil.example.com/fix.sh", ["ftp://evil.example.com/fix.sh"]),
        ("Ver HTTPS://evil.example.com/x", ["HTTPS://evil.example.com/x"]),
        ("Ver hxxps://evil.test/p", ["hxxps://evil.test/p"]),
    ],
)
def test_prefixed_versions_and_bare_hosts_are_facts(action: str, expected: list[str]) -> None:
    assert traceable_facts(action) == expected
    assert validate_mitigation([step(action=action)], package()).status is (
        MitigationStatus.DISCARDED if expected else MitigationStatus.ACCEPTED
    )


def test_a_v_prefixed_version_matches_the_quote() -> None:
    assert validate_mitigation([step(action="Actualizar a v2.4.60.")], package()).status is MitigationStatus.ACCEPTED


def test_fact_at_the_end_of_a_sentence_still_matches() -> None:
    quote = "A heap overflow in Example HTTP Server before 2.4.60 allows remote attackers"
    assert appears_as_fact("2.4.60", quote)
    assert appears_as_fact("2.4.60", "fixed in 2.4.60.")
    assert not appears_as_fact("2.4.6", "fixed in 2.4.60.")
    assert not appears_as_fact("4.60", "fixed in 2.4.60.")


def test_traceable_facts_extraction() -> None:
    facts = traceable_facts(
        "Ver https://vendor.example.test/advisories/2026-1111. Instalar 2.4.60, correr `make install` y "
        "revisar ./conf/app.conf; y/o el puerto."
    )
    assert facts == [
        "https://vendor.example.test/advisories/2026-1111",
        "make install",
        "2.4.60",
        "./conf/app.conf",
    ]
    assert traceable_facts("Aplicar el parche del fabricante.") == []


def test_url_present_in_the_quote_is_accepted() -> None:
    content = finding_package()
    content["cve_data"]["description"] += " See https://vendor.example.test/advisories/2026-1111 for details."
    action = "Seguir https://vendor.example.test/advisories/2026-1111."
    quote = "See https://vendor.example.test/advisories/2026-1111 for details."
    assert validate_mitigation([step(action=action, quote=quote)], package(content)).status is MitigationStatus.ACCEPTED


def test_ci_must_belong_to_the_package() -> None:
    assert validate_mitigation([step(ci_id="CI-9")], package()).rule == "JUE-MIT-04"


@pytest.mark.parametrize("orders", [[1, 1], [2, 3], [0, 1]])
def test_orders_must_be_one_to_n(orders: list[int]) -> None:
    steps = [step(order) for order in orders]
    assert validate_mitigation(steps, package()).rule == "JUE-MIT-06"


@pytest.mark.parametrize(
    "bad",
    [{"action": "  "}, {"action": "x" * 1001}, {"quote": FIX_QUOTE + " " + "y" * 1000}],
)
def test_lengths_the_strict_mode_cannot_express(bad: dict[str, Any]) -> None:
    assert validate_mitigation([step(**bad)], package()).rule == "VAL-02"


def test_too_many_steps() -> None:
    steps = [step(i) for i in range(1, 22)]
    assert validate_mitigation(steps, package()).rule == "VAL-02"


def test_a_step_from_a_suspicious_vendor_advisory_discards_the_draft() -> None:
    """SEG-03: an N1 element flagged as suspicious is never a source for a step (pending F6.1 #63)."""
    content = finding_package()
    news = content["news"][0]
    news["source_level"], news["suspicious"] = "N1", True
    quote = "Researchers observed mass exploitation of CVE-2026-1111"
    draft = [step(action="Revisar los servidores expuestos.", element_id="news-1", quote=quote)]
    trusted = validate_mitigation(draft, package(content))
    assert (trusted.status, trusted.rule) == (MitigationStatus.DISCARDED, "JUE-MIT-01")
    news["suspicious"] = False
    clean = validate_mitigation(draft, package(content))
    assert clean.status is MitigationStatus.ACCEPTED
