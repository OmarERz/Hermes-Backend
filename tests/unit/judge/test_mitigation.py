"""Drafted mitigation validation (docs/07 §13 JUE-MIT-01 to 06) and adversarial cases E21, E22."""

from __future__ import annotations

import signal
import time
from typing import Any

import pytest

from core.judge.mitigation import (
    FactKind,
    MitigationStatus,
    TraceableFact,
    appears_as_fact,
    traceable_facts,
    validate_mitigation,
)
from core.judge.package import ReviewPackage
from harness.judge import finding_package

pytestmark = pytest.mark.unit

FIX_QUOTE = "A heap overflow in Example HTTP Server before 2.4.60 allows remote attackers"
TEMP_QUOTE = "Successful exploitation requires the mod_proxy module to be enabled."


def package(content: dict[str, Any] | None = None) -> ReviewPackage:
    return ReviewPackage.from_content(content or finding_package())


def texts(action: str) -> list[str]:
    return [fact.text for fact in traceable_facts(action)]


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
    assert texts(action) == expected
    assert validate_mitigation([step(action=action)], package()).status is (
        MitigationStatus.DISCARDED if expected else MitigationStatus.ACCEPTED
    )


OPENSSL_RANGE = "openssl:openssl [3.0.0,3.0.23)"  # how the package renders an NVD range (real batch of 23 nov)


def openssl_package(extra_description: str = "") -> ReviewPackage:
    content = finding_package()
    content["cve_data"]["affected_ranges"] = [OPENSSL_RANGE]
    content["cve_data"]["description"] += extra_description
    return package(content)


@pytest.mark.parametrize(
    "action",
    [
        "Actualizar OpenSSL de la rama 3.0 a la versión 3.0.23 o posterior.",  # #176: real draft 1
        "Actualizar OpenSSL 3.0.x a 3.0.23.",  # #176: real draft 2
        "Actualizar OpenSSL 3.0.X o 3.0.* a 3.0.23.",
        "Identificar los equipos con OpenSSL de la serie 3.0 o de la línea v3.0.",
        "Upgrade OpenSSL from the 3.0 branch to 3.0.23.",
        "Actualizar OpenSSL 3.x a 3.0.23.",  # x stands for one or more numbers: 3.0.0 is in the 3.x line
    ],
)
def test_176_a_branch_of_a_quoted_version_is_traceable(action: str) -> None:
    result = validate_mitigation([step(action=action, quote=OPENSSL_RANGE)], openssl_package())
    assert (result.status, result.rule) == (MitigationStatus.ACCEPTED, None)


@pytest.mark.parametrize(
    "action",
    [
        "Actualizar OpenSSL de la rama 3.0 a 3.0.99.",  # E22: a made-up fix version next to a real branch
        "Actualizar OpenSSL de la rama 3.1 a 3.0.23.",  # a branch with no version in the quote
        "Actualizar OpenSSL 3.1.x a 3.0.23.",
        "Actualizar OpenSSL 1.x a 3.0.23.",
        "Actualizar OpenSSL de la rama 13.0 a 3.0.23.",  # 3.0.0 is not in the 13.0 branch
        "Actualizar OpenSSL de la rama 3.0.2 a 3.0.23.",  # 3.0.23 is not in the 3.0.2 branch
        "Actualizar OpenSSL a 3.0 o posterior.",  # written as a version, not a branch: it must appear whole
        "Actualizar OpenSSL de la rama 3.0.0-rc1 a 3.0.23.",  # a suffix keeps the strict version check
        "Actualizar OpenSSL 3.0.x-rc1 a 3.0.23.",
        "Ejecutar `3.0.x` y actualizar a 3.0.23.",  # a command keeps the textual check even if it looks like a branch
    ],
)
def test_a_branch_or_version_missing_from_the_quote_still_discards(action: str) -> None:
    result = validate_mitigation([step(action=action, quote=OPENSSL_RANGE)], openssl_package())
    assert (result.status, result.rule) == (MitigationStatus.DISCARDED, "JUE-MIT-03")


def test_a_v_prefixed_version_in_the_quote_backs_the_branch_and_the_version() -> None:
    quote = "Fixed in OpenSSL v3.0.23."
    action = "Actualizar OpenSSL de la rama 3.0 a 3.0.23."
    result = validate_mitigation([step(action=action, quote=quote)], openssl_package(f" {quote}"))
    assert (result.status, result.rule) == (MitigationStatus.ACCEPTED, None)
    made_up = validate_mitigation([step(action="Actualizar a 3.0.24.", quote=quote)], openssl_package(f" {quote}"))
    assert made_up.rule == "JUE-MIT-03"


@pytest.mark.parametrize("quote", ["Fixed in OpenSSL v3.0.23~rc1.", "Fixed in OpenSSL 3.0.23+rc1."])
def test_a_pre_release_in_the_quote_does_not_back_the_final_version(quote: str) -> None:
    action = "Actualizar OpenSSL a 3.0.23."
    result = validate_mitigation([step(action=action, quote=quote)], openssl_package(f" {quote}"))
    assert (result.status, result.rule) == (MitigationStatus.DISCARDED, "JUE-MIT-03")


def test_a_debian_version_copied_as_quoted_is_one_whole_fact() -> None:
    quote = "Fixed in openssl 3.0.11-1~deb12u2 for bookworm."
    action = "Actualizar openssl a 3.0.11-1~deb12u2."
    assert texts(action) == ["3.0.11-1~deb12u2"]
    result = validate_mitigation([step(action=action, quote=quote)], openssl_package(f" {quote}"))
    assert (result.status, result.rule) == (MitigationStatus.ACCEPTED, None)
    truncated = validate_mitigation(
        [step(action="Actualizar openssl a 3.0.11-1.", quote=quote)], openssl_package(f" {quote}")
    )
    assert truncated.rule == "JUE-MIT-03"


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("Actualizar OpenSSL de la rama 3.0 a la versión 3.0.23.", ["3.0.x", "3.0.23"]),
        ("Actualizar v3.0.X y 3.* a 3.0.23.", ["3.0.x", "3.x", "3.0.23"]),
        ("Upgrade the 2.4 series, then the branches 2.6 and the 2.8 line.", ["2.4.x", "2.6.x", "2.8.x"]),
        ("Actualizar a 3.0.x.", ["3.0.x"]),
        ("Revisar el binario x86_64 de 3.0.23.", ["3.0.23"]),
        ("Ejecutar `3.0.x`.", ["3.0.x", "3.0.x"]),  # once as a command, once as a branch
    ],
)
def test_branches_are_facts_of_their_own(action: str, expected: list[str]) -> None:
    assert texts(action) == expected


@pytest.mark.parametrize(
    ("quote", "backed"),
    [
        ("[3.0.0,3.0.23)", True),  # a version of the branch
        ("OpenSSL 3.0 is affected.", True),  # the branch itself, whole
        ("affects 3.0.x only", True),  # the same wildcard in the source
        ("Fixed in v3.0.23.", True),
        ("fixed in 13.0.1", False),
        ("fixed in 2.3.0.1", False),
        ("fixed in 3.01", False),
        ("fixed in 3.0.23.1", True),  # four numbers, as in browser versions: still the 3.0 line
        ("fixed in 3.0-rc1", True),  # a pre-release of the line is in the line
        ("fixed in 3.0.23+deb12u1", True),  # so is a descendant version with a suffix
        ("fixed in 3.0.23~rc1", True),
        ("fixed in 3.0.11-1~deb12u2", True),
        ("affects 3.0.x-rc1", False),
        ("affects 3.0.*-rc1", False),  # no backtracking from the whole token to the bare line
        ("fixed in 3.0.x86", False),
        ("see openssl-3.0.23.tar.gz", False),
    ],
)
def test_a_branch_needs_one_of_its_versions_as_a_whole_token(quote: str, backed: bool) -> None:
    assert TraceableFact(FactKind.BRANCH, "3.0.x").in_quote(quote) is backed


def test_a_major_branch_is_backed_by_any_version_of_its_line() -> None:
    assert TraceableFact(FactKind.BRANCH, "3.x").in_quote(OPENSSL_RANGE)
    assert TraceableFact(FactKind.BRANCH, "3.x").in_quote("affects 3.x only")
    assert not TraceableFact(FactKind.BRANCH, "3.x").in_quote("fixed in 13.0.0")
    assert not TraceableFact(FactKind.BRANCH, "4.x").in_quote(OPENSSL_RANGE)


def test_a_bare_number_does_not_back_a_major_branch() -> None:
    quote = "We identified 3 affected hosts."
    assert not TraceableFact(FactKind.BRANCH, "3.x").in_quote(quote)
    assert not TraceableFact(FactKind.BRANCH, "3.x").in_quote("3-rc1 is affected")
    result = validate_mitigation([step(action="Actualizar OpenSSL 3.x.", quote=quote)], openssl_package(f" {quote}"))
    assert result.rule == "JUE-MIT-03"


def test_a_debian_version_backs_its_branch() -> None:
    quote = "Fixed in openssl 3.0.11-1~deb12u2 for bookworm."
    action = "Actualizar openssl de la rama 3.0 a 3.0.11-1~deb12u2."
    result = validate_mitigation([step(action=action, quote=quote)], openssl_package(f" {quote}"))
    assert (result.status, result.rule) == (MitigationStatus.ACCEPTED, None)


@pytest.mark.parametrize("action", ["Actualizar a 3.0.x-rc1.", "Actualizar a 3.0.x86.", "Actualizar a 3.0.*-rc1."])
def test_a_wildcard_with_a_tail_is_one_version_fact_not_a_truncated_version(action: str) -> None:
    quote = "The 3.0 line is affected."
    assert [fact.kind for fact in traceable_facts(action)] == [FactKind.VERSION]
    result = validate_mitigation([step(action=action, quote=quote)], openssl_package(f" {quote}"))
    assert result.rule == "JUE-MIT-03"


def test_a_letter_version_is_read_whole() -> None:
    quote = "Fixed in OpenSSL 1.1.1w and later."
    assert texts("Actualizar OpenSSL de la rama 1.1 a 1.1.1w.") == ["1.1.x", "1.1.1w"]
    for action in ("Actualizar OpenSSL a 1.1.1w.", "Actualizar OpenSSL 1.1.x a 1.1.1w."):
        result = validate_mitigation([step(action=action, quote=quote)], openssl_package(f" {quote}"))
        assert (result.status, result.rule) == (MitigationStatus.ACCEPTED, None)
    other = validate_mitigation([step(action="Actualizar a 1.1.1x.", quote=quote)], openssl_package(f" {quote}"))
    assert other.rule == "JUE-MIT-03"


def test_only_branch_facts_get_the_branch_match() -> None:
    quote = "OpenSSL 3.0.23 fixes it."
    assert TraceableFact(FactKind.BRANCH, "3.0.x").in_quote(quote)
    assert not TraceableFact(FactKind.COMMAND, "3.0.x").in_quote(quote)
    assert not TraceableFact(FactKind.VERSION, "3.0").in_quote(quote)
    assert TraceableFact(FactKind.VERSION, "3.0.23").in_quote("fixed in V3.0.23")
    assert not TraceableFact(FactKind.COMMAND, "3.0.23").in_quote("fixed in v3.0.23")


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("Instalar la versión 3.0.23 64-bit de OpenSSL.", ["3.0.23"]),  # 64 is not a version once 3.0.23 is read
        ("Actualizar la rama 4 de OpenSSL a 3.0.23.", ["4.x", "3.0.23"]),  # a major branch is a fact too
        ("Actualizar OpenSSL de la rama «3.0» a 3.0.23.", ["3.0.x", "3.0.23"]),
        ('Upgrade the "3.0" branch to 3.0.23.', ["3.0.x", "3.0.23"]),
        ("Editar la línea 42 del archivo de configuración.", []),  # a line number is not a branch
        ("Use the 4 branch of OpenSSL and update to 3.0.23.", ["4.x", "3.0.23"]),
        ("Keep the 3 branches in sync.", []),  # a count of branches is not a branch
        ("Actualizar la serie 4 de OpenSSL a 3.0.23.", ["4.x", "3.0.23"]),
    ],
)
def test_forced_t1_findings_extraction(action: str, expected: list[str]) -> None:
    assert texts(action) == expected


@pytest.mark.parametrize(
    ("action", "status"),
    [
        ("Instalar la versión 3.0.23 64-bit de OpenSSL.", MitigationStatus.ACCEPTED),
        ("Actualizar OpenSSL de la rama «3.0» a 3.0.23.", MitigationStatus.ACCEPTED),
        ("Actualizar OpenSSL de la rama “3.0” a 3.0.23.", MitigationStatus.ACCEPTED),
        ("Actualizar la rama 3 de OpenSSL a 3.0.23.", MitigationStatus.ACCEPTED),
        ("Actualizar la rama 4 de OpenSSL a 3.0.23.", MitigationStatus.DISCARDED),
        ("Use the 4 branch of OpenSSL and update to 3.0.23.", MitigationStatus.DISCARDED),
        ("Actualizar la serie 4 de OpenSSL a 3.0.23.", MitigationStatus.DISCARDED),
        ("Actualizar la serie 3 de OpenSSL a 3.0.23.", MitigationStatus.ACCEPTED),
        ("Actualizar OpenSSL de la rama «3.1» a 3.0.23.", MitigationStatus.DISCARDED),
    ],
)
def test_forced_t1_findings_validation(action: str, status: MitigationStatus) -> None:
    result = validate_mitigation([step(action=action, quote=OPENSSL_RANGE)], openssl_package())
    assert result.status is status
    assert result.rule == (None if status is MitigationStatus.ACCEPTED else "JUE-MIT-03")


@pytest.mark.parametrize(
    ("quote", "backed"),
    [
        ("For help, contact 3.0.23.support.example.", False),  # a host name is not a version
        ("For help, contact 3.0.23-1.support.example.", False),
        ("For help, contact 3.0.23.SUPPORT.EXAMPLE.", False),  # in any case
        ("See DOCS.EXAMPLE.ORG/?id=3.0.23 for help.", False),
        ("See docs.example.org?id=3.0.23 for help.", False),  # a query without a path
        ("See docs.example.org:8443/?id=3.0.23 for help.", False),  # a port
        ("See 10.0.0.1:8443/?id=3.0.23 for help.", False),
        ("For help, contact 3.0.23.example.", False),  # one alphabetic label that is no version qualifier
        ("Fixed in v3.0.0rc1.", True),
        ("Fixed in 3.0.0.beta.", True),
        ("Is it fixed in 3.0.23?", True),  # a question mark alone is no query
        ("Fixed in 1.1.1w and 3.0.23.", True),
        ("See https://docs.example.org/?id=3.0.23 for help.", False),  # nor a URL
        ("See docs.example.org/?id=3.0.23 for help.", False),
        ("see 3.0.23.tar.gz", False),
        ("fixed in 3.0.23-1.el9_2", True),  # a Red Hat release of the line
        ("fixed in 3.0.0rc1", True),
        ("Fixed in version 3.0.23.post1.", True),
        ("Fixed in 3.0.23.Final.", True),
        ("Fixed in 3.0.23 (see docs.example.org).", True),
    ],
)
def test_a_branch_is_not_backed_by_a_host_name(quote: str, backed: bool) -> None:
    assert TraceableFact(FactKind.BRANCH, "3.0.x").in_quote(quote) is backed


@pytest.mark.parametrize(
    ("action", "version", "quote"),
    [
        ("Actualizar httpd a 2.4.57-5.el9_2.", "2.4.57-5.el9_2", "Fixed in httpd 2.4.57-5.el9_2 for RHEL 9."),
        ("Actualizar OpenSSL a 3.0.23.post1.", "3.0.23.post1", "Fixed in version 3.0.23.post1."),
    ],
)
def test_a_suffixed_version_copied_as_quoted_is_not_read_as_a_host(action: str, version: str, quote: str) -> None:
    assert [(fact.kind, fact.text) for fact in traceable_facts(action)] == [(FactKind.VERSION, version)]
    result = validate_mitigation([step(action=action, quote=quote)], openssl_package(f" {quote}"))
    assert (result.status, result.rule) == (MitigationStatus.ACCEPTED, None)


def test_hosts_are_still_facts_in_any_case() -> None:
    assert [(f.kind, f.text) for f in traceable_facts("Descargar de EVIL.EXAMPLE.COM/x.")] == [
        (FactKind.HOST, "EVIL.EXAMPLE.COM/x")
    ]
    assert [f.text for f in traceable_facts("Ver evil.example.com2 ahora.")] == ["evil.example.com2"]  # whole
    assert texts("Ver e.g. U.S.A. y 1password.com") == ["1password.com"]
    assert texts("Ver docs.example.org:8443/?id=3.0.23 ya.") == ["docs.example.org:8443/?id=3.0.23"]
    assert texts("Ver docs.example.org?id=3.0.23 ya.") == ["docs.example.org?id=3.0.23"]


def test_a_host_is_never_truncated_to_one_the_quote_has() -> None:
    quote = "Contact vendor.example for the fix."
    result = validate_mitigation(
        [step(action="Consultar vendor.example.invalid2.", quote=quote)], openssl_package(f" {quote}")
    )
    assert result.rule == "JUE-MIT-03"


def test_a_url_in_the_quote_does_not_back_a_version_either() -> None:
    assert not TraceableFact(FactKind.VERSION, "3.0.23").in_quote("See https://docs.example.org/?id=3.0.23 now.")
    assert not TraceableFact(FactKind.VERSION, "3.0.23").in_quote("See DOCS.EXAMPLE.ORG/?id=3.0.23 now.")
    assert TraceableFact(FactKind.VERSION, "5.4.24.Final").in_quote("Fixed in 5.4.24.Final.")
    assert TraceableFact(FactKind.VERSION, "2.4.57-5.el9").in_quote("Fixed in httpd-2.4.57-5.el9 too.") is False
    assert TraceableFact(FactKind.VERSION, "2.4.57-5.el9").in_quote("Fixed in httpd 2.4.57-5.el9 too.")
    assert TraceableFact(FactKind.VERSION, "3.0.23").in_quote("Fixed in 3.0.23, see https://docs.example.org/.")
    assert TraceableFact(FactKind.VERSION, "3.0.23.post1").in_quote("Fixed in version 3.0.23.post1.")


@pytest.mark.parametrize("action", ["Actualizar OpenSSL a 3.0.0rc1.", "Actualizar OpenSSL de la rama 3.0 a v3.0.0rc1."])
def test_a_v_prefixed_suffixed_version_in_the_quote_backs_the_step(action: str) -> None:
    quote = "Fixed in v3.0.0rc1."
    assert all(fact.kind is not FactKind.HOST for fact in traceable_facts(action))
    result = validate_mitigation([step(action=action, quote=quote)], openssl_package(f" {quote}"))
    assert (result.status, result.rule) == (MitigationStatus.ACCEPTED, None)


@pytest.mark.parametrize(
    "quote", ["See docs.example.org?id=3.0.23 for help.", "For help, contact 3.0.23.example.", "See 3.0.23.com now."]
)
def test_an_address_in_the_quote_does_not_back_a_version_step(quote: str) -> None:
    for action in ("Actualizar OpenSSL a 3.0.23.", "Actualizar OpenSSL de la rama 3.0."):
        result = validate_mitigation([step(action=action, quote=quote)], openssl_package(f" {quote}"))
        assert result.rule == "JUE-MIT-03", (action, quote)


def test_a_host_name_in_the_quote_does_not_back_a_branch_step() -> None:
    quote = "For help, contact 3.0.23.support.example."
    result = validate_mitigation(
        [step(action="Actualizar OpenSSL de la rama 3.0.", quote=quote)], openssl_package(f" {quote}")
    )
    assert result.rule == "JUE-MIT-03"


@pytest.mark.parametrize(
    ("action", "quote", "kinds"),
    [
        ("Consultar docs.example.org/ para el parche.", "Ver docs.example.org/ para el parche.", [FactKind.HOST]),
        ("Consultar 3.0.23.example para el parche.", "Consultar 3.0.23.example para el parche.", [FactKind.HOST]),
        ("Bloquear 192.0.2.10:8443/ en el firewall.", "Bloquear 192.0.2.10:8443/ en el firewall.", [FactKind.HOST]),
        ("Actualizar a 2.17.1.redhat-00001.", "Fixed in 2.17.1.redhat-00001.", [FactKind.VERSION]),
        (
            "Actualizar la rama 2.17 a 2.17.1.redhat-00001.",
            "Fixed in 2.17.1.redhat-00001.",
            [FactKind.BRANCH, FactKind.VERSION],
        ),
    ],
)
def test_action_and_quote_read_a_dotted_name_the_same_way(action: str, quote: str, kinds: list[FactKind]) -> None:
    assert [fact.kind for fact in traceable_facts(action)] == kinds
    result = validate_mitigation([step(action=action, quote=quote)], openssl_package(f" {quote}"))
    assert (result.status, result.rule) == (MitigationStatus.ACCEPTED, None)


@pytest.mark.parametrize(
    ("quote", "backed"),
    [
        ("For help, contact 3.0.23.dev.", False),  # qualifier words that are also domain endings do not count
        ("For help, contact 3.0.23.ga.", False),
        ("Fixed in 3.0.0.dev0.", True),  # with a number they are versions
        ("Fixed in 3.0.17.redhat-00001.", True),
    ],
)
def test_qualifier_words_that_are_domain_endings(quote: str, backed: bool) -> None:
    assert TraceableFact(FactKind.BRANCH, "3.0.x").in_quote(quote) is backed


def test_dotted_names_are_read_in_linear_time() -> None:
    """Many numbered labels with a failing tail must not backtrack combinatorially (ReDoS, ~990 characters)."""
    name = ".".join(["1" * 10] * 90) + "ab-"

    def hang(*_: object) -> None:
        raise TimeoutError("catastrophic backtracking")

    previous = signal.signal(signal.SIGALRM, hang)
    signal.alarm(10)
    try:
        start = time.perf_counter()
        traceable_facts(f"Ver {name} ahora.")
        TraceableFact(FactKind.BRANCH, "1.x").in_quote(f"Ver {name} ahora.")
        assert time.perf_counter() - start < 1
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


@pytest.mark.parametrize(
    ("fact", "quote", "backed"),
    [
        (TraceableFact(FactKind.HOST, "3.0.23.example"), "Ver 3.0.23.example ahora.", True),
        (TraceableFact(FactKind.HOST, "3.0.23.example"), "Ver 3.0.23.example:8443 ahora.", False),  # whole address
        (TraceableFact(FactKind.HOST, "docs.example.org/"), "Ver docs.example.org/?x=1 ahora.", False),
        (TraceableFact(FactKind.HOST, "vendor.example.com"), "Escribir a user@vendor.example.com.", True),
        (TraceableFact(FactKind.URL, "https://a.example/x"), "Ver https://a.example/x.", True),
        (TraceableFact(FactKind.URL, "https://a.example/x"), "Ver https://a.example/x?y=1 ahora.", False),
    ],
)
def test_addresses_are_compared_whole(fact: TraceableFact, quote: str, backed: bool) -> None:
    assert fact.in_quote(quote) is backed


@pytest.mark.parametrize(
    ("quote", "backed"),
    [
        ("Fixed in version 3.0.23.post.", True),  # an explicit version: '.post' is the qualifier, not a domain
        ("Fixed in release 3.0.23.dev.", True),
        ("For help, contact 3.0.23.post.", False),
    ],
)
def test_a_qualifier_that_is_a_domain_ending_counts_after_a_version_word(quote: str, backed: bool) -> None:
    assert TraceableFact(FactKind.BRANCH, "3.0.x").in_quote(quote) is backed


@pytest.mark.parametrize(
    ("action", "quote", "kinds", "status"),
    [
        # The version word classifies the same text as a version in the action and in the quote.
        ("Actualizar a la versión 3.0.23.post.", "Fixed in version 3.0.23.post.", [FactKind.VERSION], "accepted"),
        ("Actualizar a 3.0.23.post.", "Fixed in version 3.0.23.post.", [FactKind.HOST], "discarded"),
        ("Actualizar a 3.0.23.dev+local.", "Fixed in version 3.0.23.dev.", [FactKind.HOST], "discarded"),  # whole
        (
            "Ver https://vendor.example/advisory.",
            "See [https://vendor.example/advisory] now.",
            [FactKind.URL],
            "accepted",
        ),
        ("Ver https://vendor.example/adv.", "See [https://vendor.example/advisory] now.", [FactKind.URL], "discarded"),
        ("Consultar vendor.example.", "Consultar vendor.exampleé hoy.", [FactKind.HOST], "discarded"),
        ("Consultar vendor.exampleé.", "Consultar vendor.exampleé hoy.", [FactKind.HOST], "accepted"),
    ],
)
def test_tokens_are_classified_whole_and_alike(action: str, quote: str, kinds: list[FactKind], status: str) -> None:
    assert [fact.kind for fact in traceable_facts(action)] == kinds
    result = validate_mitigation([step(action=action, quote=quote)], openssl_package(f" {quote}"))
    assert result.status is MitigationStatus(status)
    assert result.rule == (None if status == "accepted" else "JUE-MIT-03")


def test_a_v_prefixed_version_matches_the_quote() -> None:
    assert validate_mitigation([step(action="Actualizar a v2.4.60.")], package()).status is MitigationStatus.ACCEPTED


def test_fact_at_the_end_of_a_sentence_still_matches() -> None:
    quote = "A heap overflow in Example HTTP Server before 2.4.60 allows remote attackers"
    assert appears_as_fact("2.4.60", quote)
    assert appears_as_fact("2.4.60", "fixed in 2.4.60.")
    assert not appears_as_fact("2.4.6", "fixed in 2.4.60.")
    assert not appears_as_fact("4.60", "fixed in 2.4.60.")


def test_traceable_facts_extraction() -> None:
    facts = texts(
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
    kinds = [fact.kind for fact in traceable_facts("Ver https://a.example.test/x, `make` 2.4.60 3.0.x /etc/h.conf")]
    assert kinds == [FactKind.URL, FactKind.COMMAND, FactKind.VERSION, FactKind.BRANCH, FactKind.PATH]


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
