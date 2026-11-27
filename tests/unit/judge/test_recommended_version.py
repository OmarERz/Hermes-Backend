"""Recommended version outside the affected ranges of the product (D-101, docs/07 §13 JUE-MIT-10)."""

from __future__ import annotations

import json
import logging
import signal
import time
from typing import Any

import pytest

from core.judge.mitigation import MitigationStatus, traceable_facts, validate_mitigation
from core.judge.package import ReviewPackage
from harness.judge import finding_package

pytestmark = pytest.mark.unit

# CVE-2025-9230 style: the ranges NVD and the OpenSSL CNA publish, one per release line.
OPENSSL = [
    "openssl:openssl [1.0.2,1.0.2zm)",
    "openssl:openssl [1.1.1,1.1.1zd)",
    "openssl:openssl [3.0.0,3.0.18)",
    "openssl:openssl [3.2.0,3.2.6)",
    "openssl:openssl [3.3.0,3.3.5)",
    "openssl:openssl [3.4.0,3.4.3)",
    "openssl:openssl [3.5.0,3.5.4)",
]
# Envoy style (GitHub CNA): a fix per supported line, named in the description.
ENVOY = [
    "envoyproxy:envoy [1.28.0,1.28.7)",
    "envoyproxy:envoy [1.29.0,1.29.9)",
    "envoyproxy:envoy [1.30.0,1.30.6)",
    "envoyproxy:envoy [1.31.0,1.31.2)",
]
ENVOY_FIX = "This issue has been addressed in releases 1.31.2, 1.30.6, 1.29.9, and 1.28.7."


def package(cpe: str | None, ranges: list[str], description: str = "") -> ReviewPackage:
    content: dict[str, Any] = finding_package()
    content["group"]["cpe"] = cpe
    content["cve_data"]["affected_ranges"] = ranges
    content["cve_data"]["description"] += description
    return ReviewPackage.from_content(content)


def quoted(*ranges: str) -> str:
    """A quote of consecutive ranges as the CVE element renders the list."""
    return json.dumps(list(ranges))[1:-1]


def check(action: str, quote: str, pkg: ReviewPackage) -> tuple[MitigationStatus, str | None]:
    step = {"order": 1, "ci_id": "", "action": action, "element_id": "cve-1", "quote": quote}
    result = validate_mitigation([step], pkg)
    return result.status, result.rule


ACCEPTED = (MitigationStatus.ACCEPTED, None)
OUTSIDE_RULE = (MitigationStatus.DISCARDED, "JUE-MIT-10")


def recommended(action: str) -> list[str]:
    return [fact.text for fact in traceable_facts(action) if fact.recommended]


# --- which versions an action recommends --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("Actualizar OpenSSL de la rama 3.0 a la versión 3.0.23 o posterior.", ["3.0.23"]),  # #176 real draft 1
        ("Actualizar OpenSSL 3.0.x a 3.0.23.", ["3.0.23"]),  # #176 real draft 2
        ("Actualizar Example HTTP Server a 2.4.60 o posterior.", ["2.4.60"]),
        ("Actualizar de 3.0.22 a 3.0.23.", ["3.0.23"]),  # where the move starts is not a recommendation
        ("Actualizar OpenSSL 3.0.22 a 3.0.23.", ["3.0.23"]),
        ("Actualice OpenSSL a v3.0.23.", ["3.0.23"]),
        ("Migrar a la versión corregida 3.0.23 de OpenSSL.", ["3.0.23"]),
        ("Pasar a OpenSSL 3.0.23 cuanto antes.", ["3.0.23"]),
        ("Upgrade OpenSSL from 3.0.22 to OpenSSL 3.0.23 or later.", ["3.0.23"]),
        ("Update all affected hosts to version 3.0.23.", ["3.0.23"]),
        ("Instalar OpenSSL 3.0.23 en todos los equipos.", ["3.0.23"]),
        ("Aplicar el parche oficial 3.0.23.", ["3.0.23"]),
        ("Ejecutar `apt install openssl=3.0.11-1~deb12u2`.", ["3.0.11-1~deb12u2"]),
        ("Ejecutar `pip install 'cryptography>=43.0.1'`.", ["43.0.1"]),
        ("Verificar que la versión instalada sea 3.0.23 o posterior.", ["3.0.23"]),  # a floor
        ("La versión corregida es 3.0.23.", ["3.0.23"]),
        ("Fixed version: 3.0.23.", ["3.0.23"]),
        ("Actualizar a 3.0.18, 3.2.6 o 3.5.4 según la rama.", ["3.0.18", "3.2.6", "3.5.4"]),  # a list
        ("Actualizar a 3.0.18 (rama 3.0) o a 3.2.6 (rama 3.2).", ["3.0.18", "3.2.6"]),
        ("Actualizar Chrome a la versión 126.", ["126"]),  # a number after a version word
        ("Actualizar a OpenSSL 3.0.18 (o 3.2.6 para la rama 3.2).", ["3.0.18", "3.2.6"]),
        ("Actualizar a la última versión disponible (3.0.18).", ["3.0.18"]),  # a bracket right before it
        ("Actualizar los paquetes afectados (3.0.0 a 3.0.17) a 3.0.18.", ["3.0.18"]),
        ("Identificar los servidores con OpenSSL entre 3.0.0 y 3.0.17 y actualizarlos a 3.0.18.", ["3.0.18"]),
        ("Hasta poder actualizar a 3.0.18, deshabilitar el módulo.", ["3.0.18"]),
        ("Actualizar a 1.5 sin llegar a 2.0.", ["1.5"]),  # the limit is not a recommendation (prompt example)
        ("Actualizar a una versión posterior a 3.0.22.", []),
        ("Upgrade to 3.0.23, not 3.0.22.", ["3.0.23"]),
        ("Identificar los equipos con OpenSSL 3.0.0 a 3.0.22.", []),  # an identification step
        ("Actualizar a 3.0.23 los equipos con 3.0.0 a 3.0.22.", ["3.0.23"]),  # a set once the target is named
        ("Actualizar los equipos con 3.0.0 a 3.0.22.", ["3.0.22"]),  # with no target yet, where the move goes
        ("Upgrade hosts running 3.0.22 to 3.0.23.", ["3.0.23"]),  # round 1 findings
        ("Actualizar OpenSSL a 3.0.24 para la rama 3.0 y a 3.1.22 para la rama 3.1.", ["3.0.24", "3.1.22"]),
        ("Upgrade OpenSSL to `3.0.22`.", ["3.0.22"]),
        ("Actualizar Chrome a 126.", ["126"]),
        ("Upgrade to Chrome 126 on every host.", ["126"]),
        ("Actualizar a 126 o posterior.", ["126"]),
        ("Actualizar a 3 equipos por semana.", []),  # a count, not a version
        ("Actualizar a más tardar el 15.", []),
        ("Pasar a la 2.", ["2"]),
        ("Reemplazar OpenSSL 3.0.17 por 3.0.18.", ["3.0.18"]),
        ("Replace OpenSSL 3.0.17 with 3.0.18.", ["3.0.18"]),
        ("Cambiar a OpenSSL 3.0.18.", ["3.0.18"]),
        ("Actualizar los equipos con 3.0.17.", []),
        ("Actualizar de inmediato OpenSSL 3.0.17 o anterior a 3.0.18.", ["3.0.18"]),
        ("Instalar Chrome 126.", ["126"]),  # round 2 findings
        ("Instalar 2 parches del fabricante.", []),
        ("Aplicar el parche 2.", []),
        ("Ensure OpenSSL 3.0.22 or later is deployed to affected hosts.", ["3.0.22"]),
        ("3.0.0 and later are affected.", []),
        ("Upgrade OpenSSL to 3.0.23 on branch 3.0 or 3.1.22 on branch 3.1.", ["3.0.23", "3.1.22"]),
        ("Actualizar a 3.0.18 en los servidores web y 3.2.6 en los de base de datos.", ["3.0.18", "3.2.6"]),
        ("Actualizar a 3.0.23 y verificar 3.0.22.", ["3.0.23"]),
        ("Upgrade Chrome to 128 or 126.", ["128", "126"]),  # round 3 findings
        ("Validar que los equipos ejecuten 126 o posterior.", ["126"]),
        ("Aplicar las medidas de nivel 3 o superior.", []),
        ("Actualizar 2 o 3 servidores por día.", []),
        ("Actualizar OpenSSL hasta la versión 3.0.22.", ["3.0.22"]),
        ("Actualizar OpenSSL a, como mínimo, la versión 3.0.22.", ["3.0.22"]),
        ("Instalar en todos los servidores OpenSSL 3.0.22.", ["3.0.22"]),
        ("OpenSSL 3.0.22 is the fixed version.", ["3.0.22"]),
        ("3.0.23 es la primera versión corregida.", ["3.0.23"]),
        ("Actualizar OpenSSL en los equipos con 3.0.0 a 3.0.22.", ["3.0.22"]),  # no target yet: read as a move
        ("Reemplazar Chrome 125 por 126.", ["126"]),  # forced findings of T2
        ("Actualizar Chrome hasta 126.", ["126"]),
        ("La versión corregida es 126.", ["126"]),
        ("Ejecutar `pip install --upgrade cryptography==43.0.1`.", ["43.0.1"]),
        ("Revisar las versiones afectadas y comprobar que los equipos ejecuten 3.0.22 o posterior.", ["3.0.22"]),
        ("Las versiones afectadas son 3.0.0 o posteriores.", []),
        ("Actualizar a 3.0.23 los servidores con las versiones instaladas 3.0.0 a 3.0.22.", ["3.0.23"]),
        ("Actualizar a 3.0.23 los servidores afectados y los clientes de 3.1.0 a 3.1.5.", ["3.0.23", "3.1.5"]),
        ("Re-install OpenSSL 3.0.22.", ["3.0.22"]),  # T3 round 1 findings
        ("Las versiones afectadas de OpenSSL son 3.0.0 o posteriores.", []),
        ("126 is the fixed version.", ["126"]),
        ("126 es la primera versión corregida.", ["126"]),
        ("Actualizar Chrome hasta 126 como mínimo.", ["126"]),  # T3 round 2 findings
        ("Reemplazar Chrome 125 por 126 antes del reinicio.", ["126"]),
        ("Ejecutar `pip install --upgrade package==126`.", ["126"]),
        ("Revisar las versiones afectadas de OpenSSL y ejecutar 3.0.22 o posterior.", ["3.0.22"]),
        ("Actualizar a 3.0.23 los equipos con OpenSSL en 3.0.0 a 3.0.22.", ["3.0.23"]),
        ("Upgrade the web servers to 3.0.23 and affected clients on release 3.1.0 to 3.1.5.", ["3.0.23", "3.1.5"]),
        ("Fixed version for On-Premises Data Gateway is 3.0.22.", ["3.0.22"]),  # T3 round 3 findings
        ("Revisar las versiones afectadas de OpenSSL, comprobar 3.0.22 o posterior.", ["3.0.22"]),
        ("Actualizar Chrome hasta 126 según el aviso.", ["126"]),
        ("Actualizar los servidores con OpenSSL a 3.0.22.", ["3.0.22"]),  # feature review findings
        ("Upgrade the servers with OpenSSL to 3.0.22.", ["3.0.22"]),
        ("Ensure hosts run OpenSSL 3.0.22 or later, as earlier versions are affected.", ["3.0.22"]),
        ("3.0.0 and later are also affected.", []),
        ("Upgrade hosts running up to 3.0.22 to the latest supported release.", []),  # T4 round 1 findings
        ("Upgrade hosts running OpenSSL to 3.0.23.", ["3.0.23"]),
        ("Upgrade to 3.0.23. 3.0.0 and later versions are affected.", ["3.0.23"]),
        ("Las versiones 3.0.0 o posteriores versiones están afectadas.", []),
        ("Upgrade OpenSSL from 3.0.20 up to 3.0.22.", ["3.0.22"]),  # T4 round 2 findings
        ("Upgrade only hosts with a 3.0.22 or later release to the latest supported release.", []),
        ("OpenSSL 3.0.0 and later versions of this library are affected.", []),
        ("Actualizar los equipos con versiones hasta 3.0.22 a la última versión compatible.", []),  # T4 round 3
        ("OpenSSL 3.0.0 and later versions on Windows are affected.", []),
        ("Validar que todos los servidores afectados ejecuten 3.0.22 o posterior.", ["3.0.22"]),
        ("Affected versions: 3.0.0 and later.", []),
        ("La versión corregida de OpenSSL es 3.0.22.", ["3.0.22"]),
        ("Las versiones corregidas son 3.0.18 y 3.2.6.", ["3.0.18", "3.2.6"]),
        ("The fixed version for OpenSSL is 3.0.18.", ["3.0.18"]),
        ("Actualizar los equipos con OpenSSL 3.0.0 a 3.0.22 a 3.0.23.", ["3.0.23"]),
        ("Actualizar las versiones hasta 3.0.22 a 3.0.23.", ["3.0.23"]),
        ("Actualizar a 3.0.23 (corrige las versiones hasta 3.0.22).", ["3.0.23"]),  # one target per verb
        ("Actualizar a 3.0.23 a más tardar el 1 de diciembre.", ["3.0.23"]),  # a date is not where a move goes
        ("Las versiones 3.0.0 o posteriores están afectadas.", []),  # a floor of affected versions
        ("Revisar si la versión es 3.0.22 o anterior.", []),
        ("No actualizar a 3.0.22: sigue afectada. Actualizar a 3.0.23.", ["3.0.23"]),
        ("Evitar instalar 3.0.22 y actualizar a 3.0.23.", ["3.0.23"]),
        ("Do not upgrade to 3.0.22; upgrade to 3.0.23 instead.", ["3.0.23"]),
        ("Actualizar OpenSSL. Las versiones afectadas van de 3.0.0 a 3.0.22.", []),  # another clause
        ("La versión instalada 3.0.22 está afectada.", []),  # a participle installs nothing
        ("Actualizar OpenSSL a la rama 3.1.", []),  # a branch is not a version
    ],
)
def test_recommended_versions_are_read_from_the_words_around_them(action: str, expected: list[str]) -> None:
    assert recommended(action) == expected


# --- the rule ------------------------------------------------------------------------------------------------------
def test_a_version_inside_another_range_of_the_same_product_is_rejected() -> None:
    # The prompt's own example: 1.5 closes [1.0,1.5) but is still inside [1.4,2.3).
    pkg = package("example:lib", ["example:lib [1.0,1.5)", "example:lib [1.4,2.3)"])
    quote = quoted("example:lib [1.0,1.5)", "example:lib [1.4,2.3)")
    assert check("Actualizar a 1.5 o posterior.", quote, pkg) == OUTSIDE_RULE
    assert check("Actualizar a 2.3 o posterior.", quote, pkg) == ACCEPTED


def test_a_fixed_version_outside_every_range_passes() -> None:
    pkg = package("openssl:openssl", OPENSSL)
    quote = quoted(*OPENSSL[2:4])
    assert check("Actualizar OpenSSL a 3.0.18.", quote, pkg) == ACCEPTED
    assert check("Actualizar OpenSSL a 3.2.6 o posterior.", quote, pkg) == ACCEPTED


def test_a_branch_and_its_fixed_version_still_pass_d100() -> None:
    pkg = package("openssl:openssl", OPENSSL)
    action = "Actualizar OpenSSL de la rama 3.0 a la versión 3.0.18 o posterior."
    assert check(action, quoted(OPENSSL[2]), pkg) == ACCEPTED
    assert check("Actualizar OpenSSL 3.0.x a 3.0.18.", quoted(OPENSSL[2]), pkg) == ACCEPTED
    # the branch does not shield a recommended version that is still affected
    inside = package("openssl:openssl", [*OPENSSL, "openssl:openssl [3.0.18,3.0.19)"])
    assert check(action, quoted(OPENSSL[2]), inside) == OUTSIDE_RULE


def test_multiple_ranges_every_one_is_checked() -> None:
    ranges = ["example:lib [1.0,1.5)", "example:lib [2.0,2.4)", "example:lib [3.0,3.2)"]
    pkg = package("example:lib", ranges)
    quote = quoted(*ranges)
    for version in ("1.5", "2.4", "3.2"):
        assert check(f"Actualizar a {version}.", quote, pkg) == ACCEPTED
    assert check("Actualizar a 2.0.", quote, pkg) == OUTSIDE_RULE  # the start of the second range
    assert check("Actualizar a 3.0.", quote, pkg) == OUTSIDE_RULE
    assert check("Actualizar a 1.5, 2.0 o 3.2.", quote, pkg) == OUTSIDE_RULE  # one item of a list is enough


def test_openssl_style_letter_releases_do_not_block_the_main_lines() -> None:
    pkg = package("openssl:openssl", OPENSSL)
    action = "Actualizar OpenSSL a 3.0.18, 3.2.6, 3.3.5, 3.4.3 o 3.5.4 según la rama."
    assert check(action, quoted(*OPENSSL[2:]), pkg) == ACCEPTED  # 1.0.2zm and 1.1.1zd are ordered by release
    assert check("Actualizar OpenSSL 1.1.1 a 1.1.1zd.", quoted(OPENSSL[1]), pkg) == ACCEPTED  # the end itself


def test_unparseable_versions_discard_and_log(caplog: pytest.LogCaptureFixture) -> None:
    pkg = package("openssl:openssl", OPENSSL, " Fixed in OpenSSL 1.1.1w and 3.0.17-fips.")
    with caplog.at_level(logging.WARNING, logger="core.judge.mitigation"):
        assert check("Actualizar OpenSSL a 1.1.1w.", "Fixed in OpenSSL 1.1.1w", pkg) == OUTSIDE_RULE
    assert "'1.1.1w' cannot be compared with the affected range 'openssl:openssl [1.1.1,1.1.1zd)'" in caplog.text
    assert "'CVE-2026-1111'" in caplog.text
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="core.judge.mitigation"):
        quote = "1.1.1w and 3.0.17-fips."
        assert check("Actualizar OpenSSL a 3.0.17-fips.", quote, pkg) == OUTSIDE_RULE
    assert "'3.0.17-fips' cannot be compared" in caplog.text


def test_a_bound_that_cannot_be_read_discards_only_when_it_could_decide() -> None:
    ranges = ["example:lib [2.0-preview2,2.0.final)", "example:lib [1.0,1.5)"]
    pkg = package("example:lib", ranges)
    quote = quoted(*ranges)
    assert check("Actualizar a 1.5.", quote, pkg) == ACCEPTED  # below a range whose end cannot be read
    upper = package("example:lib", ["example:lib [1.0,1.5)", "example:lib [1.4,2.0.final)"])
    assert check("Actualizar a 1.5.", quoted("example:lib [1.0,1.5)"), upper) == OUTSIDE_RULE


def test_apache_style_incomplete_fix_is_rejected() -> None:
    # The description names the first fix; NVD later widened the range after an incomplete fix.
    description = " Users are recommended to upgrade to version 2.4.58, which fixes the issue."
    pkg = package("apache:http_server", ["apache:http_server [2.4.0,2.4.59)"], description)
    quote = "Users are recommended to upgrade to version 2.4.58, which fixes the issue."
    assert check("Actualizar Apache HTTP Server a 2.4.58.", quote, pkg) == OUTSIDE_RULE


def test_envoy_style_fixes_per_line() -> None:
    pkg = package("envoyproxy:envoy", ENVOY, f" {ENVOY_FIX}")
    assert check("Actualizar Envoy de la rama 1.30 a 1.30.6.", ENVOY_FIX, pkg) == ACCEPTED
    assert check("Actualizar Envoy a 1.31.2, 1.30.6, 1.29.9 o 1.28.7 según la rama.", ENVOY_FIX, pkg) == ACCEPTED
    affected = package("envoyproxy:envoy", ENVOY, " Envoy 1.30.4 and earlier are affected.")
    assert check("Actualizar Envoy a 1.30.4.", "Envoy 1.30.4 and earlier", affected) == OUTSIDE_RULE


def test_only_the_group_product_counts() -> None:
    ranges = [*OPENSSL, "nodejs:node.js [3.0.18,3.0.20)"]  # another product of the same CVE
    pkg = package("openssl:openssl", ranges)
    assert check("Actualizar OpenSSL a 3.0.18.", quoted(OPENSSL[2]), pkg) == ACCEPTED
    node = package("nodejs:node.js", ranges)
    assert check("Actualizar a 3.0.18.", quoted(OPENSSL[2]), node) == OUTSIDE_RULE


def test_mentions_that_recommend_nothing_are_not_checked() -> None:
    pkg = package("openssl:openssl", OPENSSL)
    quote = quoted(*OPENSSL[2:4])
    assert check("Identificar los equipos con OpenSSL 3.0.0 o 3.2.0.", quote, pkg) == ACCEPTED
    assert check("Actualizar de 3.0.0 a 3.0.18.", quote, pkg) == ACCEPTED


def test_round_1_findings_are_checked() -> None:
    pkg = package("openssl:openssl", ["openssl:openssl [3.0.0,3.0.24)"])
    quote = quoted("openssl:openssl [3.0.0,3.0.24)")
    assert check("Upgrade hosts running 3.0.0 to 3.0.24.", quote, pkg) == ACCEPTED
    spaced = package("openssl:openssl", ["openssl:openssl [3.0.0,3.0.23 )"], " Fixed in 3.0.22 for some builds.")
    assert check("Actualizar OpenSSL a 3.0.22.", "Fixed in 3.0.22 for some builds", spaced) == OUTSIDE_RULE
    lines = ["openssl:openssl [3.0.0,3.0.24)", "openssl:openssl [3.1.0,3.1.23)"]
    both = package("openssl:openssl", lines, " Fixed in 3.0.24 and 3.1.22.")
    action = "Actualizar OpenSSL a 3.0.24 para la rama 3.0 y a 3.1.22 para la rama 3.1."
    assert check(action, "Fixed in 3.0.24 and 3.1.22.", both) == OUTSIDE_RULE
    assert (
        check(
            "Upgrade OpenSSL to `3.0.22`.",
            "`3.0.22` is affected",
            package("openssl:openssl", ["openssl:openssl [3.0.0,3.0.23)"], " `3.0.22` is affected."),
        )
        == OUTSIDE_RULE
    )
    chrome = package("google:chrome", ["google:chrome [125,127)"], " Chrome 126 ships the first fix.")
    assert check("Actualizar Chrome a 126.", "Chrome 126 ships the first fix.", chrome) == OUTSIDE_RULE
    assert check("Actualizar Chrome a 127.", quoted("google:chrome [125,127)"), chrome) == ACCEPTED
    assert check("Actualizar Chrome a 128.", quoted("google:chrome [125,127)"), chrome) == (
        MitigationStatus.DISCARDED,
        "JUE-MIT-03",  # a bare number read as a version must be in the quote too
    )
    floor = package("openssl:openssl", ["openssl:openssl [3.0.0,3.0.23)"], " Fixed in 3.0.22.")
    action = "Validar que todos los servidores afectados ejecuten 3.0.22 o posterior."
    assert check(action, "Fixed in 3.0.22.", floor) == OUTSIDE_RULE
    assert check("La versión corregida de OpenSSL es 3.0.22.", "Fixed in 3.0.22.", floor) == OUTSIDE_RULE


def test_round_2_findings_are_checked() -> None:
    chrome = package("google:chrome", ["google:chrome [125,127)"], " Chrome 126 ships the first fix.")
    assert check("Instalar Chrome 126.", "Chrome 126 ships the first fix.", chrome) == OUTSIDE_RULE
    floor = package("openssl:openssl", ["openssl:openssl [3.0.0,3.0.23)"], " Fixed in 3.0.22.")
    action = "Ensure OpenSSL 3.0.22 or later is deployed to affected hosts."
    assert check(action, "Fixed in 3.0.22.", floor) == OUTSIDE_RULE
    lines = ["openssl:openssl [3.0.0,3.0.23)", "openssl:openssl [3.1.0,3.1.23)"]
    both = package("openssl:openssl", lines, " Fixed in 3.0.23 and 3.1.22.")
    action = "Upgrade OpenSSL to 3.0.23 on branch 3.0 or 3.1.22 on branch 3.1."
    assert check(action, "Fixed in 3.0.23 and 3.1.22.", both) == OUTSIDE_RULE
    note = " Versions 3.0.0 to 3.0.22 are affected; 3.0.23 fixes it."
    one = package("openssl:openssl", ["openssl:openssl [3.0.0,3.0.23)"], note)
    action = "Actualizar a 3.0.23 los equipos con 3.0.0 a 3.0.22."
    assert check(action, note.strip(), one) == ACCEPTED


def test_round_3_findings_are_checked() -> None:
    chrome = package("google:chrome", ["google:chrome [125,127)"], " Chrome 126 and Chrome 128 ship fixes.")
    quote = "Chrome 126 and Chrome 128 ship fixes."
    assert check("Upgrade Chrome to 128 or 126.", quote, chrome) == OUTSIDE_RULE
    assert check("Validar que los equipos ejecuten 126 o posterior.", quote, chrome) == OUTSIDE_RULE
    assert check("Upgrade Chrome to 128.", quote, chrome) == ACCEPTED
    openssl = package("openssl:openssl", ["openssl:openssl [3.0.0,3.0.23)"], " Fixed in 3.0.22.")
    for action in (
        "Actualizar OpenSSL hasta la versión 3.0.22.",
        "Actualizar OpenSSL a, como mínimo, la versión 3.0.22.",
        "Instalar en todos los servidores OpenSSL 3.0.22.",
        "OpenSSL 3.0.22 is the fixed version.",
    ):
        assert check(action, "Fixed in 3.0.22.", openssl) == OUTSIDE_RULE, action


def test_forced_t2_findings_are_checked() -> None:
    chrome = package("google:chrome", ["google:chrome [125,127)"], " Chrome 126 ships the first fix.")
    quote = "Chrome 126 ships the first fix."
    for action in ("Reemplazar Chrome por 126.", "Actualizar Chrome hasta 126.", "La versión corregida es 126."):
        assert check(action, quote, chrome) == OUTSIDE_RULE, action
    command = "`pip install --upgrade cryptography==43.0.1`"
    pip = package("cryptography:cryptography", ["cryptography:cryptography [43.0.0,43.0.2)"], f" Run {command}.")
    assert check(f"Ejecutar {command}.", f"Run {command}.", pip) == OUTSIDE_RULE
    floor = package("openssl:openssl", ["openssl:openssl [3.0.0,3.0.23)"], " Fixed in 3.0.22.")
    action = "Revisar las versiones afectadas y comprobar que los equipos ejecuten 3.0.22 o posterior."
    assert check(action, "Fixed in 3.0.22.", floor) == OUTSIDE_RULE
    note = " Versions 3.0.0 to 3.0.22 are affected; 3.0.23 fixes it."
    one = package("openssl:openssl", ["openssl:openssl [3.0.0,3.0.23)"], note)
    action = "Actualizar a 3.0.23 los servidores con las versiones instaladas 3.0.0 a 3.0.22."
    assert check(action, note.strip(), one) == ACCEPTED


def test_t3_round_1_findings_are_checked() -> None:
    lines = ["openssl:openssl [3.0.0,3.0.23)", "openssl:openssl [3.1.0,3.1.6)"]
    note = " Fixed in 3.0.23; clients from 3.1.0 to 3.1.5 are affected."
    both = package("openssl:openssl", lines, note)
    action = "Actualizar a 3.0.23 los servidores afectados y los clientes de 3.1.0 a 3.1.5."
    assert check(action, note.strip(), both) == OUTSIDE_RULE
    floor = package("openssl:openssl", ["openssl:openssl [3.0.0,3.0.23)"], " Fixed in 3.0.22.")
    assert check("Re-install OpenSSL 3.0.22.", "Fixed in 3.0.22.", floor) == OUTSIDE_RULE
    chrome = package("google:chrome", ["google:chrome [125,127)"], " Chrome 126 ships the first fix.")
    assert check("126 is the fixed version.", "Chrome 126 ships the first fix.", chrome) == OUTSIDE_RULE


def test_t3_round_2_findings_are_checked() -> None:
    chrome = package("google:chrome", ["google:chrome [125,127)"], " Chrome 126 ships the first fix.")
    quote = "Chrome 126 ships the first fix."
    for action in ("Actualizar Chrome hasta 126 como mínimo.", "Reemplazar Chrome 125 por 126 antes del reinicio."):
        assert check(action, quote, chrome) == OUTSIDE_RULE, action
    command = "`pip install --upgrade package==126`"
    pinned = package("example:package", ["example:package [125,127)"], f" Run {command}.")
    assert check(f"Ejecutar {command}.", f"Run {command}.", pinned) == OUTSIDE_RULE
    floor = package("openssl:openssl", ["openssl:openssl [3.0.0,3.0.23)"], " Fixed in 3.0.22.")
    action = "Revisar las versiones afectadas de OpenSSL y ejecutar 3.0.22 o posterior."
    assert check(action, "Fixed in 3.0.22.", floor) == OUTSIDE_RULE


def test_feature_review_findings_are_checked() -> None:
    floor = package("openssl:openssl", ["openssl:openssl [3.0.0,3.0.23)"], " Fixed in 3.0.22.")
    for action in (
        "Actualizar los servidores con OpenSSL a 3.0.22.",
        "Upgrade the servers with OpenSSL to 3.0.22.",
        "Ensure hosts run OpenSSL 3.0.22 or later, as earlier versions are affected.",
    ):
        assert check(action, "Fixed in 3.0.22.", floor) == OUTSIDE_RULE, action
    fips = package("openssl:openssl", ["openssl:openssl [3.0.0,3.0.21)"], " Fixed in 3.0.22fips.")
    assert check("Actualizar OpenSSL a 3.0.22fips.", "Fixed in 3.0.22fips.", fips) == OUTSIDE_RULE  # never guessed


def test_without_a_cpe_or_a_range_of_the_product_nothing_is_checked() -> None:
    ranges = ["example:lib [1.0,1.5)", "example:lib [1.4,2.3)"]
    quote = quoted(*ranges)
    assert check("Actualizar a 1.5.", quote, package(None, ranges)) == ACCEPTED
    assert check("Actualizar a 1.5.", quote, package("other:lib", ranges)) == ACCEPTED


def test_traceability_is_checked_first() -> None:
    pkg = package("example:lib", ["example:lib [1.0,1.5)", "example:lib [1.4,2.3)"])
    quote = quoted("example:lib [1.0,1.5)")
    assert check("Actualizar a 1.6.", quote, pkg) == (MitigationStatus.DISCARDED, "JUE-MIT-03")


def test_reading_recommendations_stays_linear() -> None:
    def hang(*_: object) -> None:
        raise TimeoutError("catastrophic backtracking")

    actions = [
        "actualizar a la " * 60 + "1.1",
        "Actualizar de " + "1.1 a " * 160 + "1.2",
        "instalar " + "x " * 450 + "1.1",
        "con " + "a 1.1 " * 160,
        ("a " * 5 + "1.1 o posterior, ") * 40,
        "upgrade to " + "1 or " * 200,
    ]
    previous = signal.signal(signal.SIGALRM, hang)
    signal.alarm(10)
    try:
        for action in actions:
            start = time.perf_counter()
            traceable_facts(action[:1000])
            assert time.perf_counter() - start < 1, action[:40]
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
