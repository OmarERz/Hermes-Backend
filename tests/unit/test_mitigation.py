"""Mitigation assembly, the justification template and text cleaning (no database)."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

import pytest

from core.mitigation.builder import MitigationData, compose, version_key
from core.mitigation.justification import JudgeReason, JustificationInput, NewsEvidence, age_text, build_justification
from core.mitigation.text import clean_text, safe_url

NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)


def test_correction_lists_fixed_versions_in_numeric_order() -> None:
    result = compose(MitigationData("CVE-2026-1", fixed_versions=["1.25.3", "1.9.0", "1.10.1", "1.25.3"]))
    assert result.correction == (
        "Actualizar a 1.9.0 o superior.",
        "Actualizar a 1.10.1 o superior.",
        "Actualizar a 1.25.3 o superior.",
    )
    assert result.has_fix


def test_without_a_fixed_version_it_says_so_and_points_to_temporary_measures() -> None:
    result = compose(MitigationData("CVE-2026-1"))
    assert not result.has_fix and "no publican una versión corregida" in result.correction[0]
    assert result.temporal == () and result.detection == ()  # an empty slot stays empty


def test_temporal_measures_come_from_kev_and_the_cna() -> None:
    result = compose(
        MitigationData(
            "CVE-2026-1",
            kev_required_action="Apply mitigations\nper vendor.",
            kev_due_date=date(2026, 12, 10),
            workarounds=["Disable the module.", "   ", "Block port 8080"],
        )
    )
    assert result.temporal == (
        "CISA KEV exige: Apply mitigations per vendor. Fecha límite: 2026-12-10.",
        "Alternativa publicada por el CNA: Disable the module.",
        "Alternativa publicada por el CNA: Block port 8080",
    )


def test_many_workarounds_and_indicators_are_capped_with_a_note() -> None:
    result = compose(
        MitigationData(
            "CVE-2026-1",
            workarounds=[f"w{n}" for n in range(12)],
            iocs=[f"domain:evil{n:02d}.example" for n in range(25)] + ["domain:evil00.example"],
        )
    )
    assert len(result.temporal) == 11 and result.temporal[-1].startswith("Hay 2 alternativas")
    assert (
        len(result.detection) == 21
        and result.detection[0] == "Buscar en registros y tráfico el indicador domain:evil00.example."
    )
    assert result.detection[-1].startswith("Hay 5 indicadores")


def test_references_keep_only_safe_urls_and_are_sorted_and_unique() -> None:
    result = compose(
        MitigationData(
            "CVE-2026-1",
            patch_references=[
                "https://b.example/fix",
                "javascript:alert(1)",
                "https://a.example/fix",
                "https://b.example/fix",
            ],
            advisory_references=["ftp://x.example", "http://vendor.example/advisory", "https://ok.example/a b"],
        )
    )
    assert result.patch_references == ("https://a.example/fix", "https://b.example/fix")
    assert result.advisory_references == ("http://vendor.example/advisory",)
    assert len(result.verification) == 2


def test_text_cleaning() -> None:
    assert clean_text("a\x00b\r\n c\t\td") == "a b c d"
    assert clean_text("x" * 10, 5) == "xxxx…"
    assert safe_url("https://a.example/x?y=1") == "https://a.example/x?y=1"
    for bad in ("", "file:///etc/passwd", "https://", "https://a.example/\nx", "//a.example"):
        assert safe_url(bad) is None
    assert version_key("1.10") > version_key("1.9") and version_key("2.0.0") > version_key("2.0")


def full(**kwargs: object) -> JustificationInput:
    values: dict[str, object] = {
        "base": 74,
        "final": 86,
        "driving_ci": "api-prod",
        "cvss_score": Decimal("7.5"),
        "in_kev": True,
        "news": (NewsEvidence("BleepingComputer", NOW - timedelta(hours=5)),),
        "criticality": "high",
        "exposed": True,
        "confidentiality": "highly_classified",
        "personal_data": True,
        "judge_adjustment": 12,
        "judge_reasons": (JudgeReason("explotación masiva", "noticia-812"),),
    }
    return JustificationInput(**{**values, **kwargs})


def test_the_example_of_the_spec_is_reproduced_exactly() -> None:
    assert build_justification(full(), NOW) == (
        "**Base 74 → Final 86 · impulsada por api-prod.** CVSS 7.5 · en KEV · explotación reportada por "
        "BleepingComputer (hace 5 h) · activo crítico expuesto · datos Ultra clasificados + personales. "
        "**Juez +12:** explotación masiva (noticia-812)."
    )


def test_minimal_and_special_cases() -> None:
    minimal = JustificationInput(base=40, final=40, driving_ci="db-01")
    assert build_justification(minimal, NOW) == (
        "**Base 40 → Final 40 · impulsada por db-01.** activo de criticidad desconocida."
    )
    negative = full(judge_adjustment=-8, judge_reasons=(JudgeReason("parche disponible"),), in_kev=False, news=())
    assert "**Juez -8:** parche disponible." in build_justification(negative, NOW)
    assert "Sin revisión del juez" in build_justification(full(no_judge_review=True), NOW)
    assert build_justification(full(floor_applied=True), NOW).endswith(
        "Se aplicó el piso de KEV con el activo expuesto."
    )
    assert "sin motivo registrado" in build_justification(full(judge_reasons=()), NOW)


def test_external_names_cannot_break_the_layout() -> None:
    hostile = full(driving_ci="x**\n# inyección" + "y" * 200, news=(NewsEvidence("fuente\nfalsa", NOW),))
    text = build_justification(hostile, NOW)
    assert (
        "\n" not in text
        and "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"
        not in text
    )


AGES = [
    (timedelta(seconds=10), "hace 1 min"),
    (timedelta(minutes=45), "hace 45 min"),
    (timedelta(hours=5, minutes=59), "hace 5 h"),
    (timedelta(days=3, hours=2), "hace 3 d"),
    (timedelta(hours=-1), "hace 1 min"),
]


@pytest.mark.parametrize(("delta", "expected"), AGES)
def test_age(delta: timedelta, expected: str) -> None:
    assert age_text(NOW - delta, NOW) == expected
