"""What a ticket says in iTop (D-036, TIC-02b, TIC-08)."""

from __future__ import annotations

import pytest

from core.mitigation.builder import Mitigation
from core.tickets.content import (
    CiLine,
    ItopIdentity,
    NewsLine,
    ReasonLine,
    TicketContext,
    ci_links,
    create_fields,
    description,
    owner_contacts,
    sorted_cis,
    title,
)
from core.tickets.context import mitigation_text

pytestmark = pytest.mark.unit


def ci(name: str, score: int | None, owner: str | None = None, *, fixed: bool = False, **kw: object) -> CiLine:
    values: dict[str, object] = {
        "criticality": "high",
        "exposed": True,
        "confidentiality": "highly_classified",
        "personal_data": None,
        "owner_email": None,
    }
    values.update(kw)
    return CiLine(
        itop_ci_id=f"id-{name}",
        name=name,
        score=score,
        owner_name=owner,
        owner_itop_id=f"p-{owner}" if owner else None,
        fixed=fixed,
        **values,
    )


CONTEXT = TicketContext(
    cve="CVE-2026-1000",
    product="nginx",
    custodian="Platform Ops",
    custodian_itop_id="10",
    cis=[ci("web-02", 70, "Ana"), ci("web-01", 88, "Luis"), ci("old-01", None, "Ana", fixed=True), ci("x", None)],
    score=88,
    driving_ci="web-01",
    base=80,
    judge_adjustment=8,
    factors={"S": "0.9", "P": "1.0"},
    reasons=[ReasonLine("mass_exploitation", 8)],
    mitigation="Actualizar a 1.26.1.",
    mitigation_draft=["Actualizar nginx en web-01."],
    news=[NewsLine("Título", "https://news.example.test/a", "BleepingComputer", "2026-11-20")],
    cvss=9.8,
    in_kev=True,
)


def test_title_follows_tic_02b() -> None:
    assert title(CONTEXT) == "CVE-2026-1000 · nginx · Platform Ops"


def test_cis_are_ordered_by_their_own_score_and_fixed_ones_last() -> None:
    assert [c.name for c in sorted_cis(CONTEXT.cis)] == ["web-01", "web-02", "x", "old-01"]
    assert [link["functionalci_id"] for link in ci_links(CONTEXT.cis)] == ["id-web-01", "id-web-02", "id-x"]


def test_owners_are_the_distinct_owners_of_current_cis() -> None:
    assert owner_contacts(CONTEXT.cis) == [{"contact_id": "p-Luis"}, {"contact_id": "p-Ana"}]


def test_description_carries_everything_tic_08_asks_for() -> None:
    text = description(CONTEXT, 2)
    for expected in (
        "Puntuación del ticket: 88 (Alta), impulsada por web-01.",
        "Base 80 · Juez +8.",
        "CVSS 9.8 · en KEV: sí.",
        "- web-01: 88 · criticidad alta · expuesto sí · Ultra clasificada · datos personales desconocido · dueño Luis",
        "- old-01 (corregido): sin puntuación",
        "dueño sin dueño",
        "Factores: S 0.9 · P 1.0",
        "Motivos del juez: mass_exploitation (+8)",
        "Mitigación (desde los datos):\nActualizar a 1.26.1.",
        "Mitigación redactada por IA (validada por código):\n1. Actualizar nginx en web-01.",
        "- 2026-11-20 · BleepingComputer · https://news.example.test/a",
    ):
        assert expected in text
    assert text.index("web-01:") < text.index("web-02:")


def test_description_without_score_or_extras() -> None:
    bare = TicketContext(cve="CVE-2026-1", product="p", custodian="c", custodian_itop_id="1", cis=[])
    text = description(bare, None)
    assert "Puntuación del ticket: sin CIs vigentes." in text
    assert "Sin mitigación en las fuentes." in text
    assert "Noticias" not in text
    assert "KEV" not in text


def test_create_fields_follow_d_036() -> None:
    fields = create_fields(CONTEXT, ItopIdentity("1", "5", "7"), 2, "department")
    assert fields["team_id"] == "10"
    assert (fields["org_id"], fields["caller_id"], fields["service_id"]) == ("1", "5", "7")
    assert (fields["urgency"], fields["impact"]) == ("2", "1")
    assert "agent_id" not in fields
    assert "service_id" not in create_fields(CONTEXT, ItopIdentity("1", "5"), 2, "service")


def test_mitigation_from_the_data_lists_every_section() -> None:
    mitigation = Mitigation(
        cve_id="CVE-2026-1000",
        correction=("Actualizar a 1.26.1 o superior.",),
        temporal=("CISA KEV exige: Aplicar el parche.",),
        detection=("Buscar en registros y tráfico el indicador ip:203.0.113.5.",),
        verification=("Volver a correr el escaneo.",),
        patch_references=("https://vendor.example.test/patch",),
        advisory_references=("https://vendor.example.test/advisory",),
    )
    assert mitigation_text(mitigation) == "\n".join(
        [
            "Actualizar a 1.26.1 o superior.",
            "CISA KEV exige: Aplicar el parche.",
            "Buscar en registros y tráfico el indicador ip:203.0.113.5.",
            "Volver a correr el escaneo.",
            "Referencias: https://vendor.example.test/patch, https://vendor.example.test/advisory",
        ]
    )
    assert mitigation_text(Mitigation("CVE-2026-1", (), (), (), (), (), ())) is None
    assert mitigation_text(None) is None
