"""Realistic sample data returned by the skeleton routes until the real services exist (text in Spanish).

Synthetic: no real company, person or third-party news text.
"""

from __future__ import annotations

from api.routes.models import (
    AffectedAsset,
    CalibrationProposal,
    Metric,
    NotificationEventRow,
    Recommendation,
    Run,
)

NOW = "2026-01-15T10:30:00Z"
ITOP = "https://itop.example.test/pages/UI.php?operation=details&class=Server&id="

AFFECTED = [
    AffectedAsset(
        ci_id="CI-0001",
        name="srv-example-01",
        itop_url=ITOP + "1",
        owner="Alex Ejemplo",
        custodian="Infraestructura",
        criticality="high",
        exposed=True,
        classification="classified",
        classification_at_evaluation="classified",
        finding_status="persistent",
        score=90,
    ),
    AffectedAsset(
        ci_id="CI-0002",
        name="srv-example-02",
        itop_url=ITOP + "2",
        owner=None,
        custodian="Infraestructura",
        criticality="medium",
        exposed=False,
        classification="highly_classified",
        classification_at_evaluation="classified",
        finding_status="new",
        score=70,
    ),
]
RECOMMENDATIONS = [
    Recommendation(
        assessment_id="asm-0001",
        created_at=NOW,
        cve="CVE-2099-0001",
        product="ExampleServer 1.2",
        base=82,
        judge_adjustment=8,
        final=90,
        level="critical",
        previous_final=None,
        justification="Vulnerabilidad explotada activamente en un activo expuesto, impulsada por srv-example-01.",
        mitigation="Actualizar ExampleServer a la versión 1.2.5 o superior.",
        mitigation_draft=["Aislar el servidor de la red pública.", "Aplicar el parche del fabricante."],
        asset=AFFECTED[0],
        ticket_url="https://itop.example.test/pages/UI.php?operation=details&class=UserRequest&id=123",
        feedback_count=1,
    ),
    Recommendation(
        assessment_id="asm-0002",
        created_at="2026-01-14T09:00:00Z",
        cve=None,
        product=None,
        base=40,
        judge_adjustment=0,
        final=40,
        level="low",
        previous_final=None,
        justification="Relación inferida por IA entre una noticia y un componente; verificar su presencia.",
        mitigation=None,
        mitigation_draft=None,
        asset=None,
        ticket_url=None,
        feedback_count=0,
    ),
]
RUNS = [
    Run(
        id="run-1",
        kind="scan",
        status="succeeded",
        started_at="2026-01-15T02:00:00Z",
        finished_at="2026-01-15T02:07:00Z",
        progress=100,
    ),
    Run(id="run-2", kind="recalculation", status="running", started_at=NOW, finished_at=None, progress=40),
]
PROPOSALS = [
    CalibrationProposal(
        id="cal-1",
        created_at=NOW,
        kind="source_level",
        summary="Subir 'Medio de seguridad de ejemplo' de N3 a N2: 24 afirmaciones confirmadas",
        status="pending",
    ),
]
METRICS = [
    Metric(key="findings_open", label="Hallazgos abiertos", value="42", unit=None),
    Metric(key="judge_cost", label="Costo del juez (mes)", value="3.20", unit="USD"),
]
NOTIFICATION_EVENTS = [
    NotificationEventRow(
        id="evt-1",
        type="new_ticket",
        priority="immediate",
        status="error",
        attempts=10,
        last_error="Tiempo de espera agotado",
        created_at=NOW,
    ),
]
