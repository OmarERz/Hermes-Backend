"""Realistic sample data returned by the skeleton routes until the real services exist (text in Spanish).

Synthetic: no real company, person or third-party news text.
"""

from __future__ import annotations

from api.routes.models import (
    AffectedAsset,
    Alert,
    AssetRisk,
    AuditEntry,
    CalibrationProposal,
    CompanyProfile,
    ComparisonRow,
    ConfigParameter,
    ConfigVersion,
    ConnectionStatus,
    CpeCandidate,
    FeedbackEntry,
    InventoryItem,
    InventoryPending,
    PeerCompany,
    Recommendation,
    Run,
    SetupStep,
    Source,
    Ticket,
    VulnerabilityGroup,
)

NOW = "2026-01-15T10:30:00Z"
ITOP = "https://itop.example.test/pages/UI.php?operation=details&class=Server&id="

CONFIG_SCHEMA = [
    ConfigParameter(
        key="weights.P",
        group="formula",
        type="decimal",
        min="0",
        max="1",
        default="0.30",
        level="validated",
        min_role="admin",
        description="Peso del factor P (probabilidad de explotación)",
        validations=["weights_sum_to_one"],
    ),
    ConfigParameter(
        key="weights.T",
        group="formula",
        type="decimal",
        min="0",
        max="1",
        default="0.30",
        level="validated",
        min_role="admin",
        description="Peso del factor T (contexto de amenaza)",
        validations=["weights_sum_to_one"],
    ),
    ConfigParameter(
        key="weights.A",
        group="formula",
        type="decimal",
        min="0",
        max="1",
        default="0.30",
        level="validated",
        min_role="admin",
        description="Peso del factor A (exposición del activo)",
        validations=["weights_sum_to_one"],
    ),
    ConfigParameter(
        key="weights.D",
        group="formula",
        type="decimal",
        min="0",
        max="1",
        default="0.10",
        level="validated",
        min_role="admin",
        description="Peso del factor D (sensibilidad de los datos)",
        validations=["weights_sum_to_one"],
    ),
    ConfigParameter(
        key="judge.sensitivity",
        group="judge",
        type="enum",
        default="normal",
        level="free",
        min_role="admin",
        description="Perfil de sensibilidad del juez: mínima, normal o amplia",
    ),
    ConfigParameter(
        key="notifications.consumer",
        group="notifications",
        type="enum",
        default="log",
        level="free",
        min_role="admin",
        description="Consumidor de eventos de notificación: log o slack",
    ),
    ConfigParameter(
        key="inventory.cpe_min_score",
        group="inventory",
        type="decimal",
        min="0",
        max="1",
        default="0.80",
        level="free",
        min_role="analyst",
        description="Puntuación mínima para proponer un candidato CPE",
    ),
    ConfigParameter(
        key="ui.language",
        group="interface",
        type="enum",
        default="es",
        level="free",
        min_role="reader",
        description="Idioma de la interfaz",
    ),
]
CONFIG_VERSION = 3
CONFIG_VALUES = {
    "weights.P": "0.30",
    "weights.T": "0.30",
    "weights.A": "0.30",
    "weights.D": "0.10",
    "judge.sensitivity": "normal",
    "notifications.consumer": "log",
    "inventory.cpe_min_score": "0.80",
    "ui.language": "es",
}
CONFIG_VERSIONS = [
    ConfigVersion(version=3, created_at=NOW, author="ana.analista", summary="Perfil del juez a normal"),
    ConfigVersion(version=2, created_at="2026-01-10T09:00:00Z", author="luis.admin", summary="Peso D de 0.15 a 0.10"),
    ConfigVersion(version=1, created_at="2026-01-02T08:00:00Z", author="sistema", summary="Valores de fábrica"),
]
PROFILE = CompanyProfile(
    sector="Comercio minorista",
    subsectors=["Comercio electrónico", "Logística"],
    countries=["MX", "US"],
    language="es",
    version=2,
)
PEERS = [
    PeerCompany(
        id="peer-1",
        name="Tienda Ejemplo",
        aliases=["TiendaEj"],
        domain="tienda.example.test",
        sector="Comercio minorista",
        country="MX",
    ),
    PeerCompany(id="peer-2", name="Logística Muestra", aliases=[], domain=None, sector="Logística", country="US"),
]
SOURCES = [
    Source(
        id="src-nvd",
        name="NVD",
        type="official",
        level="N1",
        structural=True,
        active=True,
        last_capture=NOW,
        items_per_run=120,
        health="ok",
    ),
    Source(
        id="src-kev",
        name="CISA KEV",
        type="official",
        level="N1",
        structural=True,
        active=True,
        last_capture=NOW,
        items_per_run=8,
        health="ok",
    ),
    Source(
        id="src-thn",
        name="Medio de seguridad de ejemplo",
        type="media",
        level="N3",
        structural=False,
        active=True,
        last_capture="2026-01-15T06:00:00Z",
        items_per_run=35,
        health="degraded",
    ),
]
_NO_ITEMS: list[InventoryItem] = []
INVENTORY = InventoryPending(
    software_without_cpe=[
        InventoryItem(ci_id="CI-0107", name="Portal de pagos", detail="Software 'PagoFácil 2.1' sin CPE")
    ],
    without_classification=[
        InventoryItem(ci_id="CI-0112", name="srv-reportes-01", detail="Sin clasificación de datos")
    ],
    without_exposure=_NO_ITEMS,
    without_owner=[InventoryItem(ci_id="CI-0120", name="srv-legado-02", detail="Sin dueño asignado")],
    without_custodian=_NO_ITEMS,
    outside_delivery_model=_NO_ITEMS,
)
CPE_CANDIDATES = [
    CpeCandidate(cpe="cpe:2.3:a:ejemplo:pagofacil:2.1:*:*:*:*:*:*:*", title="Ejemplo PagoFácil 2.1", score=0.93),
    CpeCandidate(cpe="cpe:2.3:a:ejemplo:pagofacil:2.0:*:*:*:*:*:*:*", title="Ejemplo PagoFácil 2.0", score=0.71),
]
GROUPS = [
    VulnerabilityGroup(
        group_id="grp-1",
        cve="CVE-2099-0001",
        product="ExampleServer 1.2",
        ci_count=2,
        custodians=["Infraestructura"],
        tickets=["R-000123"],
        final=90,
        level="critical",
        in_kev=True,
        owners=["Alex Ejemplo"],
        classification="classified",
        exposed=True,
        status="persistent",
        last_seen="2026-01-15T02:00:00Z",
    ),
    VulnerabilityGroup(
        group_id="grp-2",
        cve="CVE-2099-0002",
        product="ExampleDB 5.0",
        ci_count=1,
        custodians=["Datos"],
        tickets=["R-000124"],
        final=76,
        level="high",
        in_kev=False,
        owners=["Sara Muestra"],
        classification="highly_classified",
        exposed=False,
        status="new",
        last_seen="2026-01-14T02:00:00Z",
    ),
    VulnerabilityGroup(
        group_id="grp-3",
        cve="CVE-2099-0003",
        product="ExampleProxy 3.4",
        ci_count=4,
        custodians=["Redes"],
        tickets=[],
        final=55,
        level="medium",
        in_kev=False,
        owners=[],
        classification="public",
        exposed=True,
        status="reopened",
        last_seen="2026-01-10T02:00:00Z",
    ),
]
ASSET_RISKS = [
    AssetRisk(
        ci_id="CI-0001",
        name="srv-example-01",
        risk=90,
        findings_by_level={"critical": 1, "high": 0, "medium": 1, "low": 0},
        in_kev=1,
        classification="classified",
        owner="Alex Ejemplo",
        custodian="Infraestructura",
        exposed=True,
        status="persistent",
        last_seen="2026-01-15T02:00:00Z",
    ),
    AssetRisk(
        ci_id="CI-0002",
        name="srv-example-02",
        risk=70,
        findings_by_level={"critical": 0, "high": 0, "medium": 2, "low": 3},
        in_kev=0,
        classification="public",
        owner=None,
        custodian="Infraestructura",
        exposed=False,
        status="new",
        last_seen="2026-01-12T02:00:00Z",
    ),
]
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
COMPARISON_ROWS = [
    ComparisonRow(
        cve="CVE-2099-0001",
        product="ExampleServer 1.2",
        ci_id="CI-0001",
        cvss="9.8",
        raw=98,
        base=82,
        judge_adjustment=8,
        final=90,
        delta=-8,
        main_cause="Explotación activa en KEV",
    ),
    ComparisonRow(
        cve="CVE-2099-0003",
        product="ExampleProxy 3.4",
        ci_id="CI-0009",
        cvss=None,
        raw=60,
        base=55,
        judge_adjustment=0,
        final=55,
        delta=-5,
        main_cause="Sin exposición a internet",
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
FEEDBACK = [
    FeedbackEntry(
        user="ana.analista",
        channel="slack",
        verdict="relevant",
        proposed_level=None,
        proposed_score=None,
        comment="Confirmado con el equipo de infraestructura.",
        created_at=NOW,
        active=True,
        on_older_version=False,
    ),
]
TICKETS = [
    Ticket(
        itop_id="R-000123",
        url="https://itop.example.test/pages/UI.php?operation=details&class=UserRequest&id=123",
        cve="CVE-2099-0001",
        custodian="Infraestructura",
        urgency=1,
        status="Abierto",
        fixed_cis=0,
        total_cis=2,
    ),
    Ticket(
        itop_id="R-000124",
        url="https://itop.example.test/pages/UI.php?operation=details&class=UserRequest&id=124",
        cve="CVE-2099-0002",
        custodian="Datos",
        urgency=2,
        status="En progreso",
        fixed_cis=0,
        total_cis=1,
    ),
]
ALERTS = [
    Alert(
        id="alr-1",
        created_at=NOW,
        relevance="R2",
        inferred=False,
        actor="Actor sintético",
        victim="Sector minorista",
        vector="Phishing",
        summary="Campaña contra el sector sin vulnerabilidad asociada.",
        ci_id=None,
    ),
    Alert(
        id="alr-2",
        created_at="2026-01-14T12:00:00Z",
        relevance="inferred",
        inferred=True,
        actor=None,
        victim=None,
        vector=None,
        summary="Relación inferida por IA; verificar el componente antes de actuar.",
        ci_id="CI-0001",
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
CONNECTIONS = [
    ConnectionStatus(name="itop", ok=True, latency_ms=85, missing_variable=None),
    ConnectionStatus(name="deepseek", ok=False, latency_ms=None, missing_variable="DEEPSEEK_API_KEY"),
    ConnectionStatus(name="nvd", ok=True, latency_ms=240, missing_variable=None),
    ConnectionStatus(name="abusech", ok=False, latency_ms=None, missing_variable="ABUSECH_AUTH_KEY"),
    ConnectionStatus(name="ransomwarelive", ok=False, latency_ms=None, missing_variable="RANSOMWARELIVE_API_KEY"),
    ConnectionStatus(name="firebase", ok=True, latency_ms=60, missing_variable=None),
]
DONE_STEPS = 2
SETUP_STEPS = [
    SetupStep(n=n, name=name, done=n <= DONE_STEPS, skipped=False)
    for n, name in enumerate(
        [
            "Conexiones",
            "Perfil de la empresa",
            "Empresas pares",
            "Fuentes",
            "Revisión del inventario",
            "Sensibilidad y fórmula",
            "Primer escaneo",
        ],
        start=1,
    )
]
AUDIT = [
    AuditEntry(id="aud-1", created_at=NOW, actor="luis.admin", action="config.update", target="weights.D"),
    AuditEntry(
        id="aud-2", created_at="2026-01-10T09:00:00Z", actor="luis.admin", action="config.restore", target="version 2"
    ),
]
STIX_BUNDLE = {
    "type": "bundle",
    "id": "bundle--5d0092c5-5f74-4287-9642-33f4c354e56d",
    "objects": [
        {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": "vulnerability--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
            "created": NOW,
            "modified": NOW,
            "name": "CVE-2099-0001",
        }
    ],
}
