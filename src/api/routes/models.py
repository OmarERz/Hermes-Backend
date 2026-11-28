"""Request and response models of the API-06 routes. Dates are ISO 8601 strings in UTC (API-02)."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any, Final, Literal, Self

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, model_validator

from notifications_api.models import DateTimeString

Level = Literal["critical", "high", "medium", "low"]
Classification = Literal["public", "classified", "highly_classified", "unclassified"]
Criticality = Literal["high", "medium", "low", "unknown"]  # of a CI in iTop
FindingStatus = Literal["new", "persistent", "reopened", "fixed", "no_data"]
ReviewStatus = Literal[
    "applied", "suggestion", "partial_review", "judge_disagreement", "no_judge_review", "rejected", "queued"
]
Verdict = Literal["relevant", "false_positive", "wrong_priority", "investigating", "stop_suggestions"]
# How the scan matched a finding (ESC-09, F15.9) and that match's certainty, as decimal text (F18.9)
MatchSource = Literal["nvd_cpe", "kev", "cna_affected"]
Certainty = Literal["1.0", "0.9"]


# The numeric id of a ticket in iTop, as every `ticket_itop_id` input takes it (filters and feedback).
ITOP_TICKET_ID_PATTERN: Final = r"^[0-9]{1,12}$"


def filter_ticket_id(itop_ticket_id: str | None) -> str | None:
    """The ticket's iTop id when the `ticket_itop_id` inputs accept it, else None (the `DEMO-n` ids of `make demo`)."""
    if itop_ticket_id is None or re.fullmatch(ITOP_TICKET_ID_PATTERN, itop_ticket_id) is None:
        return None
    return itop_ticket_id


def parse_moment(value: str | None) -> datetime | None:
    """An RFC 3339 filter value already checked by its model (`DateTimeString`) as a datetime; None if absent."""
    return datetime.fromisoformat(value.upper()) if value else None


def _whole_number(value: Any) -> Any:
    """JSON Schema `integer` also accepts 3.0; booleans, strings and fractions stay rejected by strict mode."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


Version = Annotated[int, Field(ge=1), BeforeValidator(_whole_number)]
# Configuration versions are a PostgreSQL `integer` column: a larger number is a 422, never a database error.
MAX_VERSION = 2_147_483_647
ConfigVersionNumber = Annotated[int, Field(ge=1, le=MAX_VERSION), BeforeValidator(_whole_number)]
Score = Annotated[int, Field(ge=0, le=100), BeforeValidator(_whole_number)]

# Request bounds (F12.3, ASVS 5.0 V2.2.1 and V4): every text of a request body has a maximum length and every list or
# map a maximum size, generous for real use (decidido de noche, revisar). The services still check the content
# (catalog codes, control characters, known parameters); these bounds keep oversized input out before any work.
MAX_NAME = 200
MAX_CODE = 100
MAX_URL = 2048
MAX_CONFIG_CHANGES = 100
MAX_CONFIG_VALUE = 1000
MAX_LIST_ITEMS = 50
MAX_COUNTRIES = 300
Name = Annotated[str, Field(min_length=1, max_length=MAX_NAME)]
Code = Annotated[str, Field(max_length=MAX_CODE)]
ConfigKey = Annotated[str, Field(max_length=MAX_CODE)]
ConfigValue = Annotated[str, Field(max_length=MAX_CONFIG_VALUE)]


class _Model(BaseModel):
    # Strict: a body that violates the published schema (e.g. 0 for a boolean) is rejected, never coerced.
    model_config = ConfigDict(extra="forbid", strict=True)


# --- configuration (API-03, API-05) -------------------------------------------------------------------------
class ConfigParameter(_Model):
    key: str
    group: str
    type: Literal["decimal", "integer", "boolean", "string", "enum"]
    min: str | None = None
    max: str | None = None
    default: str
    level: Literal["free", "validated", "blocked"]
    min_role: Literal["reader", "analyst", "admin"]
    description: str
    validations: list[str] = Field(default_factory=list)
    options: list[str] = Field(default_factory=list, description="Allowed values of an enum parameter")
    option_values: dict[str, dict[str, str]] = Field(
        default_factory=dict,
        description="Lo que fija cada opción de un parámetro `enum`: por opción, cada parámetro y su valor como texto. "
        "Hoy solo `sensitivity_profile` (docs/07 §12), con `judge.range_multiplier` y `judge.allow_lowering` (fijos "
        "del perfil), `dead_zone` (la zona muerta del perfil: mándala junto con el perfil al simular y al guardar, "
        "D-091) y `mode2.min_confidence` (la usa el juez mientras un admin no la fije). Vacío en los demás "
        "parámetros.",
    )


class ConfigDocument(_Model):
    version: int
    values: dict[str, str]


class ConfigUpdate(_Model):
    expected_version: ConfigVersionNumber = Field(description="Version the client read; 409 if it changed (API-03)")
    changes: dict[ConfigKey, ConfigValue] = Field(min_length=1, max_length=MAX_CONFIG_CHANGES)


class RestoreRequest(_Model):
    expected_version: ConfigVersionNumber = Field(
        description="Current version the client read; 409 if it changed (API-03)"
    )


class ConfigVersion(_Model):
    version: int
    created_at: str
    author: str
    summary: str


class SimulationRequest(_Model):
    changes: dict[ConfigKey, ConfigValue] = Field(min_length=1, max_length=MAX_CONFIG_CHANGES)


class SimulationResult(_Model):
    changed_findings: int
    level_matrix: dict[str, dict[str, int]] = Field(description="before level -> after level -> findings")
    last_30_days_effect: str
    top_movers: list[str]
    not_simulable: list[str] = Field(default_factory=list)


# --- profile and peers ---------------------------------------------------------------------------------------
class CompanyProfile(_Model):
    sector: str
    subsectors: list[str]
    countries: list[str]
    language: str
    version: int


class ProfileUpdate(_Model):
    expected_version: Version
    sector: str = Field(min_length=1, max_length=MAX_CODE)
    subsectors: list[Code] = Field(max_length=MAX_LIST_ITEMS)
    countries: list[Code] = Field(max_length=MAX_COUNTRIES)
    language: str = Field(min_length=2, max_length=5)


class PeerCompanyInput(_Model):
    name: Name
    # Empty aliases stay allowed: the service drops them (profile.py normalisation), as before F12.3.
    aliases: list[Annotated[str, Field(max_length=MAX_NAME)]] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    domain: str | None = Field(default=None, max_length=253)  # the longest DNS name
    sector: Code
    country: str = Field(min_length=2, max_length=2)


# A stored peer company. The F12.3 bounds apply to what comes in, not to rows saved before them, so the list never
# fails on an older, longer value (API-06).
class PeerCompany(_Model):
    name: str = Field(min_length=1)
    aliases: list[str] = Field(default_factory=list)
    domain: str | None = None
    sector: str
    country: str = Field(min_length=2, max_length=2)
    id: str


# --- sources and inventory -------------------------------------------------------------------------------------
class Source(_Model):
    id: str
    name: str
    type: Literal["official", "research", "media", "feed"]
    level: Literal["N1", "N2", "N3", "N4"]
    structural: bool
    active: bool
    last_capture: str | None
    items_per_run: int
    health: Literal["ok", "degraded", "failing"]
    description: str | None = None
    provider: str | None = None
    refresh_interval_minutes: int | None = None


class SourceCreate(_Model):
    name: Name
    url: str = Field(
        pattern=r"^https://", max_length=MAX_URL, description="Own feeds must use HTTPS; they enter as N4 (D-041)"
    )
    kind: Literal["rss", "atom", "json", "csv", "api"] = Field(default="rss", description="How the feed is read")


class SourcePatch(_Model):
    active: bool | None = None
    level: Literal["N1", "N2", "N3", "N4"] | None = Field(default=None, description="Admin only")


class InventoryItem(_Model):
    ci_id: str
    name: str
    detail: str
    # F18.6: the proper id of each kind of row; `ci_id` stays as it was for clients already generated
    software_product_id: str | None = Field(
        default=None,
        description="Id (UUID) del producto de software, el `{software}` de `PUT /api/mappings/{software}`. Solo en "
        "`software_without_cpe`; nulo en las listas de activos.",
    )
    itop_class: str | None = Field(
        default=None,
        description="Clase del CI en iTop (Server, VirtualMachine…), para enlazarlo en la consola de iTop. Solo en las "
        "listas de activos; nula en `software_without_cpe`.",
    )


class InventoryPendingTotals(_Model):
    """How many items of each type wait for a person, whatever the cap of each list (F18.6)."""

    software_without_cpe: int = Field(ge=0)
    without_classification: int = Field(ge=0)
    without_exposure: int = Field(ge=0)
    without_owner: int = Field(ge=0)
    without_custodian: int = Field(ge=0)
    outside_delivery_model: int = Field(ge=0)


class InventoryPending(_Model):
    software_without_cpe: list[InventoryItem]
    without_classification: list[InventoryItem]
    without_exposure: list[InventoryItem]
    without_owner: list[InventoryItem]
    without_custodian: list[InventoryItem]
    outside_delivery_model: list[InventoryItem]
    totals: InventoryPendingTotals | None = Field(
        default=None,
        description="Total de pendientes de cada tipo. Cada lista trae a lo más 200 elementos (sin paginación): si "
        "su total es mayor, la lista está cortada.",
    )


class CpeCandidate(_Model):
    cpe: str
    title: str
    score: float


# A CPE 2.3 name whose part, vendor and product the mapping can store (F12.3, D-107): part `a`, `o` or `h`, then vendor
# and product that
# start with a letter or digit and hold only letters, digits, `. _ ~ + -` or an escaped colon (the rule of
# `core.cpe.mapping`, case-insensitive), then at least one more field. Anything else is a 422 from the schema itself,
# so a schema-valid name is never refused later (Schemathesis "schema-valid request rejected").
_CPE_PART = r"[A-Za-z0-9](?:[A-Za-z0-9._~+\-]|\\[:._~+\-]){0,199}"
CPE_NAME_PATTERN = rf"^cpe:2\.3:[aoh]:{_CPE_PART}:{_CPE_PART}(?::(?:[^:\\]|\\.)*)+$"


# A CNA name as CVE.org writes it (F15.9, `core.cpe.mapping`): 1 to 200 characters, no control characters (C0, DEL,
# C1) and at least one that is not a space, so a schema-valid name is never refused later. U+FEFF counts as a space in
# JSON Schema (ECMAScript `\s`) but not in the server's regex engine, so it never counts as the visible one either.
CNA_NAME_PATTERN = r"^[^\x00-\x1f\x7f-\x9f]*[^\s\x00-\x1f\x7f-\x9f\ufeff][^\x00-\x1f\x7f-\x9f]*$"


class CnaNames(_Model):
    """CNA vendor and product of a software product, as CVE.org writes them in `affected[]` (ESC-05, F15.9)."""

    vendor: str = Field(
        min_length=1,
        max_length=200,
        pattern=CNA_NAME_PATTERN,
        description="Fabricante como lo escribe el CNA en CVE.org (por ejemplo `Linux` o `n/a`).",
    )
    product: str = Field(
        min_length=1,
        max_length=200,
        pattern=CNA_NAME_PATTERN,
        description="Producto como lo escribe el CNA en CVE.org (por ejemplo `Linux` o `CPython`).",
    )


class MappingInput(_Model):
    cpe: str = Field(pattern=CPE_NAME_PATTERN, max_length=512)
    cna: CnaNames | None = Field(
        default=None,
        description="Nombres del CNA (CVE.org) del producto, para comparar sus rangos con certeza 0.9. Si se omite, "
        "se conservan los que ya tenía el mapeo; `null` los quita.",
    )


class Mapping(_Model):
    software: str
    cpe: str
    cna: CnaNames | None = Field(default=None, description="Nombres del CNA (CVE.org) que quedaron en el mapeo.")


# --- grouped views, detail, history, comparison -------------------------------------------------------------------
class VulnerabilityGroup(_Model):
    group_id: str
    cve: str
    product: str
    ci_count: int
    custodians: list[str]
    tickets: list[str]
    final: int = Field(ge=0, le=100)
    level: Level
    in_kev: bool
    owners: list[str]
    classification: Classification = Field(description="The most restrictive among its assets (FRO-13)")
    exposed: bool
    status: FindingStatus
    last_seen: str
    match_sources: list[MatchSource] = Field(
        default_factory=list,
        description="Cómo se detectaron sus hallazgos (F18.9), sin repetir y de la más a la menos segura: `nvd_cpe` "
        "(rango de NVD, certeza 1.0), `kev` (CVE de KEV de CISA que coincidió por los rangos del CNA en CVE.org, "
        "certeza 1.0) y `cna_affected` (solo los rangos del CNA en CVE.org, certeza 0.9). Cuenta los activos que "
        "hablan por el grupo (los vigentes, o todos si ya está corregido); en el detalle de un activo, solo la de ese "
        "activo.",
    )


class VulnerabilityBand(_Model):
    level: Level
    count: int
    groups: list[VulnerabilityGroup]


class AssetRisk(_Model):
    ci_id: str
    name: str
    risk: int = Field(ge=0, le=100, description="Highest final of its findings; scores are never summed (FRO-11)")
    findings_by_level: dict[str, int]
    in_kev: int
    classification: Classification
    owner: str | None
    custodian: str | None
    exposed: bool
    status: FindingStatus
    last_seen: str


class VulnerabilityList(_Model):
    view: Literal["vulnerability", "criticality", "asset"]
    groups: list[VulnerabilityGroup] | None = None
    bands: list[VulnerabilityBand] | None = None
    assets: list[AssetRisk] | None = None
    next_cursor: str | None = None


class AffectedAsset(_Model):
    ci_id: str
    name: str
    itop_url: str
    owner: str | None
    custodian: str | None
    criticality: str
    exposed: bool
    classification: Classification
    classification_at_evaluation: Classification
    finding_status: FindingStatus
    score: int = Field(ge=0, le=100)
    finding_id: str | None = Field(
        default=None,
        description="Id del hallazgo de este CI en la vulnerabilidad: se usa en GET /api/findings/{id}/history. "
        "Viene en el detalle de vulnerabilidad; es nulo en una recomendación (su CI puede ser el de una alerta, "
        "sin hallazgo de escaneo).",
    )
    match_source: MatchSource | None = Field(
        default=None,
        description="Cómo se detectó el hallazgo `finding_id` (F18.9): `nvd_cpe` (rango de NVD), `kev` (CVE de KEV de "
        "CISA que coincidió por los rangos del CNA en CVE.org) o `cna_affected` (solo los rangos del CNA en CVE.org). "
        "Si el CI tiene varias instalaciones del producto, es la de la instalación con el estado más urgente, la "
        "misma de `finding_id` y `finding_status`. Nulo cuando `finding_id` es nulo (en una recomendación).",
    )
    certainty: Certainty | None = Field(
        default=None,
        description="Certeza de esa coincidencia, como texto decimal (ESC-09): `1.0` para `nvd_cpe` y `kev`, `0.9` "
        "para `cna_affected`. Nula cuando `match_source` es nulo.",
    )


class VulnerabilityDetail(VulnerabilityGroup):
    description: str
    assets: list[AffectedAsset]


SoftwareCategory = Literal["DBServer", "Middleware", "OtherSoftware", "PCSoftware", "WebServer"]


class SoftwareLicenceInfo(_Model):
    """iTop software licence of an installation (F18.3). Its key is never read from iTop."""

    name: str
    usage_limit: str | None = Field(description="Límite de uso tal como está en iTop (texto libre).")
    start_date: str | None = Field(description="Fecha de inicio (AAAA-MM-DD).")
    end_date: str | None = Field(description="Vencimiento (AAAA-MM-DD); nulo si iTop no tiene fecha.")
    perpetual: bool = Field(description="Licencia perpetua en iTop (sin vencimiento).")


class AssetSoftware(_Model):
    """A live software installation of the CI, as iTop has it (F18.3, D-088)."""

    software: str = Field(description="Nombre del producto en el catálogo de iTop.")
    version: str
    category: SoftwareCategory | None = Field(
        description="Categoría: la clase de la instalación en iTop. Nula si aún no se sincroniza o es una clase "
        "propia de la instancia de iTop."
    )
    status: Literal["active", "inactive"] | None = Field(
        description="Estado de la instalación en iTop; nulo sin dato. Solo informativo: una instalación inactiva "
        "se sigue escaneando."
    )
    description: str | None = Field(description="Descripción de la instalación en iTop (dato, no instrucciones).")
    licence: SoftwareLicenceInfo | None = Field(description="Licencia viva asignada en iTop; nula si no tiene.")


class AssetDetail(_Model):
    ci_id: str
    name: str
    risk: int
    classification: Classification
    owner: str | None
    custodian: str | None
    findings: list[VulnerabilityGroup]
    itop_class: str | None = Field(default=None, description="Clase del CI en iTop (Server, VirtualMachine…).")
    description: str | None = Field(default=None, description="Descripción del CI en iTop (dato, no instrucciones).")
    cpu: str | None = Field(
        default=None, description="CPU de un Server o VirtualMachine en iTop, texto libre sin convertir."
    )
    ram: str | None = Field(
        default=None, description="RAM de un Server o VirtualMachine en iTop, texto libre sin convertir."
    )
    software: list[AssetSoftware] = Field(
        default_factory=list, description="Software instalado vivo del CI, por producto y versión."
    )
    # F18.6: the CI's inventory fields, the same values `GET /api/inventory/assets` gives for it
    criticality: Criticality | None = Field(
        default=None,
        description="Criticidad del CI en iTop (`unknown` si iTop no la tiene); igual que en el inventario.",
    )
    exposed: bool | None = Field(
        default=None,
        description="Si el CI está expuesto a internet; nulo si iTop no lo dice. Igual que en el inventario.",
    )
    personal_data: bool | None = Field(
        default=None, description="Si el CI guarda datos personales; nulo si iTop no lo dice."
    )
    os: str | None = Field(default=None, description="Sistema operativo del CI, según iTop; nulo sin dato.")
    service: str | None = Field(default=None, description="Servicio de negocio del CI, según iTop; nulo sin dato.")
    synced_at: str | None = Field(default=None, description="Última sincronización del CI con iTop (UTC).")
    itop_url: str | None = Field(
        default=None,
        description="Enlace al CI en la consola de iTop (para editarlo allá); vacío si el backend no tiene la URL de "
        "iTop configurada, igual que en el inventario.",
    )


class ScoreHistoryPoint(_Model):
    date: str
    base: int
    judge_adjustment: int
    final: int


class ComparisonSummary(_Model):
    reclassification_matrix: dict[str, dict[str, int]]
    funnel: dict[str, int]
    reclassified_percent: str
    hidden_criticals: int
    avoided_noise: int
    rank_correlation: str


class ComparisonRow(_Model):
    cve: str
    product: str
    ci_id: str
    cvss: str | None
    raw: int
    base: int
    judge_adjustment: int
    final: int
    delta: int
    main_cause: str


class Breakdown(_Model):
    assessment_id: str
    waterfall: dict[str, int] = Field(
        description="Whole-point bars from the raw value to the final (EVA-12): P, T, A, D, judge, floor and "
        "rounding, plus clamp (keeping base + adjustment in 0-100) and version (E of alerts without a finding); "
        "raw + every bar = final"
    )
    final: int
    ci_id: str | None = Field(default=None, description="CI of the waterfall: the requested one or the top one")
    raw: int | None = Field(default=None, description="Raw value 100 x S (EVA-11), where the bars start")


# --- recommendations, feedback, tickets, alerts -----------------------------------------------------------------
class AcceptedReason(_Model):
    """A judge reason that reached the score (FRO-13): its points and the quote it cites, shown as data (SEG-02)."""

    code: str
    label: str
    points: int
    quote: str
    ci_id: str | None


class Recommendation(_Model):
    assessment_id: str
    created_at: str
    cve: str | None
    product: str | None
    base: int
    judge_adjustment: int
    final: int
    level: Level
    previous_final: int | None
    justification: str
    mitigation: str | None
    mitigation_draft: list[str] | None
    asset: AffectedAsset | None
    ticket_url: str | None
    feedback_count: int
    accepted_reasons: list[AcceptedReason] = Field(default_factory=list)
    judge_summary: str | None = None
    judge_status: ReviewStatus | None = None
    ticket_itop_id: str | None = None


class FeedbackRequest(_Model):
    """Body of POST /api/feedback. The user and channel come from the token, never from the body."""

    # `wrong_priority` needs a proposed level (NOT-06): stated in the schema so clients and fuzzers see the rule.
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        json_schema_extra={
            "if": {"properties": {"verdict": {"const": "wrong_priority"}}, "required": ["verdict"]},
            "then": {"required": ["proposed_level"], "properties": {"proposed_level": {"type": "string"}}},
        },
    )

    assessment_id: str = Field(max_length=MAX_CODE)
    verdict: Literal["relevant", "false_positive", "wrong_priority", "investigating", "stop_suggestions"]
    proposed_level: Level | None = None
    proposed_score: Score | None = None
    comment: str | None = Field(default=None, max_length=2000)
    ticket_itop_id: str | None = Field(
        default=None,
        pattern=ITOP_TICKET_ID_PATTERN,
        description="Optional: iTop id of the ticket the user acted on; scopes ticket-level effects "
        "(stop_suggestions, false_positive) to it instead of every ticket of the assessment (TIC-07).",
    )

    @model_validator(mode="after")
    def _wrong_priority_needs_a_level(self) -> Self:
        if self.verdict == "wrong_priority" and self.proposed_level is None:
            raise ValueError("proposed_level is required when verdict is wrong_priority")
        return self


class FeedbackEntry(_Model):
    user: str
    channel: Literal["frontend", "slack"]
    verdict: str
    proposed_level: Level | None
    proposed_score: int | None
    comment: str | None
    created_at: str
    active: bool
    on_older_version: bool


class Ticket(_Model):
    itop_id: str
    url: str
    cve: str
    custodian: str
    urgency: int = Field(ge=1, le=4)
    status: str
    fixed_cis: int
    total_cis: int
    ticket_itop_id: str | None = Field(
        default=None,
        description="Id numérico del ticket en iTop (F18.4): el valor que aceptan los filtros `ticket_itop_id` de "
        "`GET /api/tickets/updates` y `GET /api/recommendations` y el campo `ticket_itop_id` de "
        "`POST /api/feedback`. Nulo si el ticket no tiene un id numérico (los tickets de demostración, `DEMO-n`). "
        "`itop_id` es para mostrar: trae la referencia (`R-000123`) cuando ya existe.",
    )


class Alert(_Model):
    id: str
    created_at: str
    relevance: Literal["R2", "R3", "inferred"]
    inferred: bool
    actor: str | None
    victim: str | None
    vector: str | None
    summary: str
    ci_id: str | None


# --- runs, STIX, calibration, metrics, notifications, connections, setup, audit ---------------------------------------
class ScanRequest(_Model):
    kind: Literal["scan"] = "scan"


class Run(_Model):
    id: str
    kind: Literal["scan", "ingestion", "recalculation", "nightly"]
    status: Literal["queued", "running", "succeeded", "failed"]
    started_at: str
    finished_at: str | None
    progress: int = Field(ge=0, le=100)
    trigger_reason: Literal["schedule", "manual", "after_scan", "formula_change"] | None = None
    triggered_by: str | None = None


class RunFilters(_Model):
    """Optional filters of the run list (HI-2)."""

    # The same query string also carries `cursor` and `limit`, read by other parameters.
    model_config = ConfigDict(extra="ignore", strict=False)

    kind: Literal["scan", "ingestion", "recalculation", "nightly"] | None = Field(
        default=None, description="Tipo de corrida."
    )
    status: Literal["queued", "running", "succeeded", "failed"] | None = Field(
        default=None, description="Estado de la corrida."
    )
    date_from: DateTimeString | None = Field(default=None, description="Started on or after (RFC 3339)")
    date_to: DateTimeString | None = Field(default=None, description="Started on or before (RFC 3339)")


class StixExportRequest(_Model):
    scope: Literal["vulnerability", "run", "date_range"]
    vulnerability_id: str | None = Field(default=None, max_length=MAX_CODE)
    run_id: str | None = Field(default=None, max_length=MAX_CODE)
    date_from: str | None = Field(default=None, max_length=MAX_CODE)
    date_to: str | None = Field(default=None, max_length=MAX_CODE)
    exclude_ultra_classified: bool = False  # leaves highly classified CIs out of the bundle and of its TLP (P-021)


class StixBundle(_Model):
    type: Literal["bundle"]
    id: str
    objects: list[dict[str, Any]]


class CalibrationProposal(_Model):
    id: str
    created_at: str
    kind: Literal["source_level", "reason_threshold", "formula_weight"]
    summary: str
    status: Literal["pending", "approved", "rejected"]
    target_key: str | None = Field(default=None, description="What the proposal changes, e.g. weights.P or source:code")
    previous_value: dict[str, Any] | None = None
    proposed_value: dict[str, Any] | None = None
    evidence: str | None = None
    backtest: dict[str, Any] | None = Field(default=None, description="Before and after of the 30-day replay")
    decided_at: str | None = None


class Metric(_Model):
    key: str
    label: str
    value: str
    unit: str | None


class MetricsDashboard(_Model):
    generated_at: str
    metrics: list[Metric]


class NotificationEventRow(_Model):
    id: str
    type: str
    priority: Literal["immediate", "normal", "digest"]
    status: Literal["pending", "delivered", "error"]
    attempts: int
    last_error: str | None
    created_at: str


class ConnectionStatus(_Model):
    name: Literal["itop", "deepseek", "nvd", "abusech", "ransomwarelive", "firebase"]
    ok: bool
    latency_ms: int | None
    missing_variable: str | None = Field(description="Name of the missing variable; never a key, not even partial")
    message: str | None = Field(
        default=None, description="Generic status in Spanish (e.g. 'Llave rechazada'); never an error body (SEG-23)"
    )
    checked_at: DateTimeString | None = Field(default=None, description="When this result was checked (UTC)")
    last_ok_at: DateTimeString | None = Field(default=None, description="Last successful check since the API started")


class ConnectionTestRequest(_Model):
    names: list[Literal["itop", "deepseek", "nvd", "abusech", "ransomwarelive", "firebase"]] | None = Field(
        default=None, max_length=10
    )


class SetupStep(_Model):
    n: int
    name: str
    done: bool
    skipped: bool
    done_source: Literal["data", "manual"] | None = Field(
        default=None,
        description="De dónde sale `done` (F18.6): `data` si los datos ya lo muestran (desmarcarlo no cambia nada), "
        "`manual` si solo lo marcó un admin (`PUT /api/setup/steps/{n}` con `done: false` lo desmarca). Nulo si el "
        "paso no está hecho.",
    )


class SetupStepUpdate(_Model):
    done: bool = True
    skipped: bool = False


class AuditFilters(_Model):
    """Filters of the audit trail; every one optional."""

    # The same query string also carries `cursor` and `limit`, read by other parameters.
    model_config = ConfigDict(extra="ignore", strict=False)  # query strings need coercion

    actor: str | None = Field(default=None, max_length=100, description="E-mail or display name; 'sistema' for none")
    action: str | None = Field(default=None, max_length=100, description="Exact action, e.g. 'source.enable'")
    date_from: DateTimeString | None = Field(default=None, description="On or after (RFC 3339)")
    date_to: DateTimeString | None = Field(default=None, description="On or before (RFC 3339)")


class AuditEntry(_Model):
    id: str
    created_at: str
    actor: str
    action: str
    target: str


# --- users and error queue (D-088, F18.2) ------------------------------------------------------------------------
RoleName = Literal["reader", "analyst", "admin"]
ErrorKind = Literal["notification", "itop", "llm_validation"]
ErrorStatus = Literal["failed", "pending", "gave_up"]


class UserAccount(_Model):
    uid: str
    email: str | None
    display_name: str | None
    role: RoleName | None
    claim_role: RoleName | None
    effective_role: RoleName | None
    active: bool
    signed_in: bool
    last_login_at: str | None


class ErrorQueueFilters(_Model):
    """Optional filter of the error queue (FRO-18)."""

    # The same query string also carries `cursor` and `limit`, read by other parameters.
    model_config = ConfigDict(extra="ignore", strict=False)

    kind: ErrorKind | None = Field(default=None, description="Origen del error.")


class ErrorQueueItem(_Model):
    id: str
    kind: ErrorKind
    created_at: str
    status: ErrorStatus
    attempts: int
    next_attempt_at: str | None
    error: str | None
    component: str
    cve: str | None
    ticket_itop_id: str | None
    ticket_ref: str | None
    assessment_id: str | None
    retryable: bool


class VulnerabilityFilters(_Model):
    """Common filters of the grouped views (FRO-10). Every one is optional and applies to all views."""

    # The same query string also carries `view`, `cursor` and `limit`, read by other parameters.
    model_config = ConfigDict(extra="ignore", strict=False)  # query strings need coercion

    band: Level | None = None
    custodian: str | None = Field(default=None, max_length=100)
    owner: str | None = Field(default=None, max_length=100)
    classification: Classification | None = None
    exposed: bool | None = None
    in_kev: bool | None = None
    status: FindingStatus | None = None
    date_from: DateTimeString | None = Field(default=None, description="Last seen on or after (RFC 3339)")
    date_to: DateTimeString | None = Field(default=None, description="Last seen on or before (RFC 3339)")


class RecommendationFilters(_Model):
    """Optional narrowing of the recommendation feed to one timeline (FRO-12)."""

    # The same query string also carries `cursor` and `limit`, read by other parameters.
    model_config = ConfigDict(extra="ignore", strict=False)

    group_id: str | None = Field(default=None, max_length=100, description="Timeline of one vulnerability group")
    ci_id: str | None = Field(default=None, max_length=100, description="Timeline of one CI (iTop id)")
    ticket_itop_id: str | None = Field(
        default=None,
        pattern=ITOP_TICKET_ID_PATTERN,
        description="Solo las evaluaciones del grupo de ese ticket de iTop.",
    )
    level: Level | None = Field(default=None, description="Solo las recomendaciones de ese nivel.")
    verdict: Verdict | None = Field(
        default=None, description="Solo las que tienen un feedback vigente con ese veredicto."
    )
    without_feedback: bool | None = Field(
        default=None, description="Solo las que no tienen (`true`) o sí tienen (`false`) feedback vigente."
    )


# --- agent telemetry (D-088, F18.1) ------------------------------------------------------------------------------
AgentName = Literal["news_analyst", "cve_analyst", "judge"]
TelemetryWindow = Literal["24h", "7d", "30d"]
RunKindAny = Literal["scan", "ingestion", "recalculation", "nightly", "inventory_sync", "calibration"]


class RunCounts(_Model):
    kind: RunKindAny
    queued: int
    running: int
    succeeded: int
    failed: int


class AgentTelemetry(_Model):
    agent: AgentName
    reviews: int
    by_status: dict[str, int]
    success_percent: str | None
    latency_avg_ms: int | None
    latency_p95_ms: int | None
    tokens_input: int
    tokens_output: int
    cost_usd: str
    provider: Literal["deepseek", "claude-code"]
    model: str
    last_model: str | None
    spend_today_usd: str
    active: bool
    ladder_level: int | None


class ReasonUsage(_Model):
    code: str
    label: str
    accepted: int
    rejected: int


class TelemetrySummary(_Model):
    window: TelemetryWindow
    since: str
    generated_at: str
    runs: list[RunCounts]
    runs_queued: int
    runs_running: int
    runs_succeeded: int
    runs_failed: int
    run_success_percent: str | None
    agents: list[AgentTelemetry]
    top_reasons: list[ReasonUsage]
    daily_budget_usd: str
    spend_today_usd: str
    ladder_level: int = Field(ge=0, le=3)
    ladder_label: str


class AgentDay(_Model):
    agent: AgentName
    reviews: int
    success_percent: str | None
    latency_avg_ms: int | None
    cost_usd: str


class TelemetryDay(_Model):
    date: str
    runs_succeeded: int
    runs_failed: int
    agents: list[AgentDay]


class TelemetryDaily(_Model):
    days: int
    series: list[TelemetryDay]


class LlmReviewFilters(_Model):
    """Optional filters of the LLM review log."""

    # The same query string also carries `cursor` and `limit`, read by other parameters.
    model_config = ConfigDict(extra="ignore", strict=False)

    agent: AgentName | None = None
    status: ReviewStatus | None = Field(default=None, description="Estado de la revisión.")
    date_from: DateTimeString | None = Field(default=None, description="On or after (RFC 3339)")
    date_to: DateTimeString | None = Field(default=None, description="On or before (RFC 3339)")


class LlmReviewEntry(_Model):
    id: str
    created_at: str
    agent: AgentName
    mode: str | None
    model: str
    status: ReviewStatus
    attempts: int
    latency_ms: int
    tokens_input: int
    tokens_cached: int
    tokens_output: int
    tokens_reasoning: int
    cost_usd: str
    ladder_level: int
    second_review: bool
    assessment_id: str | None
    reasons_accepted: int
    reasons_rejected: int


# --- history timeline (D-088, F18.1) ------------------------------------------------------------------------------
HistoryType = Literal["run", "llm_review", "config_change"]


class HistoryFilters(_Model):
    """Optional filters of the history timeline (HI-2)."""

    # The same query string also carries `cursor` and `limit`, read by other parameters.
    model_config = ConfigDict(extra="ignore", strict=False)

    type: HistoryType | None = Field(default=None, description="Tipo de evento.")
    status: str | None = Field(
        default=None,
        max_length=30,
        pattern=r"^[a-z_]{1,30}$",
        description="Estado final exacto: el de la corrida (`succeeded`, `failed`…) o el de la revisión "
        "(`applied`, `no_judge_review`…); los cambios de configuración tienen `applied`.",
    )
    date_from: DateTimeString | None = Field(default=None, description="On or after (RFC 3339)")
    date_to: DateTimeString | None = Field(default=None, description="On or before (RFC 3339)")


class HistoryEvent(_Model):
    id: str
    type: HistoryType
    at: str
    title: str
    status: str
    actor: str
    trigger: Literal["schedule", "manual", "after_scan", "formula_change"] | None
    run_kind: RunKindAny | None
    agent: AgentName | None
    assessment_id: str | None
    config_version: int | None
    duration_seconds: int | None


# --- inventory and software (D-088, F18.1) -----------------------------------------------------------------------
FilterText = Annotated[str, Field(min_length=1, max_length=100)]


class InventoryAssetFilters(_Model):
    """Optional filters of the inventory list (AC-1). Text filters compare the exact value, `q` searches."""

    # The same query string also carries `cursor` and `limit`, read by other parameters.
    model_config = ConfigDict(extra="ignore", strict=False)

    q: FilterText | None = Field(default=None, description="Texto a buscar en el nombre o el id del CI.")
    itop_class: FilterText | None = Field(default=None, description="Clase de iTop exacta, por ejemplo `Server`.")
    criticality: Criticality | None = Field(default=None, description="Criticidad del CI en iTop.")
    exposed: bool | None = None
    classification: Classification | None = None
    owner: FilterText | None = None
    custodian: FilterText | None = None
    with_findings: bool | None = Field(
        default=None, description="Solo CIs con (`true`) o sin (`false`) hallazgos abiertos."
    )


class InventoryAsset(_Model):
    ci_id: str
    name: str
    itop_class: str
    criticality: Criticality
    exposed: bool | None
    classification: Classification
    personal_data: bool | None
    owner: str | None
    custodian: str | None
    service: str | None
    os: str | None
    itop_url: str
    synced_at: str
    open_findings: int
    kev_findings: int
    risk: int | None = Field(ge=0, le=100)
    level: Level | None
    software_count: int
    description: str | None = Field(default=None, description="Descripción del CI en iTop (dato, no instrucciones).")
    cpu: str | None = Field(
        default=None, description="CPU de un Server o VirtualMachine en iTop, texto libre sin convertir."
    )
    ram: str | None = Field(
        default=None, description="RAM de un Server o VirtualMachine en iTop, texto libre sin convertir."
    )


class SoftwareHealth(_Model):
    total: int
    with_cpe: int
    with_known_version: int
    without_critical: int
    cpe_percent: str | None
    known_version_percent: str | None
    without_critical_percent: str | None


class InventorySummary(_Model):
    total_assets: int
    by_class: dict[str, int]
    by_criticality: dict[str, int]
    by_exposure: dict[str, int]
    by_classification: dict[str, int]
    owners: int
    without_owner: int
    custodians: int
    with_open_findings: int
    with_kev_findings: int
    last_sync_at: str | None
    software: SoftwareHealth


class SoftwareFilters(_Model):
    """Optional filters of the software list (ST-1)."""

    # The same query string also carries `cursor` and `limit`, read by other parameters.
    model_config = ConfigDict(extra="ignore", strict=False)

    q: FilterText | None = Field(default=None, description="Texto a buscar en el nombre del software.")
    has_cpe: bool | None = Field(default=None, description="Solo software con (`true`) o sin (`false`) CPE.")
    worst_level: Level | None = Field(default=None, description="Peor nivel de sus vulnerabilidades abiertas.")
    with_vulnerabilities: bool | None = Field(
        default=None, description="Solo software con (`true`) o sin (`false`) vulnerabilidades abiertas."
    )
    category: SoftwareCategory | None = Field(
        default=None,
        description="Solo el software con alguna instalación viva de esa categoría (clase de la instalación en iTop).",
    )


class CatalogueLicence(SoftwareLicenceInfo):
    """A live iTop licence of a catalogue product (F18.3 proposal §9.1). Its key is never read from iTop."""

    instances: int = Field(description="Instalaciones vivas del producto con esta licencia asignada en iTop.")


class SoftwareItem(_Model):
    id: str
    name: str
    versions: list[str]
    version_known: bool
    instances: int
    ci_count: int
    cpe: str | None
    has_cpe: bool
    cna: CnaNames | None = Field(
        default=None, description="Nombres del CNA (CVE.org) del mapeo; nulo si el mapeo no tiene (F15.9)."
    )
    open_vulnerabilities: int
    worst_level: Level | None
    categories: list[SoftwareCategory] = Field(
        default_factory=list,
        description="Categorías distintas (clase de iTop) de sus instalaciones vivas, en orden alfabético; vacía "
        "si ninguna se ha sincronizado con su clase.",
    )
    by_category: dict[str, int] = Field(
        default_factory=dict,
        description="Instalaciones vivas por categoría (clase de iTop); las que aún no tienen categoría no cuentan.",
    )
    by_status: dict[str, int] = Field(
        default_factory=dict,
        description="Instalaciones vivas por estado en iTop, siempre con las tres claves: `active`, `inactive` y "
        "`unknown` (sin dato). Solo informativo: una instalación inactiva se sigue escaneando.",
    )
    licences: list[CatalogueLicence] = Field(
        default_factory=list,
        description="Licencias vivas del producto en iTop, asignadas o no, por nombre; cada una con las "
        "instalaciones vivas del producto que la tienen asignada.",
    )
    licensed_instances: int = Field(
        default=0,
        description="Instalaciones vivas del producto con alguna licencia viva asignada en iTop (aunque iTop la haya "
        "ligado a la licencia de otro software).",
    )


class InstalledSoftwareItem(_Model):
    software_id: str
    name: str
    version: str
    version_known: bool
    cpe: str | None
    has_cpe: bool
    open_vulnerabilities: int
    worst_level: Level | None
    category: SoftwareCategory | None = Field(
        default=None,
        description="Categoría: la clase de la instalación en iTop. Nula si aún no se sincroniza o es una clase "
        "propia de la instancia de iTop.",
    )
    status: Literal["active", "inactive"] | None = Field(
        default=None,
        description="Estado de la instalación en iTop; nulo sin dato. Solo informativo: una instalación inactiva "
        "se sigue escaneando.",
    )
    description: str | None = Field(
        default=None, description="Descripción de la instalación en iTop (dato, no instrucciones)."
    )
    licence: SoftwareLicenceInfo | None = Field(
        default=None, description="Licencia viva asignada en iTop; nula si no tiene."
    )
    cna: CnaNames | None = Field(
        default=None,
        description="Nombres del CNA (CVE.org) del mapeo de su producto, los mismos de `cna` en "
        "`GET /api/inventory/software` (F18.9); nulo si el producto no tiene mapeo o su mapeo no los tiene.",
    )


# --- ticket summary and log, judge detail (D-088, F18.1) ---------------------------------------------------------
TicketAction = Literal[
    "create",
    "add_ci",
    "add_owner",
    "comment",
    "raise_urgency",
    "lower_urgency",
    "suggest",
    "partial_fix",
    "fix_comment",
    "reopen",
]


class TicketSummary(_Model):
    total: int
    by_status: dict[str, int]
    by_urgency: dict[str, int]
    changed_by_person: int
    resolved: int
    resolved_percent: str | None
    avg_resolution_hours: str | None


class TicketUpdateFilters(_Model):
    """Optional filters of the ticket log (HI-4)."""

    # The same query string also carries `cursor` and `limit`, read by other parameters.
    model_config = ConfigDict(extra="ignore", strict=False)

    ticket_itop_id: str | None = Field(
        default=None, pattern=ITOP_TICKET_ID_PATTERN, description="Id numérico del ticket en iTop."
    )
    action: TicketAction | None = Field(default=None, description="Acción registrada.")


class TicketUpdateEntry(_Model):
    id: str
    created_at: str
    action: TicketAction
    label: str
    assessment_id: str | None
    ticket_itop_id: str | None
    ticket_ref: str | None
    ticket_url: str | None
    cve: str
    custodian: str
    itop_status: Literal["pending", "in_progress", "done", "failed"] | None


class JudgeReasonItem(_Model):
    seq: int
    code: str
    label: str
    points: int
    quote: str
    element_id: str
    ci_id: str | None
    status: Literal["accepted", "rejected", "withdrawn"]
    rejection_rule: str | None


class DoubleReviewInfo(_Model):
    agreed: bool | None
    first_adjustment: int | None
    second_adjustment: int | None
    second_status: ReviewStatus


class JudgeDetail(_Model):
    assessment_id: str
    review_id: str | None
    status: ReviewStatus | None
    summary: str | None
    model: str | None
    reviewed_at: str | None
    proposed_adjustment: int | None
    applied_adjustment: int
    dead_zone_applied: bool
    accepted_reasons: list[JudgeReasonItem]
    rejected_reasons: list[JudgeReasonItem]
    double_review: DoubleReviewInfo | None
    mitigation_status: Literal["accepted", "discarded", "absent"] | None
