"""Request and response models of the API-06 routes. Dates are ISO 8601 strings in UTC (API-02)."""

from __future__ import annotations

from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, model_validator

from notifications_api.models import DateTimeString

Level = Literal["critical", "high", "medium", "low"]
Classification = Literal["public", "classified", "highly_classified", "unclassified"]
FindingStatus = Literal["new", "persistent", "reopened", "fixed", "no_data"]


def _whole_number(value: Any) -> Any:
    """JSON Schema `integer` also accepts 3.0; booleans, strings and fractions stay rejected by strict mode."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


Version = Annotated[int, Field(ge=1), BeforeValidator(_whole_number)]
Score = Annotated[int, Field(ge=0, le=100), BeforeValidator(_whole_number)]


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


class ConfigDocument(_Model):
    version: int
    values: dict[str, str]


class ConfigUpdate(_Model):
    expected_version: Version = Field(description="Version the client read; 409 if it changed (API-03)")
    changes: dict[str, str] = Field(min_length=1)


class RestoreRequest(_Model):
    expected_version: Version = Field(description="Current version the client read; 409 if it changed (API-03)")


class ConfigVersion(_Model):
    version: int
    created_at: str
    author: str
    summary: str


class SimulationRequest(_Model):
    changes: dict[str, str] = Field(min_length=1)


class SimulationResult(_Model):
    changed_findings: int
    level_matrix: dict[str, dict[str, int]] = Field(description="before level -> after level -> findings")
    last_30_days_effect: str
    top_movers: list[str]


# --- profile and peers ---------------------------------------------------------------------------------------
class CompanyProfile(_Model):
    sector: str
    subsectors: list[str]
    countries: list[str]
    language: str
    version: int


class ProfileUpdate(_Model):
    expected_version: Version
    sector: str = Field(min_length=1)
    subsectors: list[str]
    countries: list[str]
    language: str = Field(min_length=2, max_length=5)


class PeerCompanyInput(_Model):
    name: str = Field(min_length=1)
    aliases: list[str] = Field(default_factory=list)
    domain: str | None = None
    sector: str
    country: str = Field(min_length=2, max_length=2)


class PeerCompany(PeerCompanyInput):
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


class SourceCreate(_Model):
    name: str = Field(min_length=1)
    url: str = Field(pattern=r"^https://", description="Own feeds must use HTTPS; they enter as N4 (D-041)")
    kind: Literal["rss", "atom", "json", "csv", "api"] = Field(default="rss", description="How the feed is read")


class SourcePatch(_Model):
    active: bool | None = None
    level: Literal["N1", "N2", "N3", "N4"] | None = Field(default=None, description="Admin only")


class InventoryItem(_Model):
    ci_id: str
    name: str
    detail: str


class InventoryPending(_Model):
    software_without_cpe: list[InventoryItem]
    without_classification: list[InventoryItem]
    without_exposure: list[InventoryItem]
    without_owner: list[InventoryItem]
    without_custodian: list[InventoryItem]
    outside_delivery_model: list[InventoryItem]


class CpeCandidate(_Model):
    cpe: str
    title: str
    score: float


class MappingInput(_Model):
    cpe: str = Field(pattern=r"^cpe:2\.3:")


class Mapping(_Model):
    software: str
    cpe: str


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


class VulnerabilityDetail(VulnerabilityGroup):
    description: str
    assets: list[AffectedAsset]


class AssetDetail(_Model):
    ci_id: str
    name: str
    risk: int
    classification: Classification
    owner: str | None
    custodian: str | None
    findings: list[VulnerabilityGroup]


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
    waterfall: dict[str, int] = Field(description="P, T, A, D, judge, floor and rounding contributions (EVA-12)")
    final: int


# --- recommendations, feedback, tickets, alerts -----------------------------------------------------------------
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

    assessment_id: str
    verdict: Literal["relevant", "false_positive", "wrong_priority", "investigating", "stop_suggestions"]
    proposed_level: Level | None = None
    proposed_score: Score | None = None
    comment: str | None = Field(default=None, max_length=2000)

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


class StixExportRequest(_Model):
    scope: Literal["vulnerability", "run", "date_range"]
    vulnerability_id: str | None = None
    run_id: str | None = None
    date_from: str | None = None
    date_to: str | None = None


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


class ConnectionTestRequest(_Model):
    names: list[Literal["itop", "deepseek", "nvd", "abusech", "ransomwarelive", "firebase"]] | None = None


class SetupStep(_Model):
    n: int
    name: str
    done: bool
    skipped: bool


class SetupStepUpdate(_Model):
    done: bool = True
    skipped: bool = False


class AuditEntry(_Model):
    id: str
    created_at: str
    actor: str
    action: str
    target: str


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
