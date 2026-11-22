"""Pydantic models equivalent to schemas/notification_event.schema.json and schemas/feedback.schema.json.

Field names, enums, nullability and constraints follow the JSON Schemas exactly (they are law, NOT-03/NOT-06).
This module imports nothing from the rest of the backend (D-043).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any, Literal, Self

from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field, model_validator


class _Contract(BaseModel):
    """Closed, immutable, strict contract object: no coercion of types the JSON Schema rejects."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


_RFC3339 = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?([Zz]|[+-](?P<oh>[0-9]{2}):(?P<om>[0-9]{2}))$"
)


def _check_date_time(value: str) -> str:
    """JSON Schema `format: date-time` (RFC 3339): full date, time and a `Z` or `+hh:mm` offset."""
    match = _RFC3339.fullmatch(value)
    if match is None or int(match["oh"] or 0) > 23 or int(match["om"] or 0) > 59:  # noqa: PLR2004
        raise ValueError("must be an RFC 3339 date-time string")
    try:
        datetime.fromisoformat(value.upper())
    except ValueError as exc:
        raise ValueError("must be an RFC 3339 date-time string") from exc
    return value


def _whole_number(value: Any) -> Any:
    """JSON Schema `integer` accepts 80.0 (no fractional part); booleans, strings and fractions stay rejected."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


Integer = Annotated[int, BeforeValidator(_whole_number)]


DateTimeString = Annotated[str, AfterValidator(_check_date_time), Field(json_schema_extra={"format": "date-time"})]


EventType = Literal["new_ticket", "level_up", "reopened", "partially_fixed", "fixed", "threat_alert", "inferred_alert"]
Priority = Literal["immediate", "normal", "digest"]
Level = Literal["critical", "high", "medium", "low"]
Confidentiality = Literal["public", "classified", "highly_classified", "unclassified"]
AssetStatus = Literal["active", "fixed", "no_data", "inferred"]
Percent = Annotated[int, Field(ge=0, le=100), BeforeValidator(_whole_number)]


class TicketOwner(_Contract):
    name: str
    email: str | None


class TicketInfo(_Contract):
    itop_id: str
    url: str
    custodian: str
    owners: list[TicketOwner]
    urgency: Integer = Field(ge=1, le=4)
    fixed_cis: Integer = Field(ge=0)
    total_cis: Integer = Field(ge=0)


class VulnerabilityInfo(_Contract):
    cve: str
    product: str
    cvss: float | None
    in_kev: bool


class AlertInfo(_Contract):
    relevance: Literal["R2", "R3", "inferred"]
    inferred: bool = Field(description="true = 'AI-inferred relationship' (mode 2)")
    actor: str | None
    victim: str | None
    vector: str | None
    relationship: str | None


class ScoreInfo(_Contract):
    base: Percent
    judge_adjustment: Integer
    final: Percent
    level: Level
    previous: Percent | None
    driving_ci: str | None


class AssetInfo(_Contract):
    ci_id: str
    name: str
    score: Percent | None
    criticality: str
    exposed: bool
    confidentiality: Confidentiality
    personal_data: bool | None
    owner: str | None
    status: AssetStatus


class NewsItem(_Contract):
    title: str = Field(description="External text: the consumer must escape it")
    url: str
    source: str
    date: str


class NotificationEvent(_Contract):
    """Emitted by the backend when something deserves a notification (NOT-03). At-least-once delivery."""

    event_id: str
    contract_version: Literal["1.0"]
    type: EventType
    priority: Priority = Field(description="immediate: individual and immediate delivery is mandatory (NOT-03)")
    date: DateTimeString
    ticket: TicketInfo | None
    vulnerability: VulnerabilityInfo | None
    alert: AlertInfo | None
    score: ScoreInfo | None
    assets: list[AssetInfo]
    justification: str
    mitigation: str | None = Field(description="Data-based mitigation built by code (D-017)")
    mitigation_draft: list[str] | None = Field(description="AI-drafted steps validated by code; null if none")
    news: list[NewsItem]
    assessment_id: str | None = Field(description="Used to link feedback (FeedbackService)")
    frontend_url: str | None = Field(description="Link to the detail page in the frontend")


_FEEDBACK_EXTRA: dict[str, Any] = {
    "allOf": [
        {
            "if": {"properties": {"verdict": {"const": "wrong_priority"}}},
            "then": {"properties": {"proposed_level": {"type": "string"}}},
        }
    ]
}


class FeedbackInput(_Contract):
    """Input of FeedbackService (NOT-06, D-044). The comment is untrusted input."""

    model_config = ConfigDict(json_schema_extra=_FEEDBACK_EXTRA)

    assessment_id: str
    user_email: str = Field(description="Must belong to a Firebase user with the analyst or admin role")
    channel: Literal["frontend", "slack"]
    verdict: Literal["relevant", "false_positive", "wrong_priority", "investigating", "stop_suggestions"]
    proposed_level: Level | None = Field(
        description="Result of the arrows (one level per click). Required when verdict = wrong_priority"
    )
    proposed_score: Percent | None = Field(description="Optional, for users who want precision")
    comment: str | None = Field(max_length=2000, description="Optional but recommended")

    @model_validator(mode="after")
    def _wrong_priority_needs_level(self) -> Self:
        if self.verdict == "wrong_priority" and self.proposed_level is None:
            raise ValueError("proposed_level is required when verdict is wrong_priority")
        return self


class FeedbackResult(_Contract):
    """Outcome of FeedbackService.record. Not defined by a JSON Schema; minimal on purpose (see docs/08 NOT-06)."""

    feedback_id: str
    replaced_previous: bool = Field(description="true if an earlier active feedback of the user was archived")
