"""What a ticket says in iTop (D-036, TIC-02b, TIC-08). Pure functions over a `TicketContext`.

The text is for people and goes out in Spanish (D-060). Names, titles and descriptions coming from iTop, NVD or the
news are data: they are copied, never interpreted, and iTop stores the description as plain text.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from core.tickets.rules import level

CONFIDENTIALITY_ES: Final[dict[str, str]] = {
    "public": "Pública",
    "classified": "Clasificada",
    "highly_classified": "Ultra clasificada",
    "unclassified": "Sin clasificar",
}
CRITICALITY_ES: Final[dict[str, str]] = {"high": "alta", "medium": "media", "low": "baja", "unknown": "desconocida"}
LEVEL_ES: Final[dict[str, str]] = {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja"}
# iTop's UserRequest impact codes ⚠️ (P-011): 1 department, 2 service.
IMPACT_CODES: Final[dict[str, str]] = {"department": "1", "service": "2"}


@dataclass(frozen=True)
class CiLine:
    """One CI of the ticket with its own score in the latest assessment."""

    itop_ci_id: str
    name: str
    score: int | None
    criticality: str
    exposed: bool | None
    confidentiality: str
    personal_data: bool | None
    owner_name: str | None
    owner_itop_id: str | None
    owner_email: str | None
    fixed: bool = False


@dataclass(frozen=True)
class NewsLine:
    title: str
    url: str
    source: str
    published: str


@dataclass(frozen=True)
class ReasonLine:
    code: str
    points: int


@dataclass(frozen=True)
class TicketContext:
    """Everything a ticket shows, loaded from the database for one group, custodian and assessment."""

    cve: str
    product: str
    custodian: str
    custodian_itop_id: str
    cis: Sequence[CiLine]
    score: int | None = None
    driving_ci: str | None = None
    base: int | None = None
    judge_adjustment: int = 0
    factors: dict[str, str] = field(default_factory=dict)
    reasons: Sequence[ReasonLine] = ()
    mitigation: str | None = None
    mitigation_draft: Sequence[str] | None = None
    news: Sequence[NewsLine] = ()
    cvss: float | None = None
    in_kev: bool = False

    @property
    def current_cis(self) -> list[CiLine]:
        return [ci for ci in self.cis if not ci.fixed]


def title(context: TicketContext) -> str:
    """`<CVE> · <product> · <custodian>` (TIC-02b); also the idempotency lookup of the create (ARQ-01)."""
    return f"{context.cve} · {context.product} · {context.custodian}"


def _yes_no(value: bool | None) -> str:
    return "sí" if value is True else "no" if value is False else "desconocido"


def _ci_line(ci: CiLine) -> str:
    score = "sin puntuación" if ci.score is None else str(ci.score)
    owner = ci.owner_name or "sin dueño"
    state = " (corregido)" if ci.fixed else ""
    return (
        f"- {ci.name}{state}: {score} · criticidad {CRITICALITY_ES.get(ci.criticality, ci.criticality)} · "
        f"expuesto {_yes_no(ci.exposed)} · {CONFIDENTIALITY_ES.get(ci.confidentiality, ci.confidentiality)} · "
        f"datos personales {_yes_no(ci.personal_data)} · dueño {owner}"
    )


def sorted_cis(cis: Sequence[CiLine]) -> list[CiLine]:
    """Current CIs first, by their own score (highest first), then by name; fixed CIs last."""
    return sorted(cis, key=lambda ci: (ci.fixed, -(ci.score if ci.score is not None else -1), ci.name))


def description(context: TicketContext, urgency: int | None) -> str:
    """TIC-08: score and driving CI, CIs by score, factors, judge reasons, mitigation and every news URL."""
    lines = [f"Vulnerabilidad {context.cve} en {context.product} (equipo custodio: {context.custodian})."]
    if context.score is not None and urgency is not None:
        lines.append(
            f"Puntuación del ticket: {context.score} ({LEVEL_ES[level(urgency)]}), impulsada por {context.driving_ci}."
        )
    else:
        lines.append("Puntuación del ticket: sin CIs vigentes.")
    if context.base is not None:
        lines.append(f"Base {context.base} · Juez {context.judge_adjustment:+d}.")
    if context.cvss is not None or context.in_kev:
        cvss = "sin CVSS" if context.cvss is None else f"CVSS {context.cvss}"
        lines.append(f"{cvss} · en KEV: {'sí' if context.in_kev else 'no'}.")
    lines += ["", "CIs afectados (por su puntuación):", *(_ci_line(ci) for ci in sorted_cis(context.cis))]
    if context.factors:
        lines += ["", "Factores: " + " · ".join(f"{k} {v}" for k, v in context.factors.items())]
    if context.reasons:
        lines += ["Motivos del juez: " + " · ".join(f"{r.code} ({r.points:+d})" for r in context.reasons)]
    lines += ["", "Mitigación (desde los datos):", context.mitigation or "Sin mitigación en las fuentes."]
    if context.mitigation_draft:
        lines += ["", "Mitigación redactada por IA (validada por código):"]
        lines += [f"{i}. {step}" for i, step in enumerate(context.mitigation_draft, start=1)]
    if context.news:
        lines += ["", "Noticias:", *(f"- {n.published} · {n.source} · {n.url}" for n in context.news)]
    return "\n".join(lines)


def ci_links(cis: Sequence[CiLine]) -> list[dict[str, str]]:
    """`functionalcis_list` with the current CIs, ordered by score. A linked-set write replaces the whole list."""
    return [{"functionalci_id": ci.itop_ci_id, "impact_code": "manual"} for ci in sorted_cis(cis) if not ci.fixed]


def owner_contacts(cis: Sequence[CiLine]) -> list[dict[str, str]]:
    """`contacts_list`: the distinct owners of the current CIs. ⚠️ the owner role field is not set yet (P-011)."""
    seen: dict[str, None] = {}
    for ci in sorted_cis(cis):
        if not ci.fixed and ci.owner_itop_id:
            seen.setdefault(ci.owner_itop_id, None)
    return [{"contact_id": owner} for owner in seen]


@dataclass(frozen=True)
class ItopIdentity:
    """Who files tickets in iTop: organization, the system person as caller and the service (C7)."""

    org_id: str
    caller_id: str
    service_id: str | None = None


def create_fields(context: TicketContext, identity: ItopIdentity, urgency: int, impact: str) -> dict[str, Any]:
    """`core/create` fields of the UserRequest (D-036): custodian team, owners, system caller, no agent."""
    fields: dict[str, Any] = {
        "org_id": identity.org_id,
        "caller_id": identity.caller_id,
        "title": title(context),
        "description": description(context, urgency),
        "team_id": context.custodian_itop_id,
        "urgency": str(urgency),
        "impact": IMPACT_CODES[impact],
        "functionalcis_list": ci_links(context.cis),
        "contacts_list": owner_contacts(context.cis),
    }
    if identity.service_id:
        fields["service_id"] = identity.service_id
    return fields
