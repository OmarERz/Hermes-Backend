"""Justification of a score: a code template plus the judge's reasons (docs/06 §6, `TODO(P-009)`).

Example of the output:

    **Base 74 → Final 86 · impulsada por api-prod.** CVSS 7.5 · en KEV · explotación reportada por
    BleepingComputer (hace 5 h) · activo crítico expuesto · datos Ultra clasificados + personales.
    **Juez +12:** explotación masiva (noticia-812).

The numbers come from the engine and are inputs here. The text is Spanish (the configured output language) and
every name that comes from outside is cleaned first.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import ROUND_HALF_UP, Decimal
from typing import Final

from core.mitigation.text import escape_markdown

NAME_LIMIT: Final = 80
CRITICALITY: Final = {
    "high": "crítico",
    "medium": "de criticidad media",
    "low": "de criticidad baja",
    "unknown": "de criticidad desconocida",
}
CONFIDENTIALITY: Final = {"highly_classified": "Ultra clasificados", "classified": "clasificados", "public": "públicos"}
SECONDS_PER_HOUR: Final = 3600
HOURS_PER_DAY: Final = 24
TEN: Final = Decimal(10)
TENTH: Final = Decimal("0.1")


@dataclass(frozen=True)
class NewsEvidence:
    source: str
    reported_at: datetime
    kind: str = "explotación reportada"


@dataclass(frozen=True)
class JudgeReason:
    text: str
    reference: str | None = None  # for example "noticia-812"


@dataclass(frozen=True)
class JustificationInput:
    base: int
    final: int
    driving_ci: str
    cvss_score: Decimal | None = None
    in_kev: bool = False
    news: tuple[NewsEvidence, ...] = ()
    criticality: str = "unknown"
    exposed: bool | None = None
    confidentiality: str = "unclassified"
    personal_data: bool | None = None
    judge_adjustment: int = 0
    judge_reasons: tuple[JudgeReason, ...] = ()
    floor_applied: bool = False
    no_judge_review: bool = False
    # Without a CVSS (docs/06 §S): the S the engine used and whether it came from the CVE analyst's inferred vector
    # (estimated); otherwise it is the conservative default, marked `unrated`. Unused when `cvss_score` is set.
    severity_s: Decimal | None = None
    severity_estimated: bool = False


def age_text(then: datetime, now: datetime) -> str:
    seconds = max(0, int((now - then).total_seconds()))
    hours = seconds // SECONDS_PER_HOUR
    if hours < 1:
        return f"hace {max(1, seconds // 60)} min"
    if hours < HOURS_PER_DAY:
        return f"hace {hours} h"
    return f"hace {hours // HOURS_PER_DAY} d"


def _signed(value: int) -> str:
    return f"{value:+d}"


def _asset_facts(data: JustificationInput) -> list[str]:
    facts = [f"activo {CRITICALITY.get(data.criticality, CRITICALITY['unknown'])}"]
    if data.exposed:
        facts[0] += " expuesto"
    labels = [CONFIDENTIALITY[data.confidentiality]] if data.confidentiality in CONFIDENTIALITY else []
    if data.personal_data:
        labels.append("personales")
    if labels:
        facts.append("datos " + " + ".join(labels))
    return facts


def _without_cvss(data: JustificationInput, s: Decimal) -> str:
    """docs/06 §S, on the CVSS scale of the rest of the text: the inferred vector's score, or the default S (0.8)."""
    shown = (s * TEN).quantize(TENTH, rounding=ROUND_HALF_UP)
    if data.severity_estimated:
        return f"Sin CVSS publicado: severidad estimada {shown} con el vector que infirió el Analista de CVE"
    return f"Sin CVSS publicado: severidad estimada {shown} (valor conservador, `unrated`)"


def build_justification(data: JustificationInput, now: datetime) -> str:
    """The justification text of one finding's score."""
    driver = escape_markdown(data.driving_ci, NAME_LIMIT)
    head = f"**Base {data.base} → Final {data.final} · impulsada por {driver}.**"
    parts: list[str] = []
    if data.cvss_score is not None:
        parts.append(f"CVSS {data.cvss_score}")
    elif data.severity_s is not None:
        parts.append(_without_cvss(data, data.severity_s))
    if data.in_kev:
        parts.append("en KEV")
    for item in data.news:
        source = escape_markdown(item.source, NAME_LIMIT)
        parts.append(f"{escape_markdown(item.kind, NAME_LIMIT)} por {source} ({age_text(item.reported_at, now)})")
    parts.extend(_asset_facts(data))
    text = f"{head} {' · '.join(parts)}."
    if data.no_judge_review:
        text += " **Sin revisión del juez:** no hay ajuste."
    elif data.judge_adjustment or data.judge_reasons:
        reasons = "; ".join(
            escape_markdown(r.text, 200) + (f" ({escape_markdown(r.reference, NAME_LIMIT)})" if r.reference else "")
            for r in data.judge_reasons
        )
        text += f" **Juez {_signed(data.judge_adjustment)}:** {reasons or 'sin motivo registrado'}."
    if data.floor_applied:
        text += " Se aplicó el piso de KEV con el activo expuesto."
    return text
