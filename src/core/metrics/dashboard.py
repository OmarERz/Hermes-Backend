"""Dashboard metrics for `GET /api/metrics` (FRO-21, docs/10 §1): the latest stored value of each metric.

The shape matches the API model `MetricsDashboard` (`generated_at`, `metrics: [{key, label, value, unit, as_of,
description}]`): values are already formatted text and labels are in Spanish (D-060). Metrics with dimensions are
folded into one figure (the total cost, the most delayed source); the per-dimension detail stays in `daily_metric`.
Each value carries the UTC day it was stored for (`as_of`: the nightly job stores the previous day), and the metrics
the comparison screen also shows live say their scope (rehearsal 2 P2-C: «ruido evitado» 34 live, 0 here). The
current level of the judge ladder (L14) is always included.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime
from decimal import ROUND_HALF_UP, Decimal
from typing import Final, Literal

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.metrics.ladder import current_level

Kind = Literal["ratio", "count", "hours", "minutes", "seconds", "usd", "points"]
Fold = Literal["only", "sum", "max", "min"]


@dataclass(frozen=True)
class MetricInfo:
    label: str
    kind: Kind
    fold: Fold = "only"  # only: the '' dimension; sum/max/min: across the dimensions of the latest day
    description: str | None = None  # scope and date, for the front to label it (Spanish)


NIGHTLY_SCOPE: Final = "entre las evaluaciones del día UTC anterior, al cierre de la noche anterior"
LIVE_ELSEWHERE: Final = (
    "La pantalla de comparación la calcula en vivo sobre los hallazgos vigentes, así que puede dar otra cifra."
)


CATALOG: Final[dict[str, MetricInfo]] = {
    "precision": MetricInfo("Precisión", "ratio"),
    "feedback_rate": MetricInfo("Tasa de retroalimentación", "ratio"),
    "critical_precision": MetricInfo("Precisión de los críticos", "ratio"),
    "double_review_rate": MetricInfo("Doble revisión disparada", "ratio"),
    "double_review_disagreement": MetricInfo("Desacuerdo en doble revisión", "ratio"),
    "judge_adjustment_avg": MetricInfo("Ajuste promedio del juez", "points"),
    "judge_adjustment_up": MetricInfo("Ajustes que suben", "ratio"),
    "judge_adjustment_down": MetricInfo("Ajustes que bajan", "ratio"),
    "judge_adjustment_large": MetricInfo("Ajustes de 15 puntos o más", "ratio"),
    "fallback_rate": MetricInfo("Revisiones con respaldo (sin juez)", "ratio"),
    "validation_failure_rate": MetricInfo("Respuestas del juez que no validan", "ratio"),
    "wrong_priority_judged": MetricInfo("«Prioridad incorrecta» en ajustes del juez", "ratio"),
    "original_score_accepted": MetricInfo("«Aceptar puntaje original» en ajustes del juez", "ratio"),
    "first_pass_validation": MetricInfo("Validación a la primera (peor pieza)", "ratio", "min"),
    "retries": MetricInfo("Reintentos de LLM", "count", "sum"),
    "cost_usd": MetricInfo("Costo de LLM del día", "usd", "sum"),
    "rule_rejections": MetricInfo("Motivos rechazados por regla", "count", "sum"),
    "reason_usage": MetricInfo("Motivos aceptados del juez", "count", "sum"),
    "error_queue_size": MetricInfo("Cola de error", "count"),
    "error_queue_oldest_hours": MetricInfo("Antigüedad de la cola de error", "hours"),
    "cpe_mapping_coverage": MetricInfo("Software con mapeo CPE", "ratio"),
    "source_hours_since_ok": MetricInfo("Fuente más atrasada", "hours", "max"),
    "reclassified": MetricInfo(
        "Hallazgos reclasificados",
        "ratio",
        description=f"Proporción de puntajes de CI cuyo nivel no es el de su CVSS, {NIGHTLY_SCOPE}. {LIVE_ELSEWHERE}",
    ),
    "hidden_criticals": MetricInfo(
        "Críticos ocultos",
        "count",
        description=f"Puntajes de CI con CVSS menor a 7.0 y final de 75 o más, {NIGHTLY_SCOPE}. {LIVE_ELSEWHERE}",
    ),
    "noise_avoided": MetricInfo(
        "Ruido evitado",
        "count",
        description=f"Puntajes de CI con CVSS de 9.0 o más y final menor a 50, {NIGHTLY_SCOPE}. {LIVE_ELSEWHERE}",
    ),
    "inventory_pending": MetricInfo("CIs con pendientes de inventario", "ratio"),
    "notification_pending": MetricInfo("Eventos pendientes", "count"),
    "notification_failed": MetricInfo("Eventos en error", "count"),
    "immediate_oldest_pending_minutes": MetricInfo("Evento inmediato más antiguo sin entregar", "minutes"),
    "delivery_latency_p95_seconds": MetricInfo("Latencia de entrega p95", "seconds"),
}
UNITS: Final[dict[Kind, str | None]] = {
    "ratio": "%",
    "count": None,
    "hours": "h",
    "minutes": "min",
    "seconds": "s",
    "usd": "USD",
    "points": "puntos",
}
LADDER_LABELS: Final = {0: "Normal", 1: "Vigilado", 2: "Cauteloso", 3: "Apagado"}

_LATEST: Final = text(
    """SELECT d.metric_code, d.dimension, d.value, d.metric_date FROM daily_metric d
    JOIN (SELECT metric_code, max(metric_date) AS metric_date FROM daily_metric GROUP BY metric_code) latest
      ON latest.metric_code = d.metric_code AND latest.metric_date = d.metric_date"""
)


@dataclass(frozen=True)
class DashboardMetric:
    key: str
    label: str
    value: str
    unit: str | None
    as_of: date | None = None  # the UTC day the value was stored for; None for the live ladder level
    description: str | None = None


@dataclass(frozen=True)
class Dashboard:
    generated_at: datetime
    metrics: list[DashboardMetric]


def _quantize(value: Decimal, places: str) -> str:
    return str(value.quantize(Decimal(places), rounding=ROUND_HALF_UP))


PLACES: Final[dict[Kind, str]] = {"count": "1", "usd": "0.01"}


def format_value(value: Decimal, kind: Kind) -> str:
    """Text for people: percentages with one decimal, money with two, counts as integers, the rest one decimal."""
    shown = value * 100 if kind == "ratio" else value
    return _quantize(shown, PLACES.get(kind, "0.1"))


def _fold(values: dict[str, Decimal], fold: Fold) -> Decimal | None:
    if fold == "only":
        return values.get("")
    if not values:
        return None
    folds: dict[Fold, Callable[[list[Decimal]], Decimal]] = {
        "sum": lambda items: sum(items, Decimal(0)),
        "max": max,
        "min": min,
    }
    return folds[fold](list(values.values()))


def build_dashboard(session: Session, now: datetime) -> Dashboard:
    """The latest value of every catalogued metric (in catalog order) plus the judge ladder level."""
    latest: dict[str, tuple[date, dict[str, Decimal]]] = {}
    for row in session.execute(_LATEST).all():
        _, values = latest.setdefault(row.metric_code, (row.metric_date, {}))
        values[row.dimension] = Decimal(row.value)
    metrics: list[DashboardMetric] = []
    for code, info in CATALOG.items():
        if code not in latest:
            continue
        day, values = latest[code]
        value = _fold(values, info.fold)
        if value is not None:
            shown = format_value(value, info.kind)
            metrics.append(DashboardMetric(code, info.label, shown, UNITS[info.kind], day, info.description))
    level, _ = current_level(session)
    metrics.append(
        DashboardMetric(
            "judge_ladder_level", "Nivel de la escalera del juez", f"{level} · {LADDER_LABELS[level]}", None
        )
    )
    return Dashboard(generated_at=now, metrics=metrics)
