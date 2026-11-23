"""Grouped views, detail, history, comparison, recommendations, feedback, tickets and alerts (docs/13 §5 to §7)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query

from api.errors import ApiError
from api.pagination import PAGINATED_RESPONSES, Page, PageQuery, Signer, paginate
from api.routes import samples
from api.routes._auth import guard
from api.routes.models import (
    Alert,
    AssetDetail,
    AssetRisk,
    Breakdown,
    ComparisonRow,
    ComparisonSummary,
    FeedbackEntry,
    FeedbackRequest,
    Level,
    Recommendation,
    ScoreHistoryPoint,
    Ticket,
    VulnerabilityBand,
    VulnerabilityDetail,
    VulnerabilityFilters,
    VulnerabilityGroup,
    VulnerabilityList,
)
from notifications_api import FeedbackResult

router = APIRouter(tags=["findings"])


def _not_found(what: str) -> ApiError:
    return ApiError(404, "not_found", f"{what} no existe.")


BANDS: tuple[Level, ...] = ("critical", "high", "medium", "low")


def _level_of(risk: int) -> Level:
    """Default urgency bands (TIC-03): the asset risk is its highest final."""
    return "critical" if risk >= 90 else "high" if risk >= 75 else "medium" if risk >= 50 else "low"  # noqa: PLR2004


def _in_range(last_seen: str, filters: VulnerabilityFilters) -> bool:
    seen = datetime.fromisoformat(last_seen)
    after = filters.date_from is None or seen >= datetime.fromisoformat(filters.date_from.upper())
    before = filters.date_to is None or seen <= datetime.fromisoformat(filters.date_to.upper())
    return after and before


def _group_matches(group: VulnerabilityGroup, f: VulnerabilityFilters) -> bool:
    return (
        (f.band is None or group.level == f.band)
        and (f.custodian is None or f.custodian in group.custodians)
        and (f.owner is None or f.owner in group.owners)
        and (f.classification is None or group.classification == f.classification)
        and (f.exposed is None or group.exposed == f.exposed)
        and (f.in_kev is None or group.in_kev == f.in_kev)
        and (f.status is None or group.status == f.status)
        and _in_range(group.last_seen, f)
    )


def _asset_matches(asset: AssetRisk, f: VulnerabilityFilters) -> bool:
    return (
        (f.band is None or _level_of(asset.risk) == f.band)
        and (f.custodian is None or asset.custodian == f.custodian)
        and (f.owner is None or asset.owner == f.owner)
        and (f.classification is None or asset.classification == f.classification)
        and (f.exposed is None or asset.exposed == f.exposed)
        and (f.in_kev is None or (asset.in_kev > 0) == f.in_kev)
        and (f.status is None or asset.status == f.status)
        and _in_range(asset.last_seen, f)
    )


@router.get("/api/vulnerabilities", dependencies=[guard("GET", "/api/vulnerabilities")], responses=PAGINATED_RESPONSES)
def list_vulnerabilities(
    params: PageQuery,
    signer: Signer,
    filters: Annotated[VulnerabilityFilters, Query()],
    view: Literal["vulnerability", "criticality", "asset"] = "vulnerability",
) -> VulnerabilityList:
    """Grouped views resolved by the backend (FRO-09). The FRO-10 filters and cursor/limit apply to every view.

    In the `criticality` view the page is cut over the groups ordered by their final; each band reports the
    number of groups of the whole filtered result and only the groups that fall in the page.
    """
    if view == "asset":
        page_assets = paginate([a for a in samples.ASSET_RISKS if _asset_matches(a, filters)], params, signer)
        return VulnerabilityList(view=view, assets=page_assets.items, next_cursor=page_assets.next_cursor)
    groups = sorted((g for g in samples.GROUPS if _group_matches(g, filters)), key=lambda g: -g.final)
    page_groups = paginate(groups, params, signer)
    if view == "criticality":
        bands = [
            VulnerabilityBand(
                level=level,
                count=sum(1 for g in groups if g.level == level),
                groups=[g for g in page_groups.items if g.level == level],
            )
            for level in BANDS
        ]
        return VulnerabilityList(view=view, bands=bands, next_cursor=page_groups.next_cursor)
    return VulnerabilityList(view=view, groups=page_groups.items, next_cursor=page_groups.next_cursor)


@router.get("/api/vulnerabilities/{group_id}", dependencies=[guard("GET", "/api/vulnerabilities/{group_id}")])
def vulnerability_detail(group_id: str) -> VulnerabilityDetail:
    group = next((g for g in samples.GROUPS if g.group_id == group_id), None)
    if group is None:
        raise _not_found("El grupo de vulnerabilidad")
    return VulnerabilityDetail(
        **group.model_dump(),
        description="Ejecución remota de código en un componente expuesto (texto sintético de ejemplo).",
        assets=samples.AFFECTED,
    )


@router.get("/api/assets/{ci_id}", dependencies=[guard("GET", "/api/assets/{ci_id}")])
def asset_detail(ci_id: str) -> AssetDetail:
    asset = next((a for a in samples.ASSET_RISKS if a.ci_id == ci_id), None)
    if asset is None:
        raise _not_found("El activo")
    return AssetDetail(
        ci_id=asset.ci_id,
        name=asset.name,
        risk=asset.risk,
        classification=asset.classification,
        owner=asset.owner,
        custodian=asset.custodian,
        findings=samples.GROUPS[:2],
    )


@router.get("/api/findings/{id}/history", dependencies=[guard("GET", "/api/findings/{id}/history")])
def finding_history(id: str) -> list[ScoreHistoryPoint]:  # noqa: A002 - path parameter name of API-06
    if id != "fnd-1":
        raise _not_found("El hallazgo")
    return [
        ScoreHistoryPoint(date="2026-01-13T00:00:00Z", base=70, judge_adjustment=0, final=70),
        ScoreHistoryPoint(date="2026-01-15T00:00:00Z", base=82, judge_adjustment=8, final=90),
    ]


@router.get("/api/comparison/summary", dependencies=[guard("GET", "/api/comparison/summary")])
def comparison_summary() -> ComparisonSummary:
    return ComparisonSummary(
        reclassification_matrix={"critical": {"critical": 4, "high": 2}, "high": {"high": 9, "medium": 5}},
        funnel={"raw": 420, "groups": 130, "with_threat_context": 36, "judge_adjusted": 12, "high_or_critical": 9},
        reclassified_percent="31.5",
        hidden_criticals=1,
        avoided_noise=88,
        rank_correlation="0.62",
    )


@router.get(
    "/api/comparison/table", dependencies=[guard("GET", "/api/comparison/table")], responses=PAGINATED_RESPONSES
)
def comparison_table(params: PageQuery, signer: Signer) -> Page[ComparisonRow]:
    return paginate(samples.COMPARISON_ROWS, params, signer)


@router.get("/api/assessments/{id}/breakdown", dependencies=[guard("GET", "/api/assessments/{id}/breakdown")])
def assessment_breakdown(id: str) -> Breakdown:  # noqa: A002
    if id != "asm-0001":
        raise _not_found("La evaluación")
    return Breakdown(
        assessment_id=id,
        waterfall={"P": 20, "T": 25, "A": 22, "D": 15, "judge": 8, "floor": 0, "rounding": 0},
        final=90,
    )


@router.get("/api/recommendations", dependencies=[guard("GET", "/api/recommendations")], responses=PAGINATED_RESPONSES)
def list_recommendations(params: PageQuery, signer: Signer) -> Page[Recommendation]:
    return paginate(samples.RECOMMENDATIONS, params, signer)


@router.get("/api/recommendations/{assessment_id}", dependencies=[guard("GET", "/api/recommendations/{assessment_id}")])
def get_recommendation(assessment_id: str) -> Recommendation:
    found = next((r for r in samples.RECOMMENDATIONS if r.assessment_id == assessment_id), None)
    if found is None:
        raise _not_found("La recomendación")
    return found


@router.post("/api/feedback", status_code=201, dependencies=[guard("POST", "/api/feedback")])
def post_feedback(feedback: FeedbackRequest) -> FeedbackResult:
    """Same `FeedbackService` as Slack (NOT-06). Never changes the score by itself."""
    if not any(r.assessment_id == feedback.assessment_id for r in samples.RECOMMENDATIONS):
        raise _not_found("La evaluación")
    return FeedbackResult(feedback_id="0b1f3c5e-7a2d-4e8f-9a6b-1c2d3e4f5a6b", replaced_previous=False)


@router.get("/api/recommendations/{id}/feedback", dependencies=[guard("GET", "/api/recommendations/{id}/feedback")])
def recommendation_feedback(id: str) -> list[FeedbackEntry]:  # noqa: A002
    if not any(r.assessment_id == id for r in samples.RECOMMENDATIONS):
        raise _not_found("La recomendación")
    return samples.FEEDBACK if id == "asm-0001" else []


@router.get("/api/tickets", dependencies=[guard("GET", "/api/tickets")], responses=PAGINATED_RESPONSES)
def list_tickets(
    params: PageQuery, signer: Signer, urgency: int | None = Query(default=None, ge=1, le=4)
) -> Page[Ticket]:
    tickets = [t for t in samples.TICKETS if urgency is None or t.urgency == urgency]
    return paginate(tickets, params, signer)


@router.get("/api/alerts", dependencies=[guard("GET", "/api/alerts")], responses=PAGINATED_RESPONSES)
def list_alerts(params: PageQuery, signer: Signer) -> Page[Alert]:
    return paginate(samples.ALERTS, params, signer)
