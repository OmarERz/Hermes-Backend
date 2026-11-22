"""Grouped views, detail, history, comparison, recommendations, feedback, tickets and alerts (docs/13 §5 to §7)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, Query, Request

from api.errors import ApiError
from api.pagination import (
    PAGINATED_RESPONSES,
    Page,
    PageParams,
    PageQuery,
    Signer,
    decode_key,
    encode_key,
    paginate,
)
from api.routes import samples
from api.routes._auth import guard
from api.routes._db import SessionDep
from api.routes.models import (
    AffectedAsset,
    Alert,
    AssetDetail,
    AssetRisk,
    Breakdown,
    Classification,
    ComparisonRow,
    ComparisonSummary,
    FeedbackEntry,
    FeedbackRequest,
    FindingStatus,
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
from core.views import groups as views
from core.views.common import iso, parse_uuid
from notifications_api import FeedbackResult

router = APIRouter(tags=["findings"])


def _not_found(what: str) -> ApiError:
    return ApiError(404, "not_found", f"{what} no existe.")


BANDS: tuple[Level, ...] = ("critical", "high", "medium", "low")
VIEW_KINDS = {"vulnerability": "vulnerabilities", "criticality": "vulnerabilities", "asset": "assets"}


def get_itop_url(request: Request) -> str | None:
    url: str | None = request.app.state.itop_url
    return url


ItopUrl = Annotated[str | None, Depends(get_itop_url)]


def _filters(f: VulnerabilityFilters) -> views.Filters:
    return views.Filters(
        band=f.band,
        custodian=f.custodian,
        owner=f.owner,
        classification=f.classification,
        exposed=f.exposed,
        in_kev=f.in_kev,
        status=f.status,
        date_from=datetime.fromisoformat(f.date_from.upper()) if f.date_from else None,
        date_to=datetime.fromisoformat(f.date_to.upper()) if f.date_to else None,
    )


def _group_model(g: views.Group) -> VulnerabilityGroup:
    return VulnerabilityGroup(
        group_id=str(g.group_id),
        cve=g.cve,
        product=g.product,
        ci_count=g.ci_count,
        custodians=g.custodians,
        tickets=g.tickets,
        final=g.final,
        level=cast(Level, g.level),
        in_kev=g.in_kev,
        owners=g.owners,
        classification=cast(Classification, g.classification),
        exposed=g.exposed,
        status=cast(FindingStatus, g.status),
        last_seen=iso(g.last_seen),
    )


def _asset_risk_model(a: views.AssetRisk) -> AssetRisk:
    return AssetRisk(
        ci_id=a.ci_id,
        name=a.name,
        risk=a.risk,
        findings_by_level=a.findings_by_level,
        in_kev=a.in_kev,
        classification=cast(Classification, a.classification),
        owner=a.owner,
        custodian=a.custodian,
        exposed=a.exposed,
        status=cast(FindingStatus, a.status),
        last_seen=iso(a.last_seen),
    )


def _score_key(params: PageParams, kind: str) -> views.ScoreKey | None:
    key = decode_key(params, kind, ("int", "uuid"))
    return None if key is None else (key[0], key[1])


@router.get("/api/vulnerabilities", dependencies=[guard("GET", "/api/vulnerabilities")], responses=PAGINATED_RESPONSES)
def list_vulnerabilities(
    params: PageQuery,
    signer: Signer,
    session: SessionDep,
    filters: Annotated[VulnerabilityFilters, Query()],
    view: Literal["vulnerability", "criticality", "asset"] = "vulnerability",
) -> VulnerabilityList:
    """Grouped views resolved by the backend (FRO-09). The FRO-10 filters and cursor/limit apply to every view.

    Groups are ordered by their final (the highest among their current CIs) and CIs by their risk (the highest
    final of their findings, never a sum, FRO-11). In the `criticality` view the page is cut over the groups
    ordered by their final; each band reports the number of groups of the whole filtered result and only the
    groups that fall in the page. Only scored findings on live CIs are listed.
    """
    kind = VIEW_KINDS[view]
    after = _score_key(params, kind)
    query = _filters(filters)
    if view == "asset":
        assets, next_key = views.list_assets(session, query, after=after, limit=params.limit)
        return VulnerabilityList(
            view=view, assets=[_asset_risk_model(a) for a in assets], next_cursor=encode_key(signer, kind, next_key)
        )
    groups, next_key, counts = views.list_groups(session, query, after=after, limit=params.limit)
    page = [_group_model(g) for g in groups]
    cursor = encode_key(signer, kind, next_key)
    if view == "criticality":
        bands = [
            VulnerabilityBand(level=level, count=counts[level], groups=[g for g in page if g.level == level])
            for level in BANDS
        ]
        return VulnerabilityList(view=view, bands=bands, next_cursor=cursor)
    return VulnerabilityList(view=view, groups=page, next_cursor=cursor)


@router.get("/api/vulnerabilities/{group_id}", dependencies=[guard("GET", "/api/vulnerabilities/{group_id}")])
def vulnerability_detail(group_id: str, session: SessionDep, itop_url: ItopUrl) -> VulnerabilityDetail:
    """A vulnerability group with each scored CI and that CI's own score (D-035)."""
    parsed = parse_uuid(group_id)
    found = views.group_detail(session, parsed, itop_url) if parsed is not None else None
    if found is None:
        raise _not_found("El grupo de vulnerabilidad")
    group, assets = found
    return VulnerabilityDetail(
        **_group_model(group).model_dump(),
        description=group.description or "",
        assets=[
            AffectedAsset(
                ci_id=a.ci_id,
                name=a.name,
                itop_url=a.itop_url,
                owner=a.owner,
                custodian=a.custodian,
                criticality=a.criticality,
                exposed=a.exposed,
                classification=cast(Classification, a.classification),
                classification_at_evaluation=cast(Classification, a.classification_at_evaluation),
                finding_status=cast(FindingStatus, a.finding_status),
                score=a.score,
            )
            for a in assets
        ],
    )


@router.get("/api/assets/{ci_id}", dependencies=[guard("GET", "/api/assets/{ci_id}")])
def asset_detail(ci_id: str, session: SessionDep) -> AssetDetail:
    """A live CI and its vulnerabilities; each one carries this CI's final, level and status (D-035)."""
    found = views.asset_detail(session, ci_id)
    if found is None:
        raise _not_found("El activo")
    return AssetDetail(
        ci_id=found.ci_id,
        name=found.name,
        risk=found.risk,
        classification=cast(Classification, found.classification),
        owner=found.owner,
        custodian=found.custodian,
        findings=[_group_model(g) for g in found.findings],
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
