"""Grouped views, detail, history, comparison, recommendations, feedback, tickets and alerts (docs/13 §5 to §7)."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Annotated, Final, Literal, cast

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
)
from api.routes._auth import guard
from api.routes._config_support import CurrentUserDep
from api.routes._db import SessionDep
from api.routes._paths import CiId, UuidId
from api.routes.models import (
    AcceptedReason,
    AffectedAsset,
    Alert,
    AssetDetail,
    AssetRisk,
    AssetSoftware,
    Breakdown,
    Classification,
    ComparisonRow,
    ComparisonSummary,
    DoubleReviewInfo,
    FeedbackEntry,
    FeedbackRequest,
    FindingStatus,
    JudgeDetail,
    JudgeReasonItem,
    Level,
    Recommendation,
    RecommendationFilters,
    ReviewStatus,
    ScoreHistoryPoint,
    SoftwareCategory,
    SoftwareLicenceInfo,
    Ticket,
    TicketAction,
    TicketSummary,
    TicketUpdateEntry,
    TicketUpdateFilters,
    VulnerabilityBand,
    VulnerabilityDetail,
    VulnerabilityFilters,
    VulnerabilityGroup,
    VulnerabilityList,
)
from core.feedback.service import FeedbackRejectedError, SqlFeedbackService
from core.views import comparison, history, judge_detail, ticket_log
from core.views import groups as views
from core.views import recommendations as recs
from core.views import tickets_alerts as ta
from core.views.common import iso, parse_uuid
from notifications_api import FeedbackInput, FeedbackResult

logger = logging.getLogger(__name__)
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
def vulnerability_detail(group_id: UuidId, session: SessionDep, itop_url: ItopUrl) -> VulnerabilityDetail:
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
                finding_id=str(a.finding_id) if a.finding_id else None,
            )
            for a in assets
        ],
    )


@router.get("/api/assets/{ci_id}", dependencies=[guard("GET", "/api/assets/{ci_id}")])
def asset_detail(ci_id: CiId, session: SessionDep) -> AssetDetail:
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
        itop_class=found.itop_class,
        description=found.description,
        cpu=found.cpu,
        ram=found.ram,
        software=[_asset_software(s) for s in found.software],
    )


def _asset_software(item: views.AssetSoftware) -> AssetSoftware:
    licence = item.licence
    return AssetSoftware(
        software=item.software,
        version=item.version,
        category=cast(SoftwareCategory | None, item.category),
        status=cast(Literal["active", "inactive"] | None, item.status),
        description=item.description,
        licence=None
        if licence is None
        else SoftwareLicenceInfo(
            name=licence.name,
            usage_limit=licence.usage_limit,
            start_date=licence.start_date.isoformat() if licence.start_date else None,
            end_date=licence.end_date.isoformat() if licence.end_date else None,
            perpetual=licence.perpetual,
        ),
    )


@router.get("/api/findings/{id}/history", dependencies=[guard("GET", "/api/findings/{id}/history")])
def finding_history(id: UuidId, session: SessionDep) -> list[ScoreHistoryPoint]:  # noqa: A002 - path parameter name of API-06
    """Score of the finding's CI in each assessment of its group, oldest first (EVA-05). The judge adjustment
    shown is the group's plus the CI's own."""
    parsed = parse_uuid(id)
    points = history.finding_history(session, parsed) if parsed is not None else None
    if points is None:
        raise _not_found("El hallazgo")
    return [
        ScoreHistoryPoint(
            date=iso(p.assessed_at),
            base=p.base,
            judge_adjustment=p.judge_adjustment + p.ci_adjustment,
            final=p.final,
        )
        for p in points
    ]


@router.get("/api/comparison/summary", dependencies=[guard("GET", "/api/comparison/summary")])
def comparison_summary(session: SessionDep) -> ComparisonSummary:
    """Raw vs processed over the current scored findings (D-039, MET-24 to MET-27). The matrix crosses the CVSS
    level of the raw snapshot (rows) with the final level (columns); findings without CVSS stay out of the matrix
    and the indicators. `rank_correlation` is Kendall's tau-b, "0.00" when it is undefined."""
    found = comparison.summary(session)
    return ComparisonSummary(
        reclassification_matrix=found.reclassification_matrix,
        funnel=found.funnel,
        reclassified_percent=found.reclassified_percent,
        hidden_criticals=found.hidden_criticals,
        avoided_noise=found.avoided_noise,
        rank_correlation=found.rank_correlation,
    )


@router.get(
    "/api/comparison/table", dependencies=[guard("GET", "/api/comparison/table")], responses=PAGINATED_RESPONSES
)
def comparison_table(params: PageQuery, signer: Signer, session: SessionDep) -> Page[ComparisonRow]:
    """One row per current scored finding, largest change against the raw value first (EVA-11, EVA-12)."""
    after = _score_key(params, "comparison")
    rows, next_key = views.page_by_score(
        comparison.comparison_rows(session), lambda r: (abs(r.delta), r.finding_id), after, params.limit
    )
    return Page[ComparisonRow](
        items=[
            ComparisonRow(
                cve=r.cve,
                product=r.product,
                ci_id=r.ci_id,
                cvss=str(r.cvss) if r.cvss is not None else None,
                raw=r.raw,
                base=r.base,
                judge_adjustment=r.judge_adjustment,
                final=r.final,
                delta=r.delta,
                main_cause=r.main_cause,
            )
            for r in rows
        ],
        next_cursor=encode_key(signer, "comparison", next_key),
    )


@router.get("/api/assessments/{id}/breakdown", dependencies=[guard("GET", "/api/assessments/{id}/breakdown")])
def assessment_breakdown(
    id: UuidId,  # noqa: A002
    session: SessionDep,
    ci_id: Annotated[str | None, Query(max_length=100, description="CI of the waterfall; default the top one")] = None,
) -> Breakdown:
    """Waterfall of the change from the raw value to the final for one CI of the assessment (EVA-12)."""
    parsed = parse_uuid(id)
    found = None
    if parsed is not None and (ci_id is None or "\x00" not in ci_id):
        found = comparison.assessment_breakdown(session, parsed, ci_id)
    if found is None:
        raise _not_found("La evaluación")
    return Breakdown(
        assessment_id=str(found.assessment_id),
        waterfall=found.waterfall,
        final=found.final,
        ci_id=found.ci_id,
        raw=found.raw,
    )


def _recommendation_model(r: recs.Recommendation) -> Recommendation:
    a = r.asset
    return Recommendation(
        assessment_id=str(r.assessment_id),
        created_at=iso(r.created_at),
        cve=r.cve,
        product=r.product,
        base=r.base,
        judge_adjustment=r.judge_adjustment,
        final=r.final,
        level=cast(Level, r.level),
        previous_final=r.previous_final,
        justification=r.justification,
        mitigation=r.mitigation,
        mitigation_draft=r.mitigation_draft,
        asset=None
        if a is None
        else AffectedAsset(
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
        ),
        ticket_url=r.ticket_url,
        feedback_count=r.feedback_count,
        accepted_reasons=[
            AcceptedReason(code=x.code, label=x.label, points=x.points, quote=x.quote, ci_id=x.ci_id)
            for x in r.accepted_reasons
        ],
        judge_summary=r.judge_summary,
        judge_status=cast(ReviewStatus | None, r.judge_status),
        ticket_itop_id=r.ticket_itop_id,
    )


@router.get("/api/recommendations", dependencies=[guard("GET", "/api/recommendations")], responses=PAGINATED_RESPONSES)
def list_recommendations(
    params: PageQuery,
    signer: Signer,
    session: SessionDep,
    itop_url: ItopUrl,
    filters: Annotated[RecommendationFilters, Query()],
) -> Page[Recommendation]:
    """Recommendation feed, newest first (FRO-12); `group_id` or `ci_id` narrow it to one timeline, and the F18.1
    filters to a ticket's group, a level, a verdict or the ones without feedback (RE-1, RE-2).

    The score is the assessment's highest final (EVA-07); the CI shown is the most restrictive one at evaluation
    time, with its classification, owner and custodian of that moment (FRO-13), and the accepted judge reasons come
    with their quotes.
    """
    key = decode_key(params, "recommendations", ("time", "uuid"))
    group_id, ci_id = filters.group_id, filters.ci_id
    parsed_group = parse_uuid(group_id) if group_id is not None else None
    if (group_id is not None and parsed_group is None) or (ci_id is not None and "\x00" in ci_id):
        return Page[Recommendation](items=[], next_cursor=None)  # no group has that id, no CI has that text
    found, next_key = recs.list_recommendations(
        session,
        recs.Query(
            group_id=parsed_group,
            ci_id=ci_id,
            ticket=filters.ticket_itop_id,
            level=filters.level,
            verdict=filters.verdict,
            without_feedback=filters.without_feedback,
        ),
        itop_url,
        after=None if key is None else (key[0], key[1]),
        limit=params.limit,
    )
    return Page[Recommendation](
        items=[_recommendation_model(r) for r in found], next_cursor=encode_key(signer, "recommendations", next_key)
    )


@router.get("/api/recommendations/{assessment_id}", dependencies=[guard("GET", "/api/recommendations/{assessment_id}")])
def get_recommendation(assessment_id: UuidId, session: SessionDep, itop_url: ItopUrl) -> Recommendation:
    parsed = parse_uuid(assessment_id)
    found = recs.get_recommendation(session, parsed, itop_url) if parsed is not None else None
    if found is None:
        raise _not_found("La recomendación")
    return _recommendation_model(found)


def _reason_item(r: judge_detail.Reason) -> JudgeReasonItem:
    return JudgeReasonItem(
        seq=r.seq,
        code=r.code,
        label=r.label,
        points=r.points,
        quote=r.quote,
        element_id=r.element_id,
        ci_id=r.ci_id,
        status=cast(Literal["accepted", "rejected", "withdrawn"], r.status),
        rejection_rule=r.rejection_rule,
    )


@router.get(
    "/api/recommendations/{assessment_id}/judge",
    dependencies=[guard("GET", "/api/recommendations/{assessment_id}/judge")],
)
def recommendation_judge(assessment_id: UuidId, session: SessionDep) -> JudgeDetail:
    """The judge behind one assessment (FRO-13, RE-3, RE-5, RE-6): status, summary, proposed and applied adjustment,
    accepted and rejected reasons with their quotes, and the blind second review. Metadata and validated reasons
    only: never the prompt, the package or the raw calls (X-2)."""
    parsed = parse_uuid(assessment_id)
    found = judge_detail.judge_detail(session, parsed) if parsed is not None else None
    if found is None:
        raise _not_found("La recomendación")
    double = found.double_review
    return JudgeDetail(
        assessment_id=str(found.assessment_id),
        review_id=str(found.review_id) if found.review_id else None,
        status=cast(ReviewStatus | None, found.status),
        summary=found.summary,
        model=found.model,
        reviewed_at=iso(found.reviewed_at) if found.reviewed_at else None,
        proposed_adjustment=found.proposed_adjustment,
        applied_adjustment=found.applied_adjustment,
        dead_zone_applied=found.dead_zone_applied,
        accepted_reasons=[_reason_item(r) for r in found.accepted_reasons],
        rejected_reasons=[_reason_item(r) for r in found.rejected_reasons],
        double_review=None
        if double is None
        else DoubleReviewInfo(
            agreed=double.agreed,
            first_adjustment=double.first_adjustment,
            second_adjustment=double.second_adjustment,
            second_status=cast(ReviewStatus, double.second_status),
        ),
        mitigation_status=cast(Literal["accepted", "discarded", "absent"] | None, found.mitigation_status),
    )


FEEDBACK_ERRORS: Final = {
    "unauthorized_user": (403, "forbidden", "No tienes permisos para dar feedback."),
    "unknown_assessment": (404, "not_found", "La evaluación no existe."),
    "unknown_ticket": (422, "validation_error", "El ticket no corresponde a la evaluación."),
}


@router.post("/api/feedback", status_code=201, dependencies=[guard("POST", "/api/feedback")])
def post_feedback(feedback: FeedbackRequest, request: Request, user: CurrentUserDep) -> FeedbackResult:
    """Same `FeedbackService` as Slack (NOT-06). The user comes from the token, never from the body; it never
    changes the score by itself."""
    service = SqlFeedbackService(request.app.state.session_factory)
    try:
        return service.record(
            FeedbackInput(
                assessment_id=feedback.assessment_id,
                user_email=user.email,
                channel="frontend",
                verdict=feedback.verdict,
                proposed_level=feedback.proposed_level,
                proposed_score=feedback.proposed_score,
                comment=feedback.comment,
                ticket_itop_id=feedback.ticket_itop_id,
            )
        )
    except FeedbackRejectedError as error:
        # docs/14 §10.4: rejected feedback is a security event; the code only, never the input or the e-mail.
        logger.warning("feedback rejected: %s", error.code)
        status, code, message = FEEDBACK_ERRORS.get(error.code, (422, "validation_error", "El feedback no es válido."))
        raise ApiError(status, code, message) from None


@router.get("/api/recommendations/{id}/feedback", dependencies=[guard("GET", "/api/recommendations/{id}/feedback")])
def recommendation_feedback(id: UuidId, session: SessionDep) -> list[FeedbackEntry]:  # noqa: A002
    """Feedback received on one assessment, from Slack and the front, newest first, superseded ones included
    (FRO-15). `on_older_version`: a newer assessment of the same group changed the score."""
    parsed = parse_uuid(id)
    found = recs.feedback_of(session, parsed) if parsed is not None else None
    if found is None:
        raise _not_found("La recomendación")
    return [
        FeedbackEntry(
            user=f.user,
            channel=cast(Literal["frontend", "slack"], f.channel),
            verdict=f.verdict,
            proposed_level=cast(Level | None, f.proposed_level),
            proposed_score=f.proposed_score,
            comment=f.comment,
            created_at=iso(f.created_at),
            active=f.active,
            on_older_version=f.on_older_version,
        )
        for f in found
    ]


@router.get("/api/tickets", dependencies=[guard("GET", "/api/tickets")], responses=PAGINATED_RESPONSES)
def list_tickets(
    params: PageQuery,
    signer: Signer,
    session: SessionDep,
    itop_url: ItopUrl,
    urgency: int | None = Query(default=None, ge=1, le=4),
) -> Page[Ticket]:
    """Tickets already created in iTop (D-036), most urgent first, then newest. Before the first sync with iTop
    the urgency is the band of the ticket score (TIC-03). A CI counts as fixed when none of its linked findings
    is current or it was decommissioned."""
    key = decode_key(params, "tickets", ("int", "time", "uuid"))
    found, next_key = ta.list_tickets(
        session,
        itop_url,
        urgency=urgency,
        after=None if key is None else (key[0], key[1], key[2]),
        limit=params.limit,
    )
    return Page[Ticket](
        items=[
            Ticket(
                itop_id=t.itop_id,
                url=t.url,
                cve=t.cve,
                custodian=t.custodian,
                urgency=t.urgency,
                status=t.status,
                fixed_cis=t.fixed_cis,
                total_cis=t.total_cis,
            )
            for t in found
        ],
        next_cursor=encode_key(signer, "tickets", next_key),
    )


@router.get("/api/tickets/summary", dependencies=[guard("GET", "/api/tickets/summary")])
def ticket_summary(session: SessionDep) -> TicketSummary:
    """Every ticket by status (the ones Hermes keeps in step with iTop), the iTop ones by urgency, those whose urgency
    a person changed (D-007), the resolved share and the average resolution time (IN-3, AG-13, AG-15, AG-16)."""
    found = ticket_log.summary(session)
    return TicketSummary(
        total=found.total,
        by_status=found.by_status,
        by_urgency=found.by_urgency,
        changed_by_person=found.changed_by_person,
        resolved=found.resolved,
        resolved_percent=found.resolved_percent,
        avg_resolution_hours=found.avg_resolution_hours,
    )


@router.get("/api/tickets/updates", dependencies=[guard("GET", "/api/tickets/updates")], responses=PAGINATED_RESPONSES)
def ticket_updates(
    params: PageQuery,
    signer: Signer,
    session: SessionDep,
    itop_url: ItopUrl,
    filters: Annotated[TicketUpdateFilters, Query()],
) -> Page[TicketUpdateEntry]:
    """What Hermes did in each ticket and why, newest first (HI-4): creation, CIs added, urgency raised or lowered,
    comments and verified fixes, with the assessment behind each one and the state of its write to iTop."""
    key = decode_key(params, "ticket_updates", ("time", "uuid"))
    found, next_key = ticket_log.updates(
        session,
        itop_url,
        ticket_log.UpdateQuery(ticket=filters.ticket_itop_id, action=filters.action),
        after=None if key is None else (key[0], key[1]),
        limit=params.limit,
    )
    return Page[TicketUpdateEntry](
        items=[
            TicketUpdateEntry(
                id=str(u.id),
                created_at=iso(u.created_at),
                action=cast(TicketAction, u.action),
                label=u.label,
                assessment_id=str(u.assessment_id) if u.assessment_id else None,
                ticket_itop_id=u.ticket_itop_id,
                ticket_ref=u.ticket_ref,
                ticket_url=u.ticket_url,
                cve=u.cve,
                custodian=u.custodian,
                itop_status=cast(Literal["pending", "in_progress", "done", "failed"] | None, u.itop_status),
            )
            for u in found
        ],
        next_cursor=encode_key(signer, "ticket_updates", next_key),
    )


@router.get("/api/alerts", dependencies=[guard("GET", "/api/alerts")], responses=PAGINATED_RESPONSES)
def list_alerts(params: PageQuery, signer: Signer, session: SessionDep) -> Page[Alert]:
    """Threat alerts without a finding: R2 and R3 packages and mode 2 inferences, newest first."""
    key = decode_key(params, "alerts", ("time", "uuid"))
    found, next_key = ta.list_alerts(session, after=None if key is None else (key[0], key[1]), limit=params.limit)
    return Page[Alert](
        items=[
            Alert(
                id=str(a.id),
                created_at=iso(a.created_at),
                relevance=cast(Literal["R2", "R3", "inferred"], a.relevance),
                inferred=a.inferred,
                actor=a.actor,
                victim=a.victim,
                vector=a.vector,
                summary=a.summary,
                ci_id=a.ci_id,
            )
            for a in found
        ],
        next_cursor=encode_key(signer, "alerts", next_key),
    )
