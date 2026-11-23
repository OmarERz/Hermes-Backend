"""Content rules of `propose_reason` (L4-L7, VAL-03): code decides accepted or rejected, the model never does.

Each rejection names the broken rule (L4.*, L5.*, L6.*, L7.*) and a Spanish reason the model can act on
(VAL-05: a rejection is never fixed silently). Rule IDs:

- L4: closed list; L4.disabled (reason off or lowering not allowed by the profile); L4.package_type;
  L4.repeated (each reason once per review); L4.<code> (the reason's own rule); L4.corroboration (SEG-12).
- L5.element (ID not in this package); L5.asset (a CI reason that does not cite a CI); L5.quote (not verbatim, too
  short or too long); L5.reused (one quote, or a trimmed or extended copy of it, one reason).
- L6 (source level too low to lower, docs/09 §2); L6.suspicious (SEG-03 news cannot lower).
- L7.direction (direction not allowed or sign mismatch); L7.points; L7.explanation.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

from core.judge.catalog import MORE_CRITICAL_ASSET, OTHER, ReasonCatalog, ReasonSpec, SensitivityProfile
from core.judge.package import Element, ElementKind, ReviewPackage, SourceLevel, normalize_text

MIN_QUOTE_CHARS = 12
MAX_QUOTE_CHARS = 1000
MAX_EXPLANATION_CHARS = 2000
MIN_OTHER_EXPLANATION_CHARS = 20
MAX_ABS_POINTS = 100  # L1 has no cap, but the final is limited to 0-100: larger values are malformed
CORROBORATION_ABOVE = 20  # SEG-12: more than 20 points in one reason needs 2 independent sources
RECENT_DAYS = 30  # mass_exploitation: evidence from the last 30 days
RANSOMWARE_NEWS_MAX = 10  # ransomware only reported by news: at most +10
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")


@dataclass(frozen=True)
class ReasonProposal:
    reason_code: str
    direction: str
    points: int
    evidence_id: str
    quote: str
    explanation: str

    @classmethod
    def from_arguments(cls, arguments: Mapping[str, Any]) -> ReasonProposal:
        """Arguments already passed the strict schema (VAL-02), so types are known."""
        return cls(
            reason_code=str(arguments["reason_code"]),
            direction=str(arguments["direction"]),
            points=int(arguments["points"]),
            evidence_id=str(arguments["evidence_id"]),
            quote=str(arguments["quote"]),
            explanation=str(arguments["explanation"]),
        )


@dataclass(frozen=True)
class AcceptedReason:
    reason_id: str
    code: str
    proposed_points: int
    points: int  # applied points, after the sensitivity profile
    evidence_id: str
    quote: str
    ci_id: str | None  # more_critical_asset only (D-035)
    out_of_range: bool  # forces the double review (docs/07 §5)
    cites_suspicious: bool  # SEG-03: forces the double review


@dataclass(frozen=True)
class Verdict:
    accepted: bool
    rule: str | None = None
    reason: str | None = None
    points: int = 0
    ci_id: str | None = None
    out_of_range: bool = False
    cites_suspicious: bool = False


def _reject(rule: str, reason: str) -> Verdict:
    return Verdict(accepted=False, rule=rule, reason=reason)


def _never_active(_cve: str) -> bool:
    return False


@dataclass(frozen=True)
class RuleContext:
    package: ReviewPackage
    catalog: ReasonCatalog
    profile: SensitivityProfile
    today: date
    active_cve: Callable[[str], bool] = _never_active  # exploit_chain: is that CVE present in an active group?


def check_reason(proposal: ReasonProposal, accepted: Sequence[AcceptedReason], ctx: RuleContext) -> Verdict:
    """Validate one proposal against the package and the reasons already accepted in this review."""
    spec = ctx.catalog.get(proposal.reason_code)
    if spec is None:
        return _reject("L4", "El motivo no está en la lista cerrada.")
    verdict = (
        _check_listing(proposal, spec, accepted, ctx)
        or _check_shape(proposal, spec)
        or _check_evidence(proposal, accepted, ctx)
    )
    if verdict is not None:
        return verdict
    element = ctx.package.elements[proposal.evidence_id]
    if spec.applies_to_asset and element.ci_id is None:  # it adds to one CI: the evidence must be that CI (#64)
        return _reject("L5.asset", "Este motivo debe citar la descripción de un CI del paquete.")
    verdict = _check_level(proposal, spec, element, ctx) or _check_own_rule(proposal, element, ctx)
    if verdict is not None:
        return verdict
    points = ctx.profile.scale(proposal.points)
    if abs(points) > CORROBORATION_ABOVE and not _corroborated(element, ctx.package):
        return _reject("L4.corroboration", "Más de 20 puntos en un motivo exige 2 fuentes independientes.")
    return Verdict(
        accepted=True,
        points=points,
        ci_id=element.ci_id if spec.applies_to_asset else None,
        out_of_range=not spec.in_range(points, ctx.profile),
        cites_suspicious=element.suspicious,
    )


def _check_listing(
    proposal: ReasonProposal, spec: ReasonSpec, accepted: Sequence[AcceptedReason], ctx: RuleContext
) -> Verdict | None:
    if not spec.enabled or (proposal.direction == "down" and not ctx.profile.allow_lowering):
        return _reject("L4.disabled", "Ese motivo está desactivado por el perfil de sensibilidad.")
    if ctx.package.kind not in spec.package_types:
        return _reject("L4.package_type", "Ese motivo no aplica a este tipo de paquete.")
    if any(reason.code == spec.code for reason in accepted):
        return _reject("L4.repeated", "Cada motivo se usa una sola vez por revisión.")
    return None


def _check_shape(proposal: ReasonProposal, spec: ReasonSpec) -> Verdict | None:
    sign_ok = (proposal.direction == "up" and proposal.points > 0) or (
        proposal.direction == "down" and proposal.points < 0
    )
    if not spec.direction.allows(proposal.direction) or not sign_ok:
        return _reject("L7.direction", "La dirección no es la del motivo o el signo de los puntos no corresponde.")
    if abs(proposal.points) > MAX_ABS_POINTS:
        return _reject("L7.points", "Los puntos están fuera de la escala de 0 a 100.")
    explanation = proposal.explanation.strip()
    minimum = MIN_OTHER_EXPLANATION_CHARS if spec.code == OTHER else 1
    if not minimum <= len(explanation) <= MAX_EXPLANATION_CHARS:
        return _reject("L7.explanation", "Falta la explicación del motivo o es demasiado larga.")
    return None


def _check_evidence(proposal: ReasonProposal, accepted: Sequence[AcceptedReason], ctx: RuleContext) -> Verdict | None:
    element = ctx.package.elements.get(proposal.evidence_id)
    if element is None:
        return _reject("L5.element", "El elemento citado no existe en este paquete.")
    quote = normalize_text(proposal.quote)
    if not MIN_QUOTE_CHARS <= len(quote) <= MAX_QUOTE_CHARS or not element.contains(quote):
        return _reject("L5.quote", "La cita no aparece textual en el elemento citado.")
    # One evidence, one reason: a trimmed or extended version of an accepted quote in the same element is the same
    # evidence (pending F6.1 #61).
    for previous in (normalize_text(r.quote) for r in accepted if r.evidence_id == proposal.evidence_id):
        if quote in previous or previous in quote:
            return _reject("L5.reused", "Esa cita ya justifica otro motivo.")
    return None


def _check_level(proposal: ReasonProposal, spec: ReasonSpec, element: Element, ctx: RuleContext) -> Verdict | None:
    """L6: any level can raise; lowering needs N1, or N2 with a second independent source (docs/09 §2)."""
    if proposal.direction != "down":
        return None
    if element.suspicious:
        return _reject("L6.suspicious", "Un elemento marcado como sospechoso no puede usarse para bajar.")
    if _may_lower(spec, element, proposal.quote, ctx.package):
        return None
    if spec.code == "missing_configuration":
        return _reject("L6", "Este motivo exige un campo estructurado de iTop como evidencia.")
    return _reject("L6", "La fuente citada no tiene nivel suficiente para bajar la puntuación.")


def _may_lower(spec: ReasonSpec, element: Element, quote: str, package: ReviewPackage) -> bool:
    level = element.quote_level(quote)
    if spec.code == "missing_configuration":
        return element.kind is ElementKind.CI and level is SourceLevel.N1
    if level is SourceLevel.N1:
        return True
    # only `other` accepts N2 evidence, and only with a second independent N1/N2 source
    return level is SourceLevel.N2 and spec.code == OTHER and _corroborated(element, package, max_level=2)


def _check_own_rule(proposal: ReasonProposal, element: Element, ctx: RuleContext) -> Verdict | None:
    check = _OWN_RULES.get(proposal.reason_code)
    if check is None or check(proposal, element, ctx):
        return None
    return _reject(f"L4.{proposal.reason_code}", _OWN_RULE_REASONS[proposal.reason_code])


def _recent(proposal: ReasonProposal, element: Element, ctx: RuleContext) -> bool:
    limit = ctx.today - timedelta(days=RECENT_DAYS)
    if element.news is not None:
        published = element.news.published
        return published is not None and limit <= published <= ctx.today
    kev = ctx.package.kev
    if element.kind is ElementKind.CVE and kev["listed"] and kev["date"]:
        listed = _date(str(kev["date"]))
        return listed is not None and limit <= listed <= ctx.today
    return False


def _ransomware(proposal: ReasonProposal, element: Element, ctx: RuleContext) -> bool:
    return bool(ctx.package.kev["known_ransomware"]) or proposal.points <= RANSOMWARE_NEWS_MAX


def _zero_day(proposal: ReasonProposal, element: Element, ctx: RuleContext) -> bool:
    cve = ctx.package.cve_data
    if cve is None:
        return True
    patched = any("Patch" in (ref.get("tags") or []) for ref in cve["references"])
    return cve["fixed_version"] is None and not patched


def _more_critical_asset(proposal: ReasonProposal, element: Element, ctx: RuleContext) -> bool:
    return (
        element.kind is ElementKind.CI
        and element.ci_id in ctx.package.ci_ids
        and element.quote_in_free_text(proposal.quote)
    )


def _exploit_chain(proposal: ReasonProposal, element: Element, ctx: RuleContext) -> bool:
    others = set(CVE_ID.findall(normalize_text(proposal.quote))) - {ctx.package.group_cve}
    return any(ctx.active_cve(cve) for cve in sorted(others))


def _requires_authentication(proposal: ReasonProposal, element: Element, ctx: RuleContext) -> bool:
    cve = ctx.package.cve_data
    vector = cve["vector"] if cve is not None else None
    return vector is None or "PR:N" in vector or "AV:N" in vector


def _missing_configuration(proposal: ReasonProposal, element: Element, ctx: RuleContext) -> bool:
    cve = ctx.package.cve_data
    return cve is not None and bool(cve["conditions"])


_OWN_RULES: Mapping[str, Callable[[ReasonProposal, Element, RuleContext], bool]] = {
    "mass_exploitation": _recent,
    "ransomware": _ransomware,
    "zero_day": _zero_day,
    MORE_CRITICAL_ASSET: _more_critical_asset,
    "exploit_chain": _exploit_chain,
    "requires_authentication": _requires_authentication,
    "missing_configuration": _missing_configuration,
}
_OWN_RULE_REASONS: Mapping[str, str] = {
    "mass_exploitation": "La evidencia de explotación masiva debe ser de los últimos 30 días.",
    "ransomware": "Sin la marca de ransomware de KEV, el máximo es +10.",
    "zero_day": "Existe una versión corregida o una referencia Patch: no es día cero.",
    MORE_CRITICAL_ASSET: "La evidencia debe ser la descripción de un CI de este grupo.",
    "exploit_chain": "El otro CVE de la cadena no está presente en ningún grupo activo.",
    "requires_authentication": "El vector CVSS ya refleja ese requisito.",
    "missing_configuration": "El CVE no declara una configuración vulnerable que iTop pueda descartar.",
}


def _corroborated(element: Element, package: ReviewPackage, max_level: int = 4) -> bool:
    """SEG-12: another non-suspicious news story, from a different domain, backs the cited source."""
    own_domains = element.news.domains if element.news is not None else frozenset()
    own_story = element.news.story_id if element.news is not None else None
    for other in package.news_elements:
        news = other.news
        if other.element_id == element.element_id or news is None or news.suspicious:
            continue
        if other.source_level.rank > max_level or news.story_id == own_story or not news.domains:
            continue
        if news.domains.isdisjoint(own_domains):
            return True
    return False


def _date(value: str) -> date | None:
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None
