"""Mode 2 · dismissal candidates (docs/07 §7, L15; docs/06 COR-07; docs/15 F-10).

A news item with a relevant security event that correlation did not match goes to the judge with the profile, the
iTop stack summary and the peer companies. The judge either dismisses it (`dismiss_news`) or proposes an alert for a
relationship code did not see (`propose_alert`). Code validates every proposal:

- the news and the evidence belong to this package and the quote is verbatim (L5);
- confidence is a number in 0..1 and at least the minimum of the profile (`mode2.min_confidence`, docs/07 §12);
- a cited product appears verbatim in the news; a `direct` relationship needs one;
- a cited CI exists in the iTop inventory;
- a relationship a person refuted is never proposed again (`verified_relationship`, docs/07 §7);
- an automatic ticket is allowed only when a CI is cited **and** the news names a product that CI runs (L15);
  otherwise it is only an alert labelled "relación inferida por IA".

The judge never writes iTop or Slack (L8): this module only decides; persistence and tickets are elsewhere.
"""

from __future__ import annotations

import re
import unicodedata
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Protocol

from core.judge.package import ElementKind, ReviewPackage, normalize_text
from core.judge.prompt import MODE2_PROMPT_VERSION, mode2_system_prompt
from core.judge.rules import MAX_QUOTE_CHARS, MIN_QUOTE_CHARS
from core.judge.session import (
    Decision,
    Failure,
    JudgeEnvironment,
    JudgeSession,
    ReviewOutcome,
    ReviewStatus,
    ToolCaller,
    ToolResult,
)
from core.llm import ToolDefinition

MODE2_TOOLS = ("read_element", "propose_alert", "dismiss_news")
MAX_TEXT_CHARS = 1000
CONFIDENCE_QUANTUM = Decimal("0.01")  # alert.confidence is numeric(3,2)
# Tool relationship types -> alert.relationship_type (a `direct` relationship is an R2 the code missed)
RELATIONSHIP_TYPES = {
    "inferred_component": "component",
    "inferred_fork": "fork",
    "inferred_supplier": "supplier",
    "inferred_peer": "peer",
    "inferred_chain": "chain",
}
_ARROW = re.compile(r"\s*(?:→|->)\s*")
_RELATIONSHIP_ENDS = 2  # "A → B" (or "A → uses → B") has a subject and an object


class Inventory(Protocol):
    """Read-only view of the iTop cache (asset, installed_software)."""

    def find_asset(self, ci_id: str) -> uuid.UUID | None: ...

    def products(self, asset_id: uuid.UUID) -> Sequence[tuple[uuid.UUID, str]]:
        """(installed_software_id, product name) of what the asset currently runs."""
        ...


class EmptyInventory:
    def find_asset(self, ci_id: str) -> uuid.UUID | None:
        return None

    def products(self, asset_id: uuid.UUID) -> Sequence[tuple[uuid.UUID, str]]:
        return ()


def _never_refuted(_relationship_type: str, _subject: str, _object: str) -> bool:
    return False


@dataclass(frozen=True)
class Mode2Context:
    min_confidence: Decimal
    inventory: Inventory
    # (relationship type, subject identity, object identity) -> a person refuted it (see `relation_identity`)
    refuted: Callable[[str, str, str], bool] = _never_refuted


@dataclass(frozen=True)
class AlertDecision:
    """A validated `propose_alert`: what the alert row and its asset link need."""

    news_id: str
    story_id: str
    relevance: str  # inferred, or R2 for a direct relationship
    relationship_type: str | None  # alert.relationship_type (None for direct)
    relationship: str
    verification_action: str
    confidence: Decimal
    cited_product: str | None
    ci_id: str | None
    asset_id: uuid.UUID | None
    installed_software_id: uuid.UUID | None
    ticket_eligible: bool  # L15: CI cited and the news names a product that CI runs
    evidence_id: str
    quote: str
    subject: str  # normalized parts of the relationship (verified_relationship)
    object: str
    predicate: str = ""  # what the relationship states between its ends ('usa', 'no depende de'), normalized
    suspicious: bool = False  # SEG-03: the news is flagged, so a blind second review must agree


def relationship_parts(relationship: str, cited_product: str) -> tuple[str, str]:
    """Normalized (subject, object) of 'A → uses → B'; the subject defaults to the cited product."""
    parts = [p for p in _ARROW.split(relationship.strip()) if p]
    has_ends = len(parts) >= _RELATIONSHIP_ENDS
    subject = parts[0] if has_ends else cited_product
    obj = parts[-1] if has_ends else relationship
    return normalize_text(subject).casefold(), normalize_text(obj).casefold()


class _RejectedError(Exception):
    """Internal control flow of `check_alert`: the proposal broke `rule`. Never escapes this module."""

    def __init__(self, rule: str, reason: str) -> None:
        super().__init__(rule)
        self.rule = rule
        self.reason = reason


def _require(condition: bool, rule: str, reason: str) -> None:
    if not condition:
        raise _RejectedError(rule, reason)


def check_alert(
    args: Mapping[str, Any], package: ReviewPackage, ctx: Mode2Context
) -> tuple[AlertDecision | None, str | None, str | None]:
    """Validate one `propose_alert`. Returns the decision, or None with the broken rule and a Spanish reason."""
    try:
        return _decide(args, package, ctx), None, None
    except _RejectedError as rejected:
        return None, rejected.rule, rejected.reason


def _decide(args: Mapping[str, Any], package: ReviewPackage, ctx: Mode2Context) -> AlertDecision:
    news = package.elements.get(str(args["news_id"]))
    if news is None or news.news is None:
        raise _RejectedError("L5.element", "La noticia citada no es la de este paquete.")
    _require(
        str(args["evidence_id"]) == news.element_id,
        "L5.element",
        "La evidencia debe ser la misma noticia que se propone.",
    )
    prose = normalize_text(news.news.prose)  # title and summary: never URLs or the source name
    quote = normalize_text(str(args["quote"]))
    verbatim = MIN_QUOTE_CHARS <= len(quote) <= MAX_QUOTE_CHARS and quote in prose
    _require(verbatim, "L5.quote", "La cita no aparece textual en el título o el resumen de la noticia.")
    confidence = args["confidence"]
    numeric = not isinstance(confidence, bool) and isinstance(confidence, int | float) and 0 <= confidence <= 1
    _require(numeric, "L7.confidence", "La confianza debe ser un número entre 0 y 1.")
    exact = Decimal(str(confidence))
    _require(
        exact >= ctx.min_confidence, "L15.confidence", "La confianza es menor que el mínimo del perfil de sensibilidad."
    )
    relationship = normalize_text(str(args["relationship"]))
    action = normalize_text(str(args["suggested_action"]))
    texts_ok = bool(relationship) and bool(action) and max(len(relationship), len(action)) <= MAX_TEXT_CHARS
    _require(texts_ok, "L7.text", "Faltan la relación explícita o la acción de verificación, o son demasiado largas.")
    product = normalize_text(str(args["cited_product"]))
    _require(
        not product or _names_product(product, prose),
        "L15.product",
        "El producto citado no aparece textual en la noticia.",
    )
    kind = str(args["relationship_type"])
    _require(
        kind != "direct" or (bool(product) and _in_stack(product, package.stack_summary)),
        "L15.direct",
        "Una relación directa exige un producto del stack de iTop nombrado tal cual en la noticia.",
    )
    ci_id = str(args["ci_id"]).strip()
    asset_id = ctx.inventory.find_asset(ci_id) if ci_id else None
    _require(not ci_id or asset_id is not None, "L15.ci", "El CI citado no existe en el inventario de iTop.")
    mapped = RELATIONSHIP_TYPES.get(kind)
    subject, obj = relationship_parts(relationship, product)
    explicit = len([p for p in _ARROW.split(relationship) if p]) >= _RELATIONSHIP_ENDS
    if product:
        ends_on_product = _word_in(product_name(product), obj)
    else:  # no cited product: the object's head must not be a stack product the news never names (E11)
        ends_on_product = not any(
            (name := product_name(entry)) and _word_in(name, _head(obj)) and not _word_in(name, prose)
            for entry in package.stack_summary
        )
    _require(
        mapped is None or (explicit and ends_on_product),
        "L15.relationship",
        "Una relación inferida debe ser explícita ('A → relación → B') y terminar en el producto que nombra la "
        "noticia.",
    )
    _require(
        not any(
            ctx.refuted(mapped or kind, sub_id, obj_id)
            for sub_id in _identities(subject)
            for obj_id in _identities(obj)
        ),
        "L15.refuted",
        "Una persona ya refutó esta relación; no se vuelve a proponer.",
    )
    software_id = _cited_installation(ctx.inventory, asset_id, product) if asset_id is not None and product else None
    return AlertDecision(
        news_id=news.element_id,
        story_id=news.news.story_id,
        relevance="R2" if mapped is None else "inferred",
        relationship_type=mapped,
        relationship=relationship,
        verification_action=action,
        confidence=exact.quantize(CONFIDENCE_QUANTUM, rounding=ROUND_HALF_UP),  # alert.confidence numeric(3,2)
        cited_product=product or None,
        ci_id=ci_id or None,
        asset_id=asset_id,
        installed_software_id=software_id,
        ticket_eligible=software_id is not None,
        evidence_id=news.element_id,
        quote=quote,
        subject=subject,
        object=obj,
        predicate=_predicate(relationship),
        suspicious=news.suspicious,
    )


_VERSION_TOKEN = re.compile(
    r"v?\d+(?:\.[\dx*]+)+[a-z]?(?:[-+][\w.]+)?|v\d+"
)  # 3.x, 1.24.0, 1.1.1k, v2; not "10" in "Windows 10"
_TRAILING_VERSION = re.compile(r"\s+v?\d[\w.+-]*$")


def _in_stack(product: str, stack_summary: Sequence[str]) -> bool:
    """A `direct` relationship needs the same product in the iTop stack ('Nginx 1.24.0' is 'Nginx', not 'Nginx Proxy
    Manager')."""
    wanted = product_name(product)
    return bool(wanted) and any(product_name(entry) == wanted for entry in stack_summary)


def _names_product(product: str, prose: str) -> bool:
    """The product appears as written, as whole words (a fragment of a longer word is not the product)."""
    return re.search(rf"(?<![\w]){re.escape(product)}(?![\w])", prose) is not None


_ARTICLES = frozenset({"el", "la", "los", "las", "un", "una", "the", "a", "an"})
_CONNECTORS = frozenset({"de", "del", "en", "para", "con", "sobre", "of", "on", "in", "for", "from", "with"})


def _head(end: str) -> str:
    """What an end of a relationship is about: without leading articles, up to the first connector ('el servidor
    Nginx' -> 'servidor nginx'; 'OpenSSL del sistema operativo Ubuntu' -> 'openssl')."""
    words = end.casefold().split()
    while words and words[0] in _ARTICLES:
        words = words[1:]
    kept: list[str] = []
    for word in words:
        if word in _CONNECTORS:
            break
        kept.append(word)
    return " ".join(kept)


def _predicate(relationship: str) -> str:
    """What the relationship states between its ends, keeping every word that carries meaning ('runs on' is not
    'runs with', 'no usa' is not 'usa'): only accents, case, spaces and articles are normalized."""
    middle = " ".join([p for p in _ARROW.split(relationship) if p][1:-1])
    plain = "".join(c for c in unicodedata.normalize("NFKD", middle) if not unicodedata.combining(c))
    return " ".join(w for w in plain.casefold().split() if w not in _ARTICLES)


def _identities(end: str) -> set[str]:
    """The identity of an end, also without a trailing bare major version ('Apache Tomcat 9' is refuted as 'Apache
    Tomcat'); when in doubt a refutation wins."""
    identity = relation_identity(end)
    return {identity, re.sub(r"\s+\d+$", "", identity)}


def _claim(end: str) -> str:
    """An end as the blind review must corroborate it: versions and qualifiers kept (Ubuntu 22.04 is not 24.04)."""
    plain = "".join(c for c in unicodedata.normalize("NFKD", end) if not unicodedata.combining(c))
    return " ".join(w for w in plain.casefold().split() if w not in _ARTICLES)


def relation_identity(end: str) -> str:
    """Identity of one end of a relationship, the same on both sides (stored refutations and new proposals): no
    accents, casefolded, without articles, connectors and dotted version tokens (anywhere; a bare number such as the
    10 of 'Windows 10' is part of the name). Qualifiers stay:
    'la OpenSSL del sistema operativo Ubuntu' is 'openssl sistema operativo ubuntu', not the Windows one."""
    plain = "".join(c for c in unicodedata.normalize("NFKD", end) if not unicodedata.combining(c))
    words = [
        w
        for w in normalize_text(plain).casefold().split()
        if w not in _ARTICLES and w not in _CONNECTORS and not _VERSION_TOKEN.fullmatch(w)
    ]
    return " ".join(words)


def _word_in(needle: str, text: str) -> bool:
    needle, text = needle.casefold(), text.casefold()
    return bool(needle) and re.search(rf"(?<![\w]){re.escape(needle)}(?![\w])", text) is not None


def product_name(product: str) -> str:
    """Product identity without its version: 'OpenSSL 3.x' -> 'openssl', 'Nginx 1.24.0' -> 'nginx'."""
    return _TRAILING_VERSION.sub("", normalize_text(product).casefold())


def _cited_installation(inventory: Inventory, asset_id: uuid.UUID, product: str) -> uuid.UUID | None:
    """L15: the CI's installed software that IS the cited product (same name without version), if any."""
    wanted = product_name(product)
    for software_id, name in inventory.products(asset_id):
        if wanted and product_name(name) == wanted:
            return software_id
    return None


class DismissalSession(JudgeSession):
    """One mode 2 review: ends with one accepted alert, a dismissal, the limits or a fallback."""

    MODE = "dismissals"
    PROMPT_VERSION = MODE2_PROMPT_VERSION
    TOOL_NAMES = MODE2_TOOLS

    def __init__(
        self,
        caller: ToolCaller,
        package: ReviewPackage,
        env: JudgeEnvironment,
        mode2: Mode2Context,
        tools: Mapping[str, ToolDefinition] | None = None,
    ) -> None:
        if package.kind != "dismissal_candidate":
            raise ValueError("mode 2 reviews only dismissal candidates")
        self._mode2 = mode2
        self._alert: AlertDecision | None = None
        self._dismissal: str | None = None
        self._last_rule: str | None = None
        super().__init__(caller, package, env, tools)

    def _system_prompt(self) -> str:
        return mode2_system_prompt(self._env.settings, self._mode2.min_confidence)

    def _handlers(self) -> Mapping[str, Callable[[Mapping[str, Any]], ToolResult]]:
        return {
            "read_element": self._read_element,
            "propose_alert": self._propose_alert,
            "dismiss_news": self._dismiss_news,
        }

    def _finished(self) -> bool:
        return self._alert is not None or self._dismissal is not None

    def _finished_status(self) -> ReviewStatus:
        return ReviewStatus.APPLIED  # the degradation ladder only governs score adjustments (docs/07 §8)

    def _partial_status(self) -> ReviewStatus:
        return ReviewStatus.PARTIAL_REVIEW

    def _content_rejection(self, result: str, rule: str, reason: str) -> ToolResult:
        """Every content rejection counts against JUE-02; the same rule twice in a row ends the review (VAL-05)."""
        state = self._state
        state.rejections += 1
        if rule == self._last_rule:
            state.rejections = max(state.rejections, self._settings.max_rejections)
        self._last_rule = rule
        return {"result": result, "rule": rule, "reason": reason}, rule, reason

    def _read_element(self, args: Mapping[str, Any]) -> ToolResult:
        result, rule, reason = super()._read_element(args)
        if rule is not None:
            return self._content_rejection("error", rule, str(reason))
        return result, rule, reason

    def _propose_alert(self, args: Mapping[str, Any]) -> ToolResult:
        decision, rule, reason = check_alert(args, self._package, self._mode2)
        if decision is None:
            return self._content_rejection("rejected", str(rule), str(reason))
        self._alert = decision
        return {"result": "accepted", "ticket_eligible": decision.ticket_eligible}, None, None

    def _dismiss_news(self, args: Mapping[str, Any]) -> ToolResult:
        news = self._package.elements.get(str(args["news_id"]))
        reason_text = normalize_text(str(args["reason"]))
        if news is None or news.kind is not ElementKind.NEWS:
            return self._content_rejection("error", "L5.element", "La noticia citada no es la de este paquete.")
        if not reason_text or len(reason_text) > MAX_TEXT_CHARS:
            return self._content_rejection("error", "L7.text", "Falta la razón del descarte o es demasiado larga.")
        self._dismissal = reason_text
        return {"result": "ok"}, None, None

    def _outcome(self, status: ReviewStatus, failure: Failure | None, decision: Decision) -> ReviewOutcome:
        outcome = self._base_outcome(status, failure, decision)
        decided = status is ReviewStatus.APPLIED
        summary = self._dismissal if self._dismissal else (self._alert.relationship if self._alert else None)
        return replace(
            outcome,
            adjustment=None,  # mode 2 never adjusts a score
            ci_adjustments={},
            summary=summary if decided else None,
            alert=self._alert if decided else None,
            dismissal=self._dismissal if decided else None,
        )


def mode2_min_confidence(env: JudgeEnvironment) -> Decimal:
    """The explicit `mode2.min_confidence` setting when an admin set one, else the profile's value (§12)."""
    explicit = env.settings.mode2_min_confidence
    return explicit if explicit is not None else env.profile.mode2_min_confidence


@dataclass(frozen=True)
class Mode2Result:
    """The outcome of one candidate: the review, the blind second review when SEG-03 asked for one, the decision."""

    status: ReviewStatus
    first: ReviewOutcome
    second: ReviewOutcome | None = None
    alert: AlertDecision | None = None
    dismissal: str | None = None


def _same_alert(first: AlertDecision, second: AlertDecision) -> bool:
    """The blind review corroborates the alert: same story, relevance, type, CI, cited product, both ends and the
    predicate of the relationship (its polarity included) and ticketing installation."""

    def key(alert: AlertDecision) -> tuple[object, ...]:
        return (
            alert.story_id,
            alert.relevance,
            alert.relationship_type,
            alert.asset_id,
            relation_identity(alert.cited_product or ""),
            _claim(alert.subject),
            alert.predicate,
            _claim(alert.object),
            alert.installed_software_id,
        )

    return key(first) == key(second)


def review_candidate(
    caller: ToolCaller,
    package: ReviewPackage,
    env: JudgeEnvironment,
    mode2: Mode2Context,
    tools: Mapping[str, ToolDefinition] | None = None,
) -> Mode2Result:
    """Run mode 2. A suspicious news item (SEG-03) needs a blind second review that reaches the same decision: the
    same alert (relevance, type, CI, cited product, ticketing installation) or a dismissal too; otherwise nothing is
    raised and the result is `judge_disagreement`."""
    first = DismissalSession(caller, package, env, mode2, tools).run()
    suspicious = any(e.suspicious for e in package.news_elements)
    if first.status is not ReviewStatus.APPLIED or not suspicious:
        return Mode2Result(first.status, first, alert=first.alert, dismissal=first.dismissal)
    second = DismissalSession(caller, package, env, mode2, tools).run()
    if second.status in (ReviewStatus.NO_JUDGE_REVIEW, ReviewStatus.PARTIAL_REVIEW):  # no decision to compare
        return Mode2Result(second.status, first, second)
    if first.alert is not None and second.alert is not None and _same_alert(first.alert, second.alert):
        return Mode2Result(ReviewStatus.APPLIED, first, second, alert=first.alert)
    if first.dismissal is not None and second.dismissal is not None:
        return Mode2Result(ReviewStatus.APPLIED, first, second, dismissal=first.dismissal)
    return Mode2Result(ReviewStatus.JUDGE_DISAGREEMENT, first, second)
