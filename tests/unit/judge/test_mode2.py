"""Mode 2 on dismissal candidates (docs/07 §7, L15; docs/15 F-10) against the deterministic LLM double, including
the reference case E11 (OpenSSL 3.x news while iTop only has Nginx on Ubuntu)."""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from datetime import date
from decimal import Decimal
from typing import Any

import pytest

from core.judge.budget import FREE, UnlimitedDailyBudget
from core.judge.catalog import JudgeSettings, ReasonCatalog, SensitivityProfile
from core.judge.mode2 import (
    DismissalSession,
    EmptyInventory,
    Mode2Context,
    check_alert,
    mode2_min_confidence,
    relationship_parts,
    review_candidate,
)
from core.judge.package import ReviewPackage
from core.judge.session import Failure, JudgeEnvironment, ReviewStatus
from doubles.llm import LlmDouble, tool_call_completion
from harness.judge import dismissal_package, double_llm_client, finding_package

pytestmark = pytest.mark.unit

NGINX_ASSET = uuid.UUID("0196a6f0-0000-7000-8000-0000000000aa")
NGINX_SOFTWARE = uuid.UUID("0196a6f0-0000-7000-8000-0000000000bb")
OPENSSL_SOFTWARE = uuid.UUID("0196a6f0-0000-7000-8000-0000000000cc")
QUOTE = "A critical memory corruption flaw affects OpenSSL 3.x"
INFERRED = {
    "news_id": "N1",
    "ci_id": "",
    "cited_product": "OpenSSL 3.x",
    "relationship_type": "inferred_component",
    "relationship": "Nginx → usa → OpenSSL del sistema operativo Ubuntu",
    "evidence_id": "N1",
    "quote": QUOTE,
    "suggested_action": "Verificar la versión de OpenSSL de Ubuntu (posible parche retroportado).",
    "confidence": 0.7,
}


class FakeInventory:
    def __init__(self, products: dict[uuid.UUID, Sequence[tuple[uuid.UUID, str]]] | None = None) -> None:
        self._products = products or {NGINX_ASSET: [(NGINX_SOFTWARE, "Nginx")]}

    def find_asset(self, ci_id: str) -> uuid.UUID | None:
        return NGINX_ASSET if ci_id == "CI-7" else None

    def products(self, asset_id: uuid.UUID) -> Sequence[tuple[uuid.UUID, str]]:
        return self._products.get(asset_id, ())


def env(**overrides: Any) -> JudgeEnvironment:
    values: dict[str, Any] = {
        "catalog": ReasonCatalog.default(),
        "profile": SensitivityProfile.named("normal"),
        "settings": JudgeSettings(),
        "today": date(2026, 11, 22),
        "daily_budget": UnlimitedDailyBudget(),
        "price": FREE,
    }
    values.update(overrides)
    return JudgeEnvironment(**values)


def ctx(**overrides: Any) -> Mode2Context:
    values: dict[str, Any] = {"min_confidence": Decimal("0.6"), "inventory": FakeInventory()}
    values.update(overrides)
    return Mode2Context(**values)


def package(content: dict[str, Any] | None = None) -> ReviewPackage:
    return ReviewPackage.from_content(content or dismissal_package())


def alert_args(**overrides: Any) -> dict[str, Any]:
    return {**INFERRED, **overrides}


def run(responses: list[dict[str, Any]], mode2: Mode2Context | None = None, **env_overrides: Any) -> Any:
    double = LlmDouble()
    double.add_case("case", responses)
    double.use("case")
    session = DismissalSession(double_llm_client(double), package(), env(**env_overrides), mode2 or ctx())
    return session.run(), double


def propose(args: dict[str, Any], call_id: str = "p") -> dict[str, Any]:
    return tool_call_completion("propose_alert", args, call_id=call_id)


def dismiss(reason: str = "No aplica: la empresa no usa ese producto.", news_id: str = "N1") -> dict[str, Any]:
    return tool_call_completion("dismiss_news", {"news_id": news_id, "reason": reason}, call_id="d")


# --- rules -----------------------------------------------------------------------------------------------------
def test_e11_inferred_os_package_alert_without_automatic_ticket() -> None:
    decision, rule, _reason = check_alert(alert_args(), package(), ctx())
    assert rule is None
    assert decision is not None
    assert (decision.relevance, decision.relationship_type) == ("inferred", "component")
    assert decision.confidence == Decimal("0.70")
    assert decision.cited_product == "OpenSSL 3.x"
    assert decision.asset_id is None
    assert not decision.ticket_eligible  # no CI cited: alert only, labelled as AI-inferred
    assert decision.story_id == "0196a6f0-0000-7000-8000-000000000001"
    assert (decision.subject, decision.object) == ("nginx", "openssl del sistema operativo ubuntu")


def test_e11_an_inferred_claim_that_nginx_is_affected_is_rejected() -> None:
    for relationship in ("Nginx está afectado", "OpenSSL → afecta → Nginx"):
        _none, rule, _reason = check_alert(alert_args(relationship=relationship), package(), ctx())
        assert rule == "L15.relationship"


def test_a_product_named_as_part_of_another_name_is_not_the_same_product() -> None:
    content = dismissal_package()
    content["news"][0]["summary"] = "A critical memory corruption flaw affects OpenSSL 3.x in Nginx Proxy Manager."
    inventory = FakeInventory({NGINX_ASSET: [(NGINX_SOFTWARE, "Nginx")]})
    args = alert_args(
        ci_id="CI-7", cited_product="Nginx Proxy Manager", relationship="CI-7 → ejecuta → Nginx Proxy Manager"
    )
    decision, rule, _reason = check_alert(args, package(content), ctx(inventory=inventory))
    assert rule is None
    assert decision is not None
    assert not decision.ticket_eligible  # Nginx is not Nginx Proxy Manager
    _none, rule, _reason = check_alert(alert_args(cited_product="OpenSS"), package(), ctx())
    assert rule == "L15.product"  # a fragment of a word is not the product named in the news


def test_e11_nginx_is_affected_is_rejected() -> None:
    """The wrong answer of the reference case: the news never names Nginx."""
    args = alert_args(relationship_type="direct", cited_product="Nginx", ci_id="CI-7", relationship="Nginx afectado")
    decision, rule, reason = check_alert(args, package(), ctx())
    assert decision is None
    assert rule == "L15.product"
    assert reason


def test_ticket_only_with_a_cited_ci_whose_product_the_news_names() -> None:
    inventory = FakeInventory({NGINX_ASSET: [(NGINX_SOFTWARE, "Nginx"), (OPENSSL_SOFTWARE, "OpenSSL")]})
    decision, _rule, _reason = check_alert(alert_args(ci_id="CI-7"), package(), ctx(inventory=inventory))
    assert decision is not None
    assert decision.asset_id == NGINX_ASSET
    assert decision.installed_software_id == OPENSSL_SOFTWARE
    assert decision.ticket_eligible
    only_nginx, _rule, _reason = check_alert(alert_args(ci_id="CI-7"), package(), ctx())
    assert only_nginx is not None
    assert only_nginx.asset_id == NGINX_ASSET
    assert not only_nginx.ticket_eligible  # the CI does not run a product the news names
    content = dismissal_package()
    content["news"][0]["summary"] += " Nginx servers terminate TLS with it."
    nginx_only = FakeInventory({NGINX_ASSET: [(NGINX_SOFTWARE, "Nginx")]})
    other, _rule, _reason = check_alert(alert_args(ci_id="CI-7"), package(content), ctx(inventory=nginx_only))
    assert other is not None
    assert not other.ticket_eligible  # the news names Nginx, but the alert cites OpenSSL
    assert other.installed_software_id is None
    no_product, _rule, _reason = check_alert(
        alert_args(ci_id="CI-7", cited_product=""), package(), ctx(inventory=inventory)
    )
    assert no_product is not None
    assert not no_product.ticket_eligible


def test_direct_relationship_needs_a_stack_product_named_in_the_news() -> None:
    # OpenSSL 3.x is named by the news but is not in the stack summary (Nginx, Ubuntu): not a direct relationship
    _none, rule, _reason = check_alert(alert_args(relationship_type="direct"), package(), ctx())
    assert rule == "L15.direct"
    _none, rule, _reason = check_alert(alert_args(relationship_type="direct", cited_product=""), package(), ctx())
    assert rule == "L15.direct"
    content = dismissal_package()
    content["news"][0]["summary"] += " Nginx 1.24 builds linked against it are affected."
    for product in ("Nginx", "Nginx 1.24"):
        decision, rule, _reason = check_alert(
            alert_args(relationship_type="direct", cited_product=product), package(content), ctx()
        )
        assert rule is None
        assert decision is not None
        assert (decision.relevance, decision.relationship_type) == ("R2", None)


def test_products_are_named_in_the_prose_not_in_urls_or_source() -> None:
    content = dismissal_package()
    content["news"][0]["urls"] = ["https://nginx.org/security/openssl-3"]
    _none, rule, _reason = check_alert(alert_args(cited_product="openssl-3"), package(content), ctx())
    assert rule == "L15.product"
    inventory = FakeInventory({NGINX_ASSET: [(NGINX_SOFTWARE, "Nginx")]})
    decision, _rule, _reason = check_alert(alert_args(ci_id="CI-7"), package(content), ctx(inventory=inventory))
    assert decision is not None
    assert not decision.ticket_eligible  # "nginx" only in the URL is not the news naming the product


@pytest.mark.parametrize(
    ("overrides", "rule"),
    [
        ({"news_id": "N9"}, "L5.element"),
        ({"evidence_id": "N9"}, "L5.element"),
        ({"quote": "A flaw affects some library"}, "L5.quote"),
        ({"quote": "https://media.example.test/openssl-3"}, "L5.quote"),  # from the element, not the prose
        ({"quote": "OpenSSL"}, "L5.quote"),
        ({"confidence": 1.5}, "L7.confidence"),
        ({"confidence": True}, "L7.confidence"),
        ({"confidence": 0.59}, "L15.confidence"),
        ({"confidence": 0.595}, "L15.confidence"),  # compared before rounding
        ({"relationship": "  "}, "L7.text"),
        ({"suggested_action": ""}, "L7.text"),
        ({"suggested_action": "x" * 1001}, "L7.text"),
        ({"cited_product": "OpenSSL 1.1"}, "L15.product"),
        ({"ci_id": "CI-404"}, "L15.ci"),
    ],
)
def test_rejections(overrides: dict[str, Any], rule: str) -> None:
    decision, broken, reason = check_alert(alert_args(**overrides), package(), ctx())
    assert decision is None
    assert broken == rule
    assert reason


def test_confidence_equal_to_an_odd_minimum_is_accepted_and_stored_rounded() -> None:
    decision, rule, _reason = check_alert(alert_args(confidence=0.601), package(), ctx(min_confidence=Decimal("0.601")))
    assert rule is None
    assert decision is not None
    assert decision.confidence == Decimal("0.60")


def test_minimum_confidence_follows_the_profile_or_the_explicit_setting() -> None:
    assert check_alert(alert_args(confidence=0.7), package(), ctx(min_confidence=Decimal("0.8")))[1] == "L15.confidence"
    assert mode2_min_confidence(env(profile=SensitivityProfile.named("minimal"))) == Decimal("0.8")
    assert mode2_min_confidence(env(profile=SensitivityProfile.named("broad"))) == Decimal("0.4")
    explicit = env(settings=JudgeSettings(mode2_min_confidence=Decimal("0.75")))
    assert mode2_min_confidence(explicit) == Decimal("0.75")


def test_a_refuted_relationship_is_not_proposed_again_however_it_is_phrased() -> None:
    refuted_rows = {("component", "nginx", "openssl")}

    def refuted(kind: str, text: str) -> bool:
        return any(kind == k and a in text and b in text for k, a, b in refuted_rows)

    for phrasing in ("Nginx → usa → OpenSSL del sistema operativo Ubuntu", "Nginx → depende de → la OpenSSL del SO"):
        _none, rule, _reason = check_alert(alert_args(relationship=phrasing), package(), ctx(refuted=refuted))
        assert rule == "L15.refuted"
    decision, rule, _reason = check_alert(
        alert_args(relationship_type="inferred_fork"), package(), ctx(refuted=refuted)
    )
    assert rule is None
    assert decision is not None


def test_relationship_parts() -> None:
    assert relationship_parts("A -> usa -> B", "") == ("a", "b")
    assert relationship_parts("Nginx → OpenSSL", "x") == ("nginx", "openssl")
    assert relationship_parts("depende del proveedor", "Acme") == ("acme", "depende del proveedor")


def test_empty_inventory() -> None:
    inventory = EmptyInventory()
    assert inventory.find_asset("CI-1") is None
    assert inventory.products(NGINX_ASSET) == ()


# --- session ---------------------------------------------------------------------------------------------------
def test_session_proposes_an_alert() -> None:
    read = tool_call_completion("read_element", {"element_id": "N1"}, call_id="r")
    outcome, double = run([read, propose(INFERRED)])
    assert outcome.status is ReviewStatus.APPLIED
    assert outcome.mode == "dismissals"
    assert outcome.alert is not None
    assert outcome.alert.relationship_type == "component"
    assert outcome.dismissal is None
    assert outcome.adjustment is None
    assert outcome.summary == outcome.alert.relationship
    assert outcome.versions.prompt_version == "judge-mode2-v1"
    assert [c.result for c in outcome.calls] == ["ok", "accepted"]
    double.assert_calls(2)
    first = double.requests[0].body
    assert {t["function"]["name"] for t in first["tools"]} == {"read_element", "propose_alert", "dismiss_news"}
    assert "modo 2" in first["messages"][0]["content"]
    assert "0.6" in first["messages"][0]["content"]
    view = json.loads(first["messages"][1]["content"].split("\n")[2])
    assert view["profile_summary"]["stack_summary"] == ["Nginx 1.24.0", "Ubuntu 22.04"]
    assert "Example Rides" not in first["messages"][0]["content"]  # profile data travels as data (SEG-02)


def test_session_dismisses() -> None:
    outcome, _ = run([dismiss()])
    assert outcome.status is ReviewStatus.APPLIED
    assert outcome.alert is None
    assert outcome.dismissal == "No aplica: la empresa no usa ese producto."
    assert outcome.summary == outcome.dismissal


def test_invalid_dismissals_are_errors_and_the_model_can_retry() -> None:
    outcome, _ = run([dismiss(news_id="N9"), dismiss(reason="  "), dismiss()])
    assert [c.result for c in outcome.calls] == ["error", "error", "ok"]
    assert [c.rule for c in outcome.calls[:2]] == ["L5.element", "L7.text"]
    assert outcome.dismissal is not None


def test_rejections_then_dismissal() -> None:
    outcome, _ = run([propose(alert_args(confidence=0.1)), dismiss()])
    assert outcome.calls[0].rule == "L15.confidence"
    assert outcome.dismissal is not None


def test_rejection_limit_closes_without_a_decision() -> None:
    bad, low = alert_args(ci_id="CI-404"), alert_args(confidence=0.1)
    outcome, double = run([propose(bad, "a"), propose(low, "b"), propose(bad, "c"), dismiss()])
    assert outcome.status is ReviewStatus.PARTIAL_REVIEW
    assert outcome.failure is Failure.LIMIT
    assert outcome.alert is None
    assert outcome.dismissal is None
    assert outcome.summary is None
    double.assert_calls(3)


def test_api_down_falls_back_without_a_decision() -> None:
    outcome, _ = run([])
    assert outcome.status is ReviewStatus.NO_JUDGE_REVIEW
    assert outcome.failure is Failure.TRANSPORT
    assert outcome.alert is None


def test_the_ladder_does_not_turn_a_decision_into_a_suggestion() -> None:
    outcome, _ = run([dismiss()], ladder_level=2)
    assert outcome.status is ReviewStatus.APPLIED
    off, double = run([dismiss()], ladder_level=3)
    assert off.status is ReviewStatus.NO_JUDGE_REVIEW
    double.assert_calls(0)


def test_only_dismissal_candidates() -> None:
    with pytest.raises(ValueError, match="dismissal candidates"):
        DismissalSession(double_llm_client(LlmDouble()), ReviewPackage.from_content(finding_package()), env(), ctx())


def test_a_suspicious_news_alert_needs_an_agreeing_blind_second_review() -> None:
    content = dismissal_package()
    content["news"][0]["suspicious"] = True

    def candidate(responses: list[dict[str, Any]]) -> Any:
        double = LlmDouble()
        double.add_case("case", responses)
        double.use("case")
        result = review_candidate(double_llm_client(double), package(content), env(), ctx())
        return result, double

    agreed, double = candidate([propose(INFERRED, "a"), propose({**INFERRED, "confidence": 0.65}, "b")])
    assert agreed.status is ReviewStatus.APPLIED
    assert agreed.alert is not None
    assert agreed.alert.suspicious
    assert agreed.second is not None
    assert [m["role"] for m in double.requests[1].body["messages"]] == ["system", "user"]  # blind
    disagree, _ = candidate([propose(INFERRED, "a"), dismiss()])
    assert (disagree.status, disagree.alert) == (ReviewStatus.JUDGE_DISAGREEMENT, None)
    other_type, _ = candidate(
        [propose(INFERRED, "a"), propose({**INFERRED, "relationship_type": "inferred_fork"}, "b")]
    )
    assert other_type.status is ReviewStatus.JUDGE_DISAGREEMENT
    down, _ = candidate([propose(INFERRED, "a")])
    assert (down.status, down.alert) == (ReviewStatus.NO_JUDGE_REVIEW, None)


def test_an_ordinary_candidate_needs_one_review() -> None:
    double = LlmDouble()
    double.add_case("case", [dismiss()])
    double.use("case")
    result = review_candidate(double_llm_client(double), package(), env(), ctx())
    assert result.status is ReviewStatus.APPLIED
    assert result.second is None
    assert result.dismissal is not None


def test_a_suspicious_dismissal_also_needs_an_agreeing_blind_review() -> None:
    content = dismissal_package()
    content["news"][0]["suspicious"] = True

    def candidate(responses: list[dict[str, Any]]) -> Any:
        double = LlmDouble()
        double.add_case("case", responses)
        double.use("case")
        return review_candidate(double_llm_client(double), package(content), env(), ctx())

    both = candidate([dismiss(), dismiss("Tampoco aplica.")])
    assert (both.status, both.dismissal) == (ReviewStatus.APPLIED, "No aplica: la empresa no usa ese producto.")
    split = candidate([dismiss(), propose(INFERRED)])
    assert (split.status, split.alert, split.dismissal) == (ReviewStatus.JUDGE_DISAGREEMENT, None, None)


def test_the_blind_review_must_corroborate_product_and_ticketing_installation() -> None:
    content = dismissal_package()
    content["news"][0]["suspicious"] = True
    inventory = FakeInventory({NGINX_ASSET: [(OPENSSL_SOFTWARE, "OpenSSL")]})
    double = LlmDouble()
    double.add_case(
        "case", [propose({**INFERRED, "ci_id": "CI-7"}), propose({**INFERRED, "ci_id": "CI-7", "cited_product": ""})]
    )
    double.use("case")
    result = review_candidate(double_llm_client(double), package(content), env(), ctx(inventory=inventory))
    assert result.status is ReviewStatus.JUDGE_DISAGREEMENT  # the second one never backed the ticket


def test_the_same_content_error_twice_ends_the_review() -> None:
    outcome, double = run([dismiss(news_id="N9"), dismiss(news_id="N9"), dismiss()])
    assert outcome.status is ReviewStatus.PARTIAL_REVIEW
    assert outcome.failure is Failure.LIMIT
    double.assert_calls(2)
