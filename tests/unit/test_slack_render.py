"""Block Kit rendering (SLK-04, SLK-05, SLK-07): content, escaping, limits and NOT-08 redaction."""

from __future__ import annotations

import json
from typing import Any

import pytest

from doubles.slack_events import EVENT_TYPES, event, raw
from notifications_slack import render

pytestmark = pytest.mark.unit


def texts(message: render.Message) -> list[str]:
    """Every text Slack would render: section texts and fields, headers, contexts and the fallback."""
    found = [message.text]
    for block in message.blocks:
        if "text" in block and isinstance(block["text"], dict):
            found.append(block["text"]["text"])
        found += [f["text"] for f in block.get("fields", [])]
        found += [e["text"] for e in block.get("elements", []) if e.get("type") == "mrkdwn"]
    return found


def all_text(message: render.Message) -> str:
    return "\n".join(texts(message))


def check_limits(message: render.Message) -> None:
    assert len(message.blocks) <= render.MAX_BLOCKS
    for block in message.blocks:
        if block["type"] == "header":
            assert len(block["text"]["text"]) <= render.MAX_HEADER
        elif "text" in block:
            assert len(block["text"]["text"]) <= render.MAX_TEXT
        assert len(block.get("fields", [])) <= render.MAX_FIELDS
        assert all(len(f["text"]) <= render.MAX_FIELD for f in block.get("fields", []))
        assert len(block.get("elements", [])) <= render.MAX_CONTEXT_ELEMENTS


@pytest.mark.parametrize("name", EVENT_TYPES)
def test_every_sample_event_renders_within_the_limits(name: str) -> None:
    message = render.message(event(name), "standard")
    check_limits(message)
    assert render.TYPE_LABEL[event(name).type] in message.blocks[0]["text"]["text"]


def test_a_ticket_shows_scores_cve_people_link_justification_mitigation_and_news() -> None:
    body = all_text(render.message(event("new_ticket"), "standard"))
    assert "*Base 82 · Juez +8 · Final 90*" in body
    assert "CVE-2099-0001" in body
    assert "ExampleServer 1.2" in body
    assert "Infrastructure Team" in body
    assert "Alex Example, Sam Sample" in body
    assert "srv-example-01 (CI-0001)" in body
    assert (
        "<https://itop.example.test/pages/UI.php?operation=details&amp;class=UserRequest&amp;id=123|Ticket R-000123>"
        in body
    )
    assert "Vulnerabilidad explotada activamente" in body
    assert "Actualizar ExampleServer" in body
    assert "*Pasos sugeridos* `IA`" in body  # D-017: the AI draft is labelled
    assert (
        "<https://news.example.test/story-1|Synthetic headline about CVE-2099-0001> — Example News, 2026-01-14" in body
    )
    assert "<https://hermes.example.test/recommendations/asm-0001|Ver en Hermes>" in body


def test_a_ticket_not_yet_created_in_itop_says_so() -> None:
    body = all_text(render.message(event("new_ticket", ticket__itop_id="", ticket__url=""), "standard"))
    assert "Pendiente de crear en iTop" in body


def test_external_text_is_escaped_and_cannot_mention_or_link() -> None:
    news = [
        {
            "title": "<!channel> & <https://evil.test|click>",
            "url": "javascript:alert(1)",
            "source": "S<>",
            "date": "2026-01-01",
        }
    ]
    data = {"justification": "<!here> a & b", "news": news, "ticket__custodian": "<@U123>"}
    body = all_text(render.message(event("new_ticket", **data), "standard"))
    assert "<!channel>" not in body
    assert "<!here>" not in body
    assert "<@U123>" not in body
    assert "&lt;!channel&gt; &amp; &lt;https://evil.test|click&gt;" in body
    assert "javascript:" not in body


@pytest.mark.parametrize(
    "url", ["javascript:alert(1)", "https://x.test/a|b", "https://x.test/a b", "ftp://x.test", "https://", ""]
)
def test_safe_link_only_links_plain_http_urls(url: str) -> None:
    assert render.safe_link(url, "<label>") == "&lt;label&gt;"


def test_many_news_respect_the_block_limit_and_are_counted() -> None:
    news = [
        {
            "title": f"Headline {i} " + "x" * 180,
            "url": f"https://news.test/{i}",
            "source": "Src",
            "date": f"2026-01-{i % 28 + 1:02d}",
        }
        for i in range(1000)
    ]
    message = render.message(event("new_ticket", news=news), "standard")
    check_limits(message)
    body = all_text(message)
    assert "Noticias (1000)" in body
    assert "más_" in body  # what does not fit is counted
    assert message.blocks[-1]["type"] == "actions"  # the buttons always fit


def test_very_long_texts_are_truncated() -> None:
    message = render.message(event("new_ticket", justification="j" * 10_000, mitigation="m" * 10_000), "standard")
    check_limits(message)


def restricted_event(**changes: Any) -> Any:
    assets = raw("new_ticket")["assets"]
    assets[0]["confidentiality"] = "highly_classified"
    justification = "Puntuación 90 impulsada por srv-example-01 (CI-0001)."
    return event("new_ticket", assets=assets, justification=justification, **changes)


def test_the_standard_copy_hides_highly_classified_assets_everywhere() -> None:
    body = all_text(render.message(restricted_event(), "standard"))
    assert "srv-example-01" not in body
    assert "CI-0001" not in body  # also the driving CI and inside the justification
    assert render.HIDDEN in body
    assert "canal restringido, si está configurado" in body  # no promise of a copy that may not exist
    assert "srv-example-02" in body  # the other assets stay visible
    assert "Alex Example" not in body  # the restricted asset's owner, also out of the ticket's owners
    assert "Sam Sample" in body


def test_the_restricted_copy_shows_everything() -> None:
    body = all_text(render.message(restricted_event(), "restricted"))
    assert "srv-example-01 (CI-0001)" in body
    assert "Alex Example" in body
    assert body.startswith("Restringido")


def test_alert_texts_hide_highly_classified_assets_too() -> None:
    """Mode 2 writes the relationship and may name the CI it cites (NOT-08)."""
    assets = raw("inferred_alert")["assets"]
    assets[0]["confidentiality"] = "highly_classified"
    text = "La nota menciona a SRV-EXAMPLE-01 (CI-0001) como objetivo."
    alert = raw("inferred_alert")["alert"] | {"relationship": text, "victim": "srv-example-01"}
    standard = all_text(render.message(event("inferred_alert", assets=assets, alert=alert), "standard"))
    assert "srv-example-01" not in standard.lower()
    assert "CI-0001" not in standard
    assert f"La nota menciona a {render.HIDDEN} ({render.HIDDEN}) como objetivo." in standard
    restricted = all_text(render.message(event("inferred_alert", assets=assets, alert=alert), "restricted"))
    assert text in restricted


def test_buttons_carry_only_the_assessment_and_the_numeric_itop_id() -> None:
    buttons = render.feedback_buttons(event("new_ticket", ticket__itop_id="123"))
    assert buttons is not None
    ids = [b["action_id"] for b in buttons["elements"]]
    assert ids == [render.ACTION_PREFIX + v for v in render.VERDICTS]
    labels = [b["text"]["text"] for b in buttons["elements"]]
    assert labels == ["Relevante", "Falso positivo", "Prioridad incorrecta", "Investigando", "No sugerir más"]
    ref = render.FeedbackRef.decode(buttons["elements"][0]["value"])
    assert ref == render.FeedbackRef("asm-0001", "123")
    confirms = [b["action_id"] for b in buttons["elements"] if "confirm" in b]
    assert confirms == [render.ACTION_PREFIX + "false_positive", render.ACTION_PREFIX + "stop_suggestions"]
    non_numeric = render.feedback_buttons(event("new_ticket"))  # the sample's id is "R-000123"
    assert non_numeric is not None
    assert render.FeedbackRef.decode(non_numeric["elements"][0]["value"]) == render.FeedbackRef("asm-0001", None)


def test_no_buttons_without_an_assessment() -> None:
    assert render.feedback_buttons(event("threat_alert")) is None
    assert render.message(event("threat_alert"), "standard").blocks[-1]["type"] == "context"


@pytest.mark.parametrize(
    "value",
    [None, 5, "not json", "[1]", '{"a": ""}', '{"a": 5}', json.dumps({"a": "x" * 65}), "{" * 4000],
)
def test_tampered_button_values_are_refused(value: object) -> None:
    assert render.FeedbackRef.decode(value) is None


def test_a_tampered_ticket_id_is_dropped() -> None:
    assert render.FeedbackRef.decode('{"a": "asm-1", "t": "1 OR 1=1"}') == render.FeedbackRef("asm-1", None)


def test_alerts_show_relevance_actor_victim_vector() -> None:
    body = all_text(render.message(event("threat_alert"), "standard"))
    assert "Relevancia R2" in body
    assert "Synthetic Actor" in body
    assert "Retail sector" in body
    assert "Phishing" in body
    inferred = all_text(render.message(event("inferred_alert"), "standard"))
    assert "Relación inferida por IA" in inferred


def test_follow_ups_are_short_thread_replies() -> None:
    message = render.follow_up(event("partially_fixed"), "standard")
    check_limits(message)
    body = all_text(message)
    assert "Corrección parcial" in body
    assert "de 2 CIs corregidos" in body
    assert ":white_check_mark: *Corregido*" in all_text(render.follow_up(event("fixed"), "standard"))


def test_a_digest_shows_the_first_ten_by_score_and_counts_the_rest() -> None:
    events = [event("new_ticket", event_id=f"e{i}", score__final=i * 5) for i in range(13)]
    message = render.digest(events)
    check_limits(message)
    lines = [b["text"]["text"] for b in message.blocks if b["type"] == "section"]
    assert len(lines) == render.DIGEST_TOP
    assert lines[0].startswith(":red_circle: *60*")  # highest final first
    assert "_y 3 más._" in all_text(message)
    assert "Resumen · 13 avisos" in message.blocks[0]["text"]["text"]


def test_the_priority_modal_round_trips_its_reference() -> None:
    view = render.priority_modal(render.FeedbackRef("asm-1", "42"), "C0TEAM0001")
    assert view["callback_id"] == render.PRIORITY_MODAL
    assert len(view["title"]["text"]) <= 24  # Slack's limit for modal titles
    metadata = json.loads(view["private_metadata"])
    assert render.FeedbackRef.decode(metadata["r"]) == render.FeedbackRef("asm-1", "42")
    assert metadata["c"] == "C0TEAM0001"
    assert [b["block_id"] for b in view["blocks"]] == ["level", "score", "comment"]


def test_rank_puts_events_without_score_last() -> None:
    scored = event("new_ticket", event_id="a")
    unscored = event("fixed", event_id="b", score=None)
    assert [e.event_id for e in render.rank([unscored, scored])] == ["a", "b"]
    assert "Sin puntuación vigente" in all_text(render.follow_up(unscored, "standard"))


def test_numeric_itop_keys_never_garble_the_text() -> None:
    """Real inventory ids are iTop object keys ('7', '12'): only whole names are hidden, never digits in scores."""
    assets = raw("new_ticket")["assets"]
    assets[0] |= {"confidentiality": "highly_classified", "ci_id": "7", "name": "srv-db"}
    text = "Puntuación 87 impulsada por SRV-DB: base 74, ajuste +7. Ver srv-db2 y srv-db.corp; actualizar srv-db."
    body = all_text(render.message(event("new_ticket", assets=assets, justification=text), "standard"))
    assert "Puntuación 87 impulsada por [activo restringido]: base 74, ajuste +7." in body  # case-insensitive
    assert "srv-db2" in body  # another asset's name is not cut
    assert "srv-db.corp" in body
    assert "actualizar [activo restringido]." in body  # the end of a sentence still hides it
