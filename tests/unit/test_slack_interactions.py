"""Buttons → FeedbackService (NOT-06, SLK-06, F11 acceptance "un clic termina en FeedbackService"), through Bolt."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from concurrent.futures import Executor, Future
from dataclasses import dataclass, field
from typing import Any

import pytest
from pydantic import ValidationError
from slack_bolt.request import BoltRequest

from doubles.slack_web import FakeWebClient
from notifications_api import FeedbackInput, FeedbackRejected, FeedbackResult
from notifications_slack import render
from notifications_slack.interactions import FAILED_TEXT, INVALID_TEXT, NO_EMAIL_TEXT, REJECTED_TEXT
from notifications_slack.module import build_module
from notifications_slack.settings import SlackSettings
from notifications_slack.store import InMemorySlackStore

pytestmark = pytest.mark.unit
USER, CHANNEL = "U0ANALYST1", "C0INFRA001"
REF = render.FeedbackRef("8b0f6f1e-3c1a-4b8e-9d55-0d6c1f2b7a10", "123")


class Immediate(Executor):
    """Runs listeners in the calling thread, so a test sees their effects when dispatch returns."""

    def submit(self, fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Future[Any]:
        future: Future[Any] = Future()
        try:
            future.set_result(fn(*args, **kwargs))
        except BaseException as exc:  # noqa: BLE001 - handed to the future, like a thread pool
            future.set_exception(exc)
        return future


@dataclass
class FakeFeedback:
    received: list[FeedbackInput] = field(default_factory=list)
    error: Exception | None = None
    replaced: bool = False

    def record(self, feedback: FeedbackInput) -> FeedbackResult:
        self.received.append(feedback)
        if self.error is not None:
            raise self.error
        return FeedbackResult(feedback_id=str(uuid.uuid4()), replaced_previous=self.replaced)


class Setup:
    def __init__(self, emails: dict[str, str] | None = None) -> None:
        self.client = FakeWebClient(emails={USER: "ana@example.test"} if emails is None else emails)
        self.feedback = FakeFeedback()
        settings = SlackSettings(_env_file=None, _secrets_dir=None, default_channel="C0DEFAULT1")  # type: ignore[call-arg]
        module = build_module(
            settings, self.feedback, InMemorySlackStore(), client=self.client, listener_executor=Immediate()
        )
        self.app = module.app

    def dispatch(self, body: dict[str, Any]) -> Any:
        return self.app.dispatch(BoltRequest(body=body, mode="socket_mode"))

    def click(self, verdict: str, value: str | None = None) -> Any:
        return self.dispatch(
            {
                "type": "block_actions",
                "user": {"id": USER, "team_id": "T00000001"},
                "team": {"id": "T00000001"},
                "api_app_id": "A00000001",
                "trigger_id": "1111.2222.abcd",
                "channel": {"id": CHANNEL},
                "container": {"type": "message", "channel_id": CHANNEL, "message_ts": "1700000000.000001"},
                "actions": [
                    {
                        "type": "button",
                        "action_id": render.ACTION_PREFIX + verdict,
                        "block_id": "hermes_feedback",
                        "value": REF.encode() if value is None else value,
                        "action_ts": "1700000001.000001",
                    }
                ],
            }
        )

    def submit(self, level: str | None, score: str | None = None, comment: str | None = None) -> Any:
        view = render.priority_modal(REF, CHANNEL)
        values = {
            "level": {"value": {"type": "static_select", "selected_option": {"value": level} if level else None}},
            "score": {"value": {"type": "number_input", "value": score}},
            "comment": {"value": {"type": "plain_text_input", "value": comment}},
        }
        return self.dispatch(
            {
                "type": "view_submission",
                "user": {"id": USER, "team_id": "T00000001"},
                "team": {"id": "T00000001"},
                "api_app_id": "A00000001",
                "view": {**view, "id": "V00000001", "state": {"values": values}},
            }
        )

    def ephemerals(self) -> list[str]:
        return [c["text"] for c in self.client.calls_of("chat.postEphemeral")]


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """CAL-03: a real HTTP request to Slack (e.g. from a client Bolt builds itself) fails the test."""

    def refuse(*_: object, **__: object) -> None:
        raise AssertionError("a test tried to reach the Slack API")

    monkeypatch.setattr("slack_sdk.web.base_client.BaseClient._perform_urllib_http_request", refuse)


@pytest.fixture
def s() -> Setup:
    return Setup()


def test_the_token_is_checked_once_through_the_given_client(s: Setup) -> None:
    s.click("relevant")
    s.click("investigating")
    assert len(s.client.calls_of("auth.test")) == 1  # at start, never again per request


@pytest.mark.parametrize("verdict", ["relevant", "false_positive", "investigating", "stop_suggestions"])
def test_a_click_ends_in_feedback_service(s: Setup, verdict: str) -> None:
    response = s.click(verdict)
    assert response.status == 200  # acknowledged
    (feedback,) = s.feedback.received
    assert feedback == FeedbackInput(
        assessment_id=REF.assessment_id,
        user_email="ana@example.test",
        channel="slack",
        verdict=verdict,  # type: ignore[arg-type]
        proposed_level=None,
        proposed_score=None,
        comment=None,
        ticket_itop_id="123",
    )
    assert s.ephemerals() == [f"Gracias: registramos tu feedback «{render.VERDICT_LABEL[verdict]}»."]


def test_a_replaced_feedback_is_mentioned(s: Setup) -> None:
    s.feedback.replaced = True
    s.click("relevant")
    assert "Reemplaza tu feedback anterior" in s.ephemerals()[0]


@pytest.mark.parametrize("code", sorted(REJECTED_TEXT))
def test_each_rejection_code_has_its_own_answer(s: Setup, code: str, caplog: pytest.LogCaptureFixture) -> None:
    s.feedback.error = FeedbackRejected(code)  # type: ignore[arg-type]
    s.click("relevant")
    assert s.ephemerals() == [REJECTED_TEXT[code]]
    assert "ana@example.test" not in caplog.text  # the e-mail never reaches the log


def test_a_user_without_a_visible_email_is_told_and_nothing_is_recorded() -> None:
    s = Setup(emails={})
    s.click("relevant")
    assert s.feedback.received == []
    assert s.ephemerals() == [NO_EMAIL_TEXT]


def test_a_service_failure_is_answered_and_the_listener_survives(s: Setup) -> None:
    s.feedback.error = RuntimeError("database down")
    s.click("relevant")
    assert s.ephemerals() == [FAILED_TEXT]


def test_a_users_info_failure_is_answered(s: Setup) -> None:
    s.client.fail("users.info", "ratelimited", status=429)
    s.click("relevant")
    assert s.feedback.received == []
    assert s.ephemerals() == [FAILED_TEXT]


def test_tampered_values_are_ignored(s: Setup) -> None:
    s.click("relevant", value='{"a": ""}')
    s.click("wrong_priority", value="nope")
    assert s.feedback.received == []
    assert s.client.calls_of("views.open") == []


def test_wrong_priority_opens_the_modal_then_records_level_score_and_comment(s: Setup) -> None:
    s.click("wrong_priority")
    (opened,) = s.client.calls_of("views.open")
    assert opened["trigger_id"] == "1111.2222.abcd"
    assert opened["view"]["callback_id"] == render.PRIORITY_MODAL
    assert s.feedback.received == []
    response = s.submit("medium", "55", "  El activo no está expuesto  ")
    assert response.status == 200
    (feedback,) = s.feedback.received
    assert (feedback.verdict, feedback.proposed_level, feedback.proposed_score) == ("wrong_priority", "medium", 55)
    assert feedback.comment == "El activo no está expuesto"
    assert feedback.ticket_itop_id == "123"
    assert s.ephemerals() == ["Gracias: registramos tu feedback «Prioridad incorrecta»."]


@pytest.mark.parametrize(
    ("level", "score", "block"),
    [(None, None, "level"), ("high", "101", "score"), ("high", "-1", "score"), ("high", "٣", "score")],
)
def test_invalid_modal_input_is_refused_in_the_modal(
    s: Setup, level: str | None, score: str | None, block: str
) -> None:
    body = json.loads(s.submit(level, score).body)
    assert body["response_action"] == "errors"
    assert list(body["errors"]) == [block]
    assert s.feedback.received == []


def test_an_empty_modal_score_and_comment_are_absent(s: Setup) -> None:
    s.submit("low", "", "   ")
    (feedback,) = s.feedback.received
    assert (feedback.proposed_score, feedback.comment) == (None, None)


def test_a_modal_that_cannot_open_is_answered(s: Setup) -> None:
    s.client.fail("views.open", "expired_trigger_id")
    s.click("wrong_priority")
    assert s.ephemerals() == ["No pudimos abrir el formulario. Inténtalo de nuevo."]


def test_a_failed_ephemeral_answer_is_only_logged(s: Setup) -> None:
    s.client.fail("chat.postEphemeral", "user_not_in_channel")
    s.click("relevant")
    assert len(s.feedback.received) == 1


def test_invalid_text_is_used_for_input_the_contract_refuses(monkeypatch: pytest.MonkeyPatch, s: Setup) -> None:
    def refuse(*_: object, **__: object) -> None:
        raise ValidationError.from_exception_data("FeedbackInput", [])

    monkeypatch.setattr(FeedbackInput, "model_validate", refuse)
    s.click("relevant")
    assert s.ephemerals() == [INVALID_TEXT]
