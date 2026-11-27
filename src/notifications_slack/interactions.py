"""Feedback buttons (SLK-06) → the backend's `FeedbackService` (NOT-06), through Bolt in Socket Mode.

* Every listener calls `ack()` first: Slack expects the acknowledgement within 3 seconds.
* The user is identified by Slack (`users.info`, scope `users:read.email`): the e-mail goes into
  `FeedbackInput(channel="slack")` and the service decides whether that person may give feedback (D-030). A button
  value carries only the assessment id and the iTop ticket id (`render.FeedbackRef`), never a secret, and is
  re-validated here because it comes back from Slack.
* "Prioridad incorrecta" opens a modal (level, optional score and comment); the others record at once.
* The answer is an ephemeral message only the user sees, with one text per rejection code; nothing echoes the input.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Final

from pydantic import ValidationError
from slack_bolt import Ack, App

from notifications_api import FeedbackInput, FeedbackRejected, FeedbackService
from notifications_slack import render
from notifications_slack.gateway import SlackError, SlackGateway

log = logging.getLogger("notifications_slack.interactions")

DIRECT_VERDICTS: Final = {render.ACTION_PREFIX + v: v for v in render.VERDICTS if v != "wrong_priority"}
DIRECT_ACTIONS: Final = re.compile("^(" + "|".join(re.escape(a) for a in DIRECT_VERDICTS) + ")$")
PRIORITY_ACTION: Final = render.ACTION_PREFIX + "wrong_priority"
LEVELS: Final = frozenset({"critical", "high", "medium", "low"})
MAX_SCORE: Final = 100
_CHANNEL: Final = re.compile(r"^[CGD][A-Z0-9]{2,31}$")

REJECTED_TEXT: Final = {
    "unauthorized_user": (
        "No pudimos registrar tu feedback: tu correo de Slack no corresponde a un analista o administrador de Hermes."
    ),
    "unknown_assessment": "No pudimos registrar tu feedback: esa evaluación ya no existe.",
    "unknown_ticket": "No pudimos registrar tu feedback: el ticket ya no corresponde a esta evaluación.",
}
NO_EMAIL_TEXT: Final = "No pudimos registrar tu feedback: Slack no comparte el correo de tu usuario."
INVALID_TEXT: Final = "No pudimos registrar tu feedback: los datos no son válidos."
FAILED_TEXT: Final = "No pudimos registrar tu feedback por un error temporal. Inténtalo de nuevo en un momento."
MODAL_FAILED_TEXT: Final = "No pudimos abrir el formulario. Inténtalo de nuevo."


@dataclass(frozen=True)
class Proposal:
    """What the "Prioridad incorrecta" modal adds: the proposed level and, optionally, a score and a comment."""

    level: str
    score: int | None = None
    comment: str | None = None


def _user(body: dict[str, Any]) -> str | None:
    user = body.get("user")
    value = user.get("id") if isinstance(user, dict) else None
    return value if isinstance(value, str) else None


def _channel(body: dict[str, Any]) -> str | None:
    for holder, key in ((body.get("channel"), "id"), (body.get("container"), "channel_id")):
        value = holder.get(key) if isinstance(holder, dict) else None
        if isinstance(value, str) and _CHANNEL.fullmatch(value):
            return value
    return None


def _action(body: dict[str, Any]) -> dict[str, Any]:
    actions = body.get("actions")
    first = actions[0] if isinstance(actions, list) and actions else None
    return first if isinstance(first, dict) else {}


def _input(values: dict[str, Any], block: str) -> dict[str, Any]:
    element = (values.get(block) or {}).get("value")
    return element if isinstance(element, dict) else {}


@dataclass
class FeedbackHandlers:
    service: FeedbackService
    gateway: SlackGateway

    def register(self, app: App) -> None:
        app.action(DIRECT_ACTIONS)(self.on_button)
        app.action(PRIORITY_ACTION)(self.on_wrong_priority)
        app.view(render.PRIORITY_MODAL)(self.on_priority_submit)

    # --- listeners ------------------------------------------------------------------------------------------
    def on_button(self, ack: Ack, body: dict[str, Any]) -> None:
        ack()
        action = _action(body)
        verdict = DIRECT_VERDICTS.get(str(action.get("action_id")))
        ref = render.FeedbackRef.decode(action.get("value"))
        user = _user(body)
        if verdict is None or ref is None or user is None:
            log.warning("feedback button ignored: not one of ours")
            return
        self._record(user, _channel(body), ref, verdict)

    def on_wrong_priority(self, ack: Ack, body: dict[str, Any]) -> None:
        ack()
        ref = render.FeedbackRef.decode(_action(body).get("value"))
        user, channel, trigger = _user(body), _channel(body), body.get("trigger_id")
        if ref is None or user is None or channel is None or not isinstance(trigger, str):
            log.warning("priority button ignored: not one of ours")
            return
        try:
            self.gateway.open_view(trigger, render.priority_modal(ref, channel))
        except SlackError as error:
            log.warning("could not open the priority modal: slack %s", error.code)
            self._reply(channel, user, MODAL_FAILED_TEXT)

    def on_priority_submit(self, ack: Ack, body: dict[str, Any], view: dict[str, Any]) -> None:
        values = (view.get("state") or {}).get("values") or {}
        level = (_input(values, "level").get("selected_option") or {}).get("value")
        raw_score = _input(values, "score").get("value")
        comment = _input(values, "comment").get("value")
        if level not in LEVELS:
            ack(response_action="errors", errors={"level": "Elige un nivel."})
            return
        score: int | None = None
        if raw_score not in (None, ""):
            if (
                not (isinstance(raw_score, str) and raw_score.isascii() and raw_score.isdigit())
                or int(raw_score) > MAX_SCORE
            ):
                ack(response_action="errors", errors={"score": "Escribe un número entero de 0 a 100."})
                return
            score = int(raw_score)
        ack()
        ref, channel = self._metadata(view.get("private_metadata"))
        user = _user(body)
        if ref is None or user is None:
            log.warning("priority modal ignored: not one of ours")
            return
        text = comment.strip() if isinstance(comment, str) and comment.strip() else None
        self._record(user, channel, ref, "wrong_priority", Proposal(level, score, text))

    # --- steps ----------------------------------------------------------------------------------------------
    @staticmethod
    def _metadata(raw: Any) -> tuple[render.FeedbackRef | None, str | None]:
        try:
            data = json.loads(raw) if isinstance(raw, str) else None
        except ValueError:
            return None, None
        if not isinstance(data, dict):
            return None, None
        channel = data.get("c")
        return render.FeedbackRef.decode(data.get("r")), channel if isinstance(channel, str) and _CHANNEL.fullmatch(
            channel
        ) else None

    def _record(
        self,
        user: str,
        channel: str | None,
        ref: render.FeedbackRef,
        verdict: str,
        proposal: Proposal | None = None,
    ) -> None:
        try:
            email = self.gateway.user_email(user)
        except SlackError as error:
            log.warning("feedback: users.info failed (slack %s)", error.code)
            self._reply(channel, user, FAILED_TEXT)
            return
        if email is None:
            self._reply(channel, user, NO_EMAIL_TEXT)
            return
        try:
            feedback = FeedbackInput.model_validate(
                {
                    "assessment_id": ref.assessment_id,
                    "user_email": email,
                    "channel": "slack",
                    "verdict": verdict,
                    "proposed_level": proposal.level if proposal else None,
                    "proposed_score": proposal.score if proposal else None,
                    "comment": proposal.comment if proposal else None,
                    "ticket_itop_id": ref.ticket_itop_id,
                }
            )
        except ValidationError:
            self._reply(channel, user, INVALID_TEXT)
            return
        try:
            result = self.service.record(feedback)
        except FeedbackRejected as rejected:
            # docs/14 §10.4: a rejected feedback is a security event; the code only, never the e-mail or the input.
            log.warning("slack feedback rejected: %s", rejected.code)
            self._reply(channel, user, REJECTED_TEXT.get(rejected.code, INVALID_TEXT))
            return
        except Exception as exc:  # noqa: BLE001 - any failure of the service: tell the user, keep the listener alive
            log.error("slack feedback failed: %s", type(exc).__name__)  # noqa: TRY400 - no traceback (SEG-21)
            self._reply(channel, user, FAILED_TEXT)
            return
        label = render.VERDICT_LABEL[verdict]
        extra = " Reemplaza tu feedback anterior sobre esta evaluación." if result.replaced_previous else ""
        self._reply(channel, user, f"Gracias: registramos tu feedback «{label}».{extra}")

    def _reply(self, channel: str | None, user: str, text: str) -> None:
        if channel is None:
            return
        try:
            self.gateway.ephemeral(channel, user, text)
        except SlackError as error:
            log.warning("could not answer the user: slack %s", error.code)
