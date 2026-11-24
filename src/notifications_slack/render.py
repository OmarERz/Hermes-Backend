"""Block Kit messages built from contract events (SLK-04, SLK-05, SLK-07). Pure functions: no Slack calls.

* Every piece of event text is external: it is escaped (`& < >`, so `<!channel>` or `<url|label>` can never be
  injected) and truncated. Links are only plain http(s) URLs (`safe_link`).
* Block Kit limits: at most 50 blocks per message, 3000 characters per text block, 10 fields per section (2000
  characters each), 150 characters per header, 75 per button label.
* NOT-08: the standard copy of an event with highly classified assets hides their names and ids, also inside the
  free texts (justification, mitigation) where the backend may quote them; the restricted copy shows everything.
* The mitigation draft carries an "IA" label (D-017): it was drafted by a model and only validated by code.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urlparse

from notifications_api import NotificationEvent
from notifications_slack.routing import RESTRICTED, Audience, is_restricted

MAX_BLOCKS: Final[int] = 50  # Slack Block Kit limit (not an advisory lock key)
MAX_TEXT: Final = 3000
MAX_FIELD: Final = 2000
MAX_FIELDS: Final = 10
MAX_HEADER: Final = 150
MAX_BUTTON: Final = 75
MAX_CONTEXT_ELEMENTS: Final = 10
DIGEST_TOP: Final = 10  # SLK-07: the first 10 and a count of the rest
COMMENT_MAX: Final = 2000  # FeedbackInput.comment

LEVEL_LABEL: Final = {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja"}
LEVEL_EMOJI: Final = {"critical": ":red_circle:", "high": ":large_orange_circle:", "medium": ":large_yellow_circle:"}
TYPE_LABEL: Final = {
    "new_ticket": "Nuevo ticket",
    "level_up": "Subió de nivel",
    "reopened": "Reabierto",
    "partially_fixed": "Corrección parcial",
    "fixed": "Corregido",
    "threat_alert": "Alerta de amenaza",
    "inferred_alert": "Relación inferida por IA",
}
HIDDEN: Final = "[activo restringido]"

ACTION_PREFIX: Final = "hermes_feedback_"
VERDICTS: Final = ("relevant", "false_positive", "wrong_priority", "investigating", "stop_suggestions")
VERDICT_LABEL: Final = {
    "relevant": "Relevante",
    "false_positive": "Falso positivo",
    "wrong_priority": "Prioridad incorrecta",
    "investigating": "Investigando",
    "stop_suggestions": "No sugerir más",
}
PRIORITY_MODAL: Final = "hermes_wrong_priority"
_CONFIRM: Final = {
    "false_positive": "Se suprimirán los avisos nuevos de este hallazgo hasta que cambie su versión.",
    "stop_suggestions": "El sistema dejará de sugerir cambios de urgencia en este ticket.",
}
_ITOP_ID: Final = re.compile(r"^[0-9]{1,12}$")
_MAX_ASSESSMENT_ID: Final = 64


@dataclass(frozen=True)
class Message:
    text: str  # notification fallback (mrkdwn, escaped)
    blocks: list[dict[str, Any]]


@dataclass(frozen=True)
class FeedbackRef:
    """What a button carries (never a secret): the rated assessment and, if known, the iTop ticket id."""

    assessment_id: str
    ticket_itop_id: str | None

    def encode(self) -> str:
        return json.dumps({"a": self.assessment_id, "t": self.ticket_itop_id or ""}, separators=(",", ":"))

    @classmethod
    def decode(cls, value: Any) -> FeedbackRef | None:
        """The reference from a button or modal; None if it is not one of ours (the value comes from Slack)."""
        try:
            data = json.loads(value) if isinstance(value, str) and len(value) <= MAX_TEXT else None
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        assessment, ticket = data.get("a"), data.get("t")
        if not isinstance(assessment, str) or not 0 < len(assessment) <= _MAX_ASSESSMENT_ID:
            return None
        ticket = ticket if isinstance(ticket, str) and _ITOP_ID.fullmatch(ticket) else None
        return cls(assessment, ticket)


# --- text helpers ---------------------------------------------------------------------------------------------
def escape(text: Any) -> str:
    """Slack's mrkdwn escaping: `&`, `<` and `>` only (links, mentions and dates all start with `<`)."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def safe_link(url: Any, label: Any) -> str:
    """A Slack link, or just the escaped label when the URL is not a plain http(s) URL."""
    url = str(url or "")
    parsed = urlparse(url)
    unsafe = any(ch in url for ch in "<>|\"' \n\r\t")
    if parsed.scheme not in ("http", "https") or not parsed.netloc or unsafe:
        return escape(label)
    return f"<{url.replace('&', '&amp;')}|{escape(label)}>"


class _Redactor:
    """Hides the names and ids of highly classified assets in the standard copy (NOT-08)."""

    def __init__(self, event: NotificationEvent, audience: Audience) -> None:
        words: set[str] = set()
        if audience == "standard" and is_restricted(event):
            for asset in event.assets:
                if asset.confidentiality == RESTRICTED:
                    words.update(w for w in (asset.name.strip(), asset.ci_id.strip()) if w)
        # Longest first, so a name that contains another one is hidden whole.
        self._pattern = (
            re.compile("|".join(re.escape(w) for w in sorted(words, key=len, reverse=True))) if words else None
        )
        self.active = self._pattern is not None

    def __call__(self, text: str) -> str:
        return self._pattern.sub(HIDDEN, text) if self._pattern is not None else text


# --- blocks -----------------------------------------------------------------------------------------------------
def _header(text: str) -> dict[str, Any]:
    return {"type": "header", "text": {"type": "plain_text", "text": truncate(text, MAX_HEADER), "emoji": True}}


def _section(text: str) -> dict[str, Any]:
    return {"type": "section", "text": {"type": "mrkdwn", "text": truncate(text, MAX_TEXT)}}


def _fields(pairs: Iterable[tuple[str, str]]) -> dict[str, Any]:
    fields = [{"type": "mrkdwn", "text": truncate(f"*{label}*\n{value}", MAX_FIELD)} for label, value in pairs]
    return {"type": "section", "fields": fields[:MAX_FIELDS]}


def _context(parts: Sequence[str]) -> dict[str, Any]:
    elements = [{"type": "mrkdwn", "text": truncate(p, MAX_TEXT)} for p in parts if p][:MAX_CONTEXT_ELEMENTS]
    return {"type": "context", "elements": elements}


def _listing(title: str, lines: Sequence[str], max_blocks: int) -> list[dict[str, Any]]:
    """`lines` under a bold title, packed into sections of at most 3000 characters and `max_blocks` blocks; what does
    not fit is counted ("y N más")."""
    blocks: list[dict[str, Any]] = []
    current = f"*{title}*"
    shown = 0
    for raw in lines:
        line = truncate(raw, MAX_TEXT - len(title) - 8)
        if len(current) + 1 + len(line) <= MAX_TEXT - 20:
            current += "\n" + line
            shown += 1
            continue
        if len(blocks) + 1 >= max_blocks:
            break
        blocks.append(_section(current))
        current = line
        shown += 1
    rest = len(lines) - shown
    if rest > 0:
        current += f"\n_y {rest} más_"
    blocks.append(_section(current))
    return blocks


def _level(event: NotificationEvent) -> tuple[str, str]:
    level = event.score.level if event.score else None
    if level is None:
        return ":white_circle:", "Sin nivel"
    return LEVEL_EMOJI.get(level, ":white_circle:"), LEVEL_LABEL[level]


def _score_line(event: NotificationEvent) -> str:
    if event.score is None:
        return "*Sin puntuación vigente*"
    s = event.score
    line = f"*Base {s.base} · Juez {s.judge_adjustment:+d} · Final {s.final}*"
    return line + (f" (antes {s.previous})" if s.previous is not None else "")


def _ticket_link(event: NotificationEvent) -> str:
    ticket = event.ticket
    if ticket is None:
        return "—"
    if not ticket.itop_id:
        return "Pendiente de crear en iTop"
    return safe_link(ticket.url, f"Ticket {ticket.itop_id}")


def _asset_lines(event: NotificationEvent, redact: _Redactor) -> list[str]:
    lines = []
    for asset in sorted(event.assets, key=lambda a: (a.score is None, -(a.score or 0), a.ci_id)):
        hidden = redact.active and asset.confidentiality == RESTRICTED
        name = HIDDEN if hidden else f"{escape(asset.name)} ({escape(asset.ci_id)})"
        bits = [name, f"puntuación {asset.score}" if asset.score is not None else "sin puntuación"]
        bits.append("expuesto" if asset.exposed else "interno")
        bits.append(
            {"fixed": "corregido", "active": "vigente", "no_data": "sin datos", "inferred": "inferido"}[asset.status]
        )
        if asset.owner and not hidden:
            bits.append(f"dueño {escape(asset.owner)}")
        lines.append("• " + " · ".join(bits))
    return lines


def _news_lines(event: NotificationEvent) -> list[str]:
    return [
        f"• {safe_link(n.url, truncate(n.title, 200))} — {escape(n.source)}, {escape(n.date)}"
        for n in sorted(event.news, key=lambda n: n.date, reverse=True)
    ]


def feedback_buttons(event: NotificationEvent) -> dict[str, Any] | None:
    """SLK-06 buttons; none when the event has no assessment to rate."""
    if not event.assessment_id:
        return None
    itop_id = event.ticket.itop_id if event.ticket else None
    value = FeedbackRef(event.assessment_id, itop_id if itop_id and _ITOP_ID.fullmatch(itop_id) else None).encode()
    elements = []
    for verdict in VERDICTS:
        button: dict[str, Any] = {
            "type": "button",
            "action_id": ACTION_PREFIX + verdict,
            "text": {"type": "plain_text", "text": truncate(VERDICT_LABEL[verdict], MAX_BUTTON)},
            "value": value,
        }
        if verdict == "relevant":
            button["style"] = "primary"
        if verdict in _CONFIRM:
            button["confirm"] = {
                "title": {"type": "plain_text", "text": VERDICT_LABEL[verdict]},
                "text": {"type": "plain_text", "text": _CONFIRM[verdict]},
                "confirm": {"type": "plain_text", "text": "Confirmar"},
                "deny": {"type": "plain_text", "text": "Cancelar"},
            }
        elements.append(button)
    return {"type": "actions", "block_id": "hermes_feedback", "elements": elements}


def _links(event: NotificationEvent) -> dict[str, Any]:
    parts = []
    if event.ticket is not None:
        parts.append("iTop: " + _ticket_link(event))
    if event.frontend_url:
        parts.append(safe_link(event.frontend_url, "Ver en Hermes"))
    parts.append(f"Evento {escape(event.event_id)} · {escape(event.date)}")
    return _context(parts)


def _title(event: NotificationEvent, audience: Audience) -> str:
    emoji, label = _level(event)
    subject = event.vulnerability.cve if event.vulnerability else (event.alert.relevance if event.alert else "")
    lock = ":lock: Restringido · " if audience == "restricted" else ""
    return f"{lock}{emoji} {label} · {TYPE_LABEL[event.type]} · {subject}"


def fallback_text(event: NotificationEvent, audience: Audience) -> str:
    _, label = _level(event)
    bits = [label, TYPE_LABEL[event.type]]
    if event.vulnerability:
        bits += [event.vulnerability.cve, event.vulnerability.product]
    if event.score:
        bits.append(f"Final {event.score.final}")
    prefix = "Restringido · " if audience == "restricted" else ""
    return truncate(prefix + escape(" · ".join(bits)), MAX_TEXT)


def message(event: NotificationEvent, audience: Audience) -> Message:
    """The full message of one event: tickets (SLK-04) and threat alerts (SLK-05)."""
    redact = _Redactor(event, audience)
    blocks: list[dict[str, Any]] = [_header(_title(event, audience))]
    head = [_score_line(event)]
    if event.vulnerability is not None:
        v = event.vulnerability
        cvss = f"CVSS {v.cvss}" if v.cvss is not None else "CVSS sin dato"
        head.append(f"*{escape(v.cve)}* · {escape(v.product)} · {cvss}" + (" · en KEV" if v.in_kev else ""))
    if event.score is not None and event.score.driving_ci:
        head.append(f"Impulsada por: {escape(redact(event.score.driving_ci))}")
    blocks.append(_section("\n".join(head)))
    if event.alert is not None:
        a = event.alert
        relevance = (
            "Relación inferida por IA" if a.inferred or a.relevance == "inferred" else f"Relevancia {a.relevance}"
        )
        pairs = [("Relevancia", relevance)]
        pairs += [
            (label, escape(value) if value else "—")
            for label, value in (
                ("Actor", a.actor),
                ("Víctima", a.victim),
                ("Vector", a.vector),
                ("Relación", a.relationship),
            )
        ]
        blocks.append(_fields(pairs))
    if event.ticket is not None:
        t = event.ticket
        owners = ", ".join(escape(o.name) for o in t.owners) or "—"
        blocks.append(
            _fields(
                [
                    ("Custodio", escape(t.custodian)),
                    ("Dueños", owners),
                    ("CIs", f"{t.fixed_cis} de {t.total_cis} corregidos"),
                    ("Ticket", _ticket_link(event)),
                ]
            )
        )
    if event.assets:
        blocks += _listing("CIs afectados", _asset_lines(event, redact), max_blocks=3)
    if redact.active:
        blocks.append(
            _context([":lock: Hay activos ultra clasificados: el detalle completo está en el canal restringido."])
        )
    blocks.append(_section("*Justificación*\n" + escape(redact(event.justification))))
    if event.mitigation:
        title = "Qué hacer" if event.alert is not None else "Mitigación"
        blocks.append(_section(f"*{title}*\n" + escape(redact(event.mitigation))))
    if event.mitigation_draft:
        steps = "\n".join(f"{i}. {escape(redact(step))}" for i, step in enumerate(event.mitigation_draft, start=1))
        blocks.append(_section("*Pasos sugeridos* `IA`\n" + steps))
        blocks.append(_context(["Borrador redactado por IA y validado por código: revísalo antes de aplicarlo."]))
    buttons = feedback_buttons(event)
    reserved = 1 + (1 if buttons else 0)  # the links context and the buttons always fit
    if event.news:
        budget = MAX_BLOCKS - len(blocks) - reserved
        if budget > 0:
            blocks += _listing(f"Noticias ({len(event.news)})", _news_lines(event), max_blocks=budget)
    blocks = blocks[: MAX_BLOCKS - reserved]
    blocks.append(_links(event))
    if buttons:
        blocks.append(buttons)
    return Message(fallback_text(event, audience), blocks)


def follow_up(event: NotificationEvent, audience: Audience) -> Message:
    """A short reply in the ticket's thread for `partially_fixed` and `fixed` (SLK-03)."""
    redact = _Redactor(event, audience)
    ticket = event.ticket
    counts = f"{ticket.fixed_cis} de {ticket.total_cis} CIs corregidos" if ticket else ""
    emoji = ":white_check_mark:" if event.type == "fixed" else ":large_yellow_circle:"
    blocks = [_section(f"{emoji} *{TYPE_LABEL[event.type]}* · {counts}\n{_score_line(event)}")]
    if event.assets:
        blocks += _listing("CIs", _asset_lines(event, redact), max_blocks=3)
    blocks.append(_links(event))
    return Message(fallback_text(event, audience), blocks)


def digest(events: Sequence[NotificationEvent]) -> Message:
    """A channel digest (SLK-07): the first 10 by final score and a count of the rest; the detail is in its thread."""
    ranked = rank(events)
    blocks: list[dict[str, Any]] = [_header(f"Resumen · {len(ranked)} avisos")]
    for event in ranked[:DIGEST_TOP]:
        emoji, label = _level(event)
        final = f"*{event.score.final}*" if event.score else "*—*"
        bits = [f"{emoji} {final} {label}", TYPE_LABEL[event.type]]
        if event.vulnerability:
            bits += [f"*{escape(event.vulnerability.cve)}*", escape(event.vulnerability.product)]
        if event.ticket:
            bits += [escape(event.ticket.custodian), _ticket_link(event)]
        blocks.append(_section(" · ".join(bits)))
    rest = len(ranked) - DIGEST_TOP
    note = "El detalle y los botones de cada aviso están en el hilo."
    blocks.append(_context([f"_y {rest} más._ {note}" if rest > 0 else note]))
    return Message(truncate(f"Resumen: {len(ranked)} avisos de Hermes", MAX_TEXT), blocks)


def rank(events: Iterable[NotificationEvent]) -> list[NotificationEvent]:
    """Highest final score first (no score last), then oldest first."""
    return sorted(events, key=lambda e: (-(e.score.final if e.score else -1), e.date, e.event_id))


def priority_modal(ref: FeedbackRef, channel_id: str) -> dict[str, Any]:
    """SLK-06 "Prioridad incorrecta": level picker, optional score and comment."""
    levels = [
        {"text": {"type": "plain_text", "text": LEVEL_LABEL[level]}, "value": level}
        for level in ("critical", "high", "medium", "low")
    ]
    metadata = json.dumps({"r": ref.encode(), "c": channel_id}, separators=(",", ":"))
    return {
        "type": "modal",
        "callback_id": PRIORITY_MODAL,
        "private_metadata": metadata,
        "title": {"type": "plain_text", "text": "Prioridad incorrecta"},
        "submit": {"type": "plain_text", "text": "Enviar"},
        "close": {"type": "plain_text", "text": "Cancelar"},
        "blocks": [
            {
                "type": "input",
                "block_id": "level",
                "label": {"type": "plain_text", "text": "Nivel que propones"},
                "element": {"type": "static_select", "action_id": "value", "options": levels},
            },
            {
                "type": "input",
                "block_id": "score",
                "optional": True,
                "label": {"type": "plain_text", "text": "Puntuación que propones (0 a 100)"},
                "element": {
                    "type": "number_input",
                    "action_id": "value",
                    "is_decimal_allowed": False,
                    "min_value": "0",
                    "max_value": "100",
                },
            },
            {
                "type": "input",
                "block_id": "comment",
                "optional": True,
                "label": {"type": "plain_text", "text": "Comentario"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "value",
                    "multiline": True,
                    "max_length": COMMENT_MAX,
                },
            },
        ],
    }
