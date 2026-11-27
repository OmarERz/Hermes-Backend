"""A fake slack_sdk `WebClient`: records every Web API call and answers from a script. Never opens a socket (CAL-03).

It subclasses the real client and replaces only `api_call`, so the real methods (`chat_postMessage`, `users_info`,
`views_open` ...) build their arguments as in production and the real `SlackResponse.validate()` raises the real
`SlackApiError` for scripted failures (status, `error` code and `Retry-After` header).
"""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass
from typing import Any

from slack_sdk import WebClient
from slack_sdk.web import SlackResponse

BOT_TOKEN = "xoxb-test-not-a-real-token"  # noqa: S105 - fake value for tests


@dataclass(frozen=True)
class Call:
    method: str
    args: dict[str, Any]


@dataclass(frozen=True)
class Scripted:
    status: int
    data: dict[str, Any]
    headers: dict[str, str]


class FakeWebClient(WebClient):
    def __init__(self, emails: dict[str, str] | None = None) -> None:
        super().__init__(token=BOT_TOKEN, base_url="https://slack.invalid/api/")
        self.calls: list[Call] = []
        self.emails = dict(emails or {})
        self._script: dict[str, list[Scripted]] = {}
        self._ts = itertools.count(1)
        self._lock = threading.Lock()

    # --- scripting ----------------------------------------------------------------------------------------------
    def fail(
        self, method: str, error: str, *, status: int = 200, retry_after: float | None = None, times: int = 1
    ) -> None:
        """The next `times` calls of `method` fail with Slack's `error` code (status 429 for rate limits)."""
        headers = {"Retry-After": str(retry_after)} if retry_after is not None else {}
        self._script.setdefault(method, []).extend([Scripted(status, {"ok": False, "error": error}, headers)] * times)

    def posts(self, channel: str | None = None) -> list[dict[str, Any]]:
        return [c.args for c in self.calls if c.method == "chat.postMessage" and channel in (None, c.args["channel"])]

    def calls_of(self, method: str) -> list[dict[str, Any]]:
        return [c.args for c in self.calls if c.method == method]

    # --- the one network entry point of WebClient, replaced ---------------------------------------------------
    def api_call(  # type: ignore[override]  # noqa: PLR0913 - the signature of WebClient.api_call
        self,
        api_method: str,
        *,
        http_verb: str = "POST",
        files: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
        auth: dict[str, Any] | None = None,
    ) -> SlackResponse:
        args = {**(params or {}), **(data or {}), **(json or {})}
        with self._lock:
            self.calls.append(Call(api_method, args))
            queue = self._script.get(api_method)
            scripted = queue.pop(0) if queue else Scripted(200, self._answer(api_method, args), {})
        response = SlackResponse(
            client=self,
            http_verb=http_verb,
            api_url=self.base_url + api_method,
            req_args={},
            data=scripted.data,
            headers=scripted.headers,
            status_code=scripted.status,
        )
        return response.validate()

    def _answer(self, method: str, args: dict[str, Any]) -> dict[str, Any]:
        if method == "chat.postMessage":
            channel = str(args["channel"])
            return {"ok": True, "channel": channel, "ts": f"1700000000.{next(self._ts):06d}"}
        if method == "users.info":
            user = str(args.get("user"))
            profile = {"email": self.emails[user]} if user in self.emails else {}
            return {"ok": True, "user": {"id": user, "deleted": False, "is_bot": False, "profile": profile}}
        if method == "auth.test":
            return {"ok": True, "user_id": "UBOT00001", "bot_id": "BBOT00001", "team_id": "T00000001", "team": "test"}
        return {"ok": True}
