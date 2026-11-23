"""Request body size limit (docs/14 §10.4 "límite de tamaño de petición", ASVS V4).

Every API body is a small JSON document (configuration, feedback, a STIX scope, an iTop doorbell), so anything
above `MAX_BODY_BYTES` is refused with 413 before a route reads it: by its Content-Length when declared, or while
streaming when the body is chunked.
"""

from __future__ import annotations

import json

from starlette.types import ASGIApp, Message, Receive, Scope, Send

MAX_BODY_BYTES = 1_048_576  # 1 MiB
_BODY = json.dumps(
    {
        "error": {
            "code": "payload_too_large",
            "message": "La petición es demasiado grande.",
            "details": [],
        }
    }
).encode()


class _TooLargeError(Exception):
    """Raised inside `receive` when a chunked body passes the limit."""


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope.get("headers", [])).get(b"content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > self.max_bytes):
            await _reject(send)
            return
        seen = 0
        started = False

        async def counting_receive() -> Message:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    raise _TooLargeError
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            started = started or message["type"] == "http.response.start"
            await send(message)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _TooLargeError:
            if not started:
                await _reject(send)


async def _reject(send: Send) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(_BODY)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": _BODY})
