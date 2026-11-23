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
        state = {"seen": 0, "started": False, "rejected": False}

        async def counting_receive() -> Message:
            if state["rejected"]:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                state["seen"] += len(message.get("body", b""))
                if state["seen"] > self.max_bytes:
                    # Answer 413 ourselves and tell the app the client is gone: FastAPI would turn an exception
                    # raised while it reads the body into a 400.
                    state["rejected"] = True
                    if not state["started"]:
                        await _reject(send)
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: Message) -> None:
            if state["rejected"]:
                return  # the 413 already went out; whatever the app answers afterwards is dropped
            state["started"] = state["started"] or message["type"] == "http.response.start"
            await send(message)

        await self.app(scope, counting_receive, guarded_send)


async def _reject(send: Send) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(_BODY)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": _BODY})
