"""Request context for the logs and an `X-Request-ID` on every answer (F12.3, ASVS 5.0 V16.2.1 and V16.3).

Every log line written while a request is served (the access line of Uvicorn, a rejected token, a denied role, an
unhandled error) carries the request id, the client address, the method and the path without its query string; the
authentication dependency adds the verified user (`core.logging.bind_request`). So a security event in the logs
says who, from where and on which request, and a person can quote the `X-Request-ID` of an answer to find it.

The id is always generated here, never taken from the request: a client (or a proxy that forwards the client's
header) could otherwise give two unrelated requests the same id, or one that the log masking would rewrite. A reverse
proxy correlates its own log through the answer's header (nginx: `$upstream_http_x_request_id`). The client address
is the one Uvicorn resolved: behind a proxy, list it in `FORWARDED_ALLOW_IPS` so `X-Forwarded-For` counts.
"""

from __future__ import annotations

import uuid
from typing import Final

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from api.errors import internal_error_response
from api.security_headers import SecurityHeadersMiddleware
from core.logging import request_context

HEADER: Final = b"x-request-id"


class RequestContextMiddleware:
    """Pure ASGI middleware (keeps streaming answers such as the SSE progress streaming)."""

    def __init__(self, app: ASGIApp, *, hsts_include_subdomains: bool = False) -> None:
        self.app = app
        self.hsts_include_subdomains = hsts_include_subdomains

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = uuid.uuid4().hex
        client = scope.get("client")
        fields = {
            "request_id": request_id,
            "client": str(client[0]) if client else "-",
            "method": str(scope.get("method", "")),
            "path": str(scope.get("path", "")),
        }

        started = False

        async def send_with_id(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = [(n, v) for n, v in message.get("headers", []) if n.lower() != HEADER]
                message["headers"] = [*headers, (HEADER, request_id.encode("ascii"))]
            await send(message)

        with request_context(**fields):
            try:
                await self.app(scope, receive, send_with_id)
            except Exception:
                if not started:
                    # A middleware outside UnhandledErrorMiddleware failed before answering: the 500 envelope goes out
                    # here, with the security headers and the X-Request-ID that Starlette's last resort would lack.
                    await SecurityHeadersMiddleware(
                        internal_error_response(), include_subdomains=self.hsts_include_subdomains
                    )(scope, receive, send_with_id)
                # Re-raised, never swallowed: a broken stream stays a broken connection for the client (ARQ-05), and
                # the server's own log of it ("Exception in ASGI application") still carries this request's context.
                raise
