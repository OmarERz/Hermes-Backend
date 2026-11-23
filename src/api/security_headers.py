"""Security response headers for every API answer (docs/14 §10.4, ASVS V3/V13; OWASP ZAP 10021 and 90004).

The API serves JSON only, so the strictest policy fits: no sniffing, no framing, no referrer, no caching of
authenticated answers and resources readable only from the same origin. The interactive docs (enabled only in
development, `API_DOCS_ENABLED`) load the Swagger UI from a CDN, so they keep a CSP that allows it.
"""

from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

DOCS_PATH = "/api/docs"
_API_CSP = "default-src 'none'; frame-ancestors 'none'"
_DOCS_CSP = (
    "default-src 'none'; frame-ancestors 'none'; img-src 'self' data: https://fastapi.tiangolo.com; "
    "style-src 'self' https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "connect-src 'self'"
)
_COMMON: tuple[tuple[bytes, bytes], ...] = (
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cache-control", b"no-store"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
    # ASVS 5.0 V3.4.1 (L2: one year, subdomains included). Browsers only honour it over HTTPS, i.e. behind the TLS
    # proxy of the deployment (README §7); over plain HTTP in development it is ignored (decidido de noche, revisar).
    (b"strict-transport-security", b"max-age=31536000; includeSubDomains"),
)


class SecurityHeadersMiddleware:
    """Pure ASGI middleware (keeps streaming responses such as SSE streaming)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        csp = (_DOCS_CSP if str(scope.get("path", "")).startswith(DOCS_PATH) else _API_CSP).encode()

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                present = {name.lower() for name, _value in message.get("headers", [])}
                extra = (*_COMMON, (b"content-security-policy", csp))
                message["headers"] = [*message.get("headers", []), *(h for h in extra if h[0] not in present)]
            await send(message)

        await self.app(scope, receive, send_with_headers)
