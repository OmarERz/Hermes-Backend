"""In-memory web for the fetcher: URL to canned response, as an httpx transport (no network)."""

from __future__ import annotations

import httpx


class FakeWeb:
    """Serves canned responses by absolute URL (query string ignored). Unknown URLs answer 404.

    The fetcher pins the connection to the approved IP and keeps the original host in the `Host` header, so the
    URL is rebuilt from that header.
    """

    def __init__(self) -> None:
        self._routes: dict[str, httpx.Response | Exception] = {}
        self.requests: list[httpx.Request] = []

    def serve(
        self,
        url: str,
        content: bytes,
        content_type: str = "application/rss+xml",
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._routes[url] = httpx.Response(
            status, content=content, headers={"content-type": content_type, **(headers or {})}
        )

    def redirect(self, url: str, location: str, status: int = 302) -> None:
        self._routes[url] = httpx.Response(status, headers={"location": location})

    def fail(self, url: str, error: Exception) -> None:
        self._routes[url] = error

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host = request.headers["host"]
        url = f"https://{host}{request.url.path}"
        route = self._routes.get(url)
        if route is None:
            return httpx.Response(404)
        if isinstance(route, Exception):
            raise route
        return httpx.Response(route.status_code, content=route.content, headers=route.headers)
