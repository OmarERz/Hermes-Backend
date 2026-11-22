"""SSRF guard and bounded fetcher, without network (respx + fake resolver)."""

from __future__ import annotations

import httpx
import pytest
import respx

from core.ingestion.fetcher import ARTICLE_CONTENT_TYPES, Fetcher, FetchError, FetchLimits
from core.ingestion.ssrf import UnsafeUrlError, validate_public_url

PUBLIC = "93.184.216.34"


def resolve_public(_host: str) -> list[str]:
    return [PUBLIC]


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/feed",
        "ftp://example.com/feed",
        "https://user:pw@example.com/feed",
        "https://example.com:8443/feed",
        "https://127.0.0.1/feed",
        "https://10.0.0.5/feed",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/feed",
        "https://[::ffff:10.0.0.1]/feed",
        "https://100.64.0.1/feed",
        "https:///nohost",
        "https://example.com:99999/feed",
    ],
)
def test_unsafe_urls_are_refused(url: str) -> None:
    with pytest.raises(UnsafeUrlError):
        validate_public_url(url, resolve_public)


def test_host_resolving_to_private_address_is_refused() -> None:
    with pytest.raises(UnsafeUrlError):
        validate_public_url("https://internal.example.com/x", lambda _h: [PUBLIC, "192.168.1.10"])


def test_unresolvable_host_is_refused() -> None:
    with pytest.raises(UnsafeUrlError):
        validate_public_url("https://nowhere.example.com/x", lambda _h: [])


def test_public_host_is_accepted() -> None:
    assert validate_public_url("https://example.com/feed.xml", resolve_public) == "example.com"
    assert validate_public_url("https://93.184.216.34/feed.xml", resolve_public) == "93.184.216.34"


def make_fetcher(limits: FetchLimits | None = None) -> Fetcher:
    return Fetcher(limits=limits, resolver=resolve_public)


@respx.mock
def test_fetch_returns_body_and_type() -> None:
    respx.get("https://example.com/feed").mock(
        return_value=httpx.Response(
            200, content=b"<rss/>", headers={"content-type": "application/rss+xml; charset=utf-8"}
        )
    )
    doc = make_fetcher().get("https://example.com/feed")
    assert doc.body == b"<rss/>"
    assert doc.content_type == "application/rss+xml"


@respx.mock
def test_wrong_content_type_is_refused() -> None:
    respx.get("https://example.com/a").mock(
        return_value=httpx.Response(200, content=b"x", headers={"content-type": "image/png"})
    )
    with pytest.raises(FetchError, match="content type"):
        make_fetcher().get("https://example.com/a")
    respx.get("https://example.com/b").mock(
        return_value=httpx.Response(200, content=b"<html/>", headers={"content-type": "text/html"})
    )
    assert make_fetcher().get("https://example.com/b", ARTICLE_CONTENT_TYPES).body == b"<html/>"


@respx.mock
def test_size_limit_applies_to_declared_and_streamed_bodies() -> None:
    limits = FetchLimits(max_bytes=10)
    respx.get("https://example.com/declared").mock(
        return_value=httpx.Response(200, content=b"x", headers={"content-type": "text/csv", "content-length": "999"})
    )
    with pytest.raises(FetchError, match="too large"):
        make_fetcher(limits).get("https://example.com/declared")
    respx.get("https://example.com/streamed").mock(
        return_value=httpx.Response(200, content=b"x" * 50, headers={"content-type": "text/csv"})
    )
    with pytest.raises(FetchError, match="too large"):
        make_fetcher(limits).get("https://example.com/streamed")


@respx.mock
def test_status_error_and_transport_error_are_fetch_errors() -> None:
    respx.get("https://example.com/missing").mock(return_value=httpx.Response(404))
    with pytest.raises(FetchError, match="status 404"):
        make_fetcher().get("https://example.com/missing")
    respx.get("https://example.com/slow").mock(side_effect=httpx.ConnectTimeout("slow"))
    with pytest.raises(FetchError, match="ConnectTimeout"):
        make_fetcher().get("https://example.com/slow")


@respx.mock
def test_redirects_are_followed_and_revalidated() -> None:
    respx.get("https://example.com/old").mock(return_value=httpx.Response(302, headers={"location": "/new"}))
    respx.get("https://example.com/new").mock(
        return_value=httpx.Response(200, content=b"ok", headers={"content-type": "text/plain"})
    )
    assert make_fetcher().get("https://example.com/old").url == "https://example.com/new"

    respx.get("https://example.com/evil").mock(
        return_value=httpx.Response(302, headers={"location": "https://127.0.0.1/admin"})
    )
    with pytest.raises(FetchError, match="Refused target"):
        make_fetcher().get("https://example.com/evil")

    respx.get("https://example.com/downgrade").mock(
        return_value=httpx.Response(302, headers={"location": "http://example.com/x"})
    )
    with pytest.raises(FetchError, match="Refused target"):
        make_fetcher().get("https://example.com/downgrade")


@respx.mock
def test_redirect_loop_and_missing_location_are_refused() -> None:
    respx.get("https://example.com/loop").mock(return_value=httpx.Response(302, headers={"location": "/loop"}))
    with pytest.raises(FetchError, match="Too many redirects"):
        make_fetcher().get("https://example.com/loop")
    respx.get("https://example.com/nolocation").mock(return_value=httpx.Response(302))
    with pytest.raises(FetchError, match="without a location"):
        make_fetcher().get("https://example.com/nolocation")


def test_initial_private_target_is_refused_before_any_request() -> None:
    with pytest.raises(FetchError, match="Refused target"):
        make_fetcher().get("https://10.1.2.3/feed")
