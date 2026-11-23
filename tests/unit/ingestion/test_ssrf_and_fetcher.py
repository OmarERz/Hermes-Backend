"""SSRF guard and bounded fetcher, without network (respx + fake resolver)."""

from __future__ import annotations

import httpx
import pytest

from core.ingestion.fetcher import ARTICLE_CONTENT_TYPES, Fetcher, FetchError, FetchLimits, PinnedTransport
from core.ingestion.ssrf import UnsafeUrlError, validate_public_url
from doubles.web import FakeWeb

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


def make_fetcher(web: FakeWeb, limits: FetchLimits | None = None) -> Fetcher:
    return Fetcher(limits=limits, transport=web.transport(), resolver=resolve_public)


def test_fetch_returns_body_and_type() -> None:
    web = FakeWeb()
    web.serve("https://example.com/feed", b"<rss/>", "application/rss+xml; charset=utf-8")
    doc = make_fetcher(web).get("https://example.com/feed?x=1")
    assert doc.body == b"<rss/>"
    assert doc.content_type == "application/rss+xml"


def test_connection_is_pinned_to_the_approved_address() -> None:
    web = FakeWeb()
    web.serve("https://example.com/feed", b"<rss/>")
    make_fetcher(web).get("https://example.com/feed")
    request = web.requests[0]
    assert request.url.host == PUBLIC
    assert request.headers["host"] == "example.com"
    assert request.extensions["sni_hostname"] == "example.com"


def test_dns_answer_changing_to_a_private_address_is_refused_at_connect_time() -> None:
    answers = iter([[PUBLIC], ["10.0.0.9"]])  # validation sees a public address, the connection a private one
    web = FakeWeb()
    web.serve("https://example.com/feed", b"<rss/>")
    fetcher = Fetcher(transport=web.transport(), resolver=lambda _host: next(answers))
    with pytest.raises(FetchError, match="Refused target"):
        fetcher.get("https://example.com/feed")
    assert web.requests == []


def test_ip_literal_is_not_rewritten() -> None:
    web = FakeWeb()
    web.serve("https://93.184.216.34/feed", b"<rss/>")
    make_fetcher(web).get("https://93.184.216.34/feed")
    assert "sni_hostname" not in web.requests[0].extensions


def test_pinned_transport_close_closes_inner() -> None:
    closed: list[bool] = []

    class Inner(httpx.BaseTransport):
        def close(self) -> None:
            closed.append(True)

    PinnedTransport(Inner(), resolve_public).close()
    make_fetcher(FakeWeb()).close()
    assert closed == [True]


def test_wrong_content_type_is_refused() -> None:
    web = FakeWeb()
    web.serve("https://example.com/a", b"x", "image/png")
    web.serve("https://example.com/b", b"<html/>", "text/html")
    with pytest.raises(FetchError, match="content type"):
        make_fetcher(web).get("https://example.com/a")
    assert make_fetcher(web).get("https://example.com/b", ARTICLE_CONTENT_TYPES).body == b"<html/>"


def test_size_limit_applies_to_declared_and_streamed_bodies() -> None:
    web = FakeWeb()
    limits = FetchLimits(max_bytes=10)
    web.serve("https://example.com/declared", b"x", "text/csv", headers={"content-length": "999"})
    web.serve("https://example.com/streamed", b"x" * 50, "text/csv")
    with pytest.raises(FetchError, match="too large"):
        make_fetcher(web, limits).get("https://example.com/declared")
    with pytest.raises(FetchError, match="too large"):
        make_fetcher(web, limits).get("https://example.com/streamed")


def test_status_error_and_transport_error_are_fetch_errors() -> None:
    web = FakeWeb()
    web.serve("https://example.com/missing", b"", status=404)
    web.fail("https://example.com/slow", httpx.ConnectTimeout("slow"))
    with pytest.raises(FetchError, match="status 404"):
        make_fetcher(web).get("https://example.com/missing")
    with pytest.raises(FetchError, match="ConnectTimeout"):
        make_fetcher(web).get("https://example.com/slow")


def test_redirects_are_followed_and_revalidated() -> None:
    web = FakeWeb()
    web.redirect("https://example.com/old", "/new")
    web.serve("https://example.com/new", b"ok", "text/plain")
    assert make_fetcher(web).get("https://example.com/old").url == "https://example.com/new"

    web.redirect("https://example.com/evil", "https://127.0.0.1/admin")
    with pytest.raises(FetchError, match="Refused target"):
        make_fetcher(web).get("https://example.com/evil")

    web.redirect("https://example.com/downgrade", "http://example.com/x")
    with pytest.raises(FetchError, match="Refused target"):
        make_fetcher(web).get("https://example.com/downgrade")


def test_redirect_loop_and_missing_location_are_refused() -> None:
    web = FakeWeb()
    web.redirect("https://example.com/loop", "/loop")
    web.serve("https://example.com/nolocation", b"", status=302)
    with pytest.raises(FetchError, match="Too many redirects"):
        make_fetcher(web).get("https://example.com/loop")
    with pytest.raises(FetchError, match="without a location"):
        make_fetcher(web).get("https://example.com/nolocation")


def test_initial_private_target_is_refused_before_any_request() -> None:
    web = FakeWeb()
    with pytest.raises(FetchError, match="Refused target"):
        make_fetcher(web).get("https://10.1.2.3/feed")
    assert web.requests == []


@pytest.mark.parametrize("url", ["https:// \u0087q\u00b6", "https://bad\u0087host.example"])
def test_host_that_is_not_a_valid_name_is_refused_by_the_system_resolver(url: str) -> None:
    with pytest.raises(UnsafeUrlError, match="not a valid name"):
        validate_public_url(url)
