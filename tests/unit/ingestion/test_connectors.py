"""Connectors and canonical URLs with short synthetic documents."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.ingestion.connectors import (
    FieldMapping,
    FormatChangedError,
    parse_csv_feed,
    parse_datetime,
    parse_feed,
    parse_json_feed,
    parse_rss_atom,
)
from core.ingestion.urls import InvalidUrlError, canonicalize_url

RSS = b"""<?xml version="1.0"?>
<rss version="2.0"><channel><title>Synthetic</title>
<item><title>First note</title><link>https://news.example.com/a?utm_source=x</link>
<pubDate>Sat, 21 Nov 2026 10:00:00 GMT</pubDate><description>&lt;p&gt;Short summary&lt;/p&gt;</description></item>
<item><title>No link here</title></item>
<item><title>Undated</title><link>https://news.example.com/b</link></item>
</channel></rss>"""

ATOM = b"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>Synthetic</title>
<entry><title>Atom note</title><link href="https://news.example.com/c"/>
<published>2026-11-20T08:30:00Z</published><content type="html">&lt;p&gt;Body&lt;/p&gt;</content></entry>
<entry><title>Updated only</title><link href="https://news.example.com/d"/><updated>2026-11-19T00:00:00Z</updated></entry>
</feed>"""


def test_rss_items_are_normalized() -> None:
    items = parse_rss_atom(RSS)
    assert [i.title for i in items] == ["First note", "Undated"]
    assert items[0].published_at == datetime(2026, 11, 21, 10, 0, tzinfo=UTC)
    assert items[0].summary == "<p>Short summary</p>"
    assert items[1].published_at is None


def test_atom_uses_published_then_updated_and_content() -> None:
    items = parse_rss_atom(ATOM)
    assert items[0].published_at == datetime(2026, 11, 20, 8, 30, tzinfo=UTC)
    assert items[0].summary == "<p>Body</p>"
    assert items[1].published_at == datetime(2026, 11, 19, tzinfo=UTC)


@pytest.mark.parametrize("body", [b"<html><body>Moved</body></html>", b"not xml at all", b""])
def test_non_feed_document_is_format_changed(body: bytes) -> None:
    with pytest.raises(FormatChangedError):
        parse_rss_atom(body)


def test_empty_valid_feed_is_not_an_error() -> None:
    body = b'<?xml version="1.0"?><rss version="2.0"><channel><title>Quiet</title></channel></rss>'
    assert parse_rss_atom(body) == []


def test_json_feed_with_path_and_mapping() -> None:
    mapping = FieldMapping(title="name", url="link", published="date", summary="desc", items_path=("data", "items"))
    body = (
        b'{"data": {"items": [{"name": "A", "link": "https://x.example/a", "date": "2026-11-20T01:00:00+00:00",'
        b' "desc": "d"}, {"name": "", "link": "https://x.example/b"}, "junk", {"name": "C", "link": "https://x.example/c",'
        b' "date": 1790000000}]}}'
    )
    items = parse_json_feed(body, mapping)
    assert [i.title for i in items] == ["A", "C"]
    assert items[0].published_at == datetime(2026, 11, 20, 1, tzinfo=UTC)
    assert items[1].published_at is not None


@pytest.mark.parametrize(
    "body",
    [b"not json", b'{"data": {}}', b'{"data": {"items": {"a": 1}}}', b'{"other": 1}'],
)
def test_json_format_changes(body: bytes) -> None:
    with pytest.raises(FormatChangedError):
        parse_json_feed(body, FieldMapping(items_path=("data", "items")))


def test_csv_feed_and_format_changes() -> None:
    body = "﻿title,url,published,summary\nOne,https://x.example/1,2026-11-20,sum\n,https://x.example/2,,\n".encode()
    items = parse_csv_feed(body, FieldMapping())
    assert [i.title for i in items] == ["One"]
    assert items[0].published_at == datetime(2026, 11, 20, tzinfo=UTC)
    with pytest.raises(FormatChangedError):
        parse_csv_feed(b"a,b\n1,2\n", FieldMapping())
    with pytest.raises(FormatChangedError):
        parse_csv_feed(b"", FieldMapping())
    with pytest.raises(FormatChangedError):
        parse_csv_feed(b"\xff\xfe", FieldMapping())


def test_parse_feed_dispatch() -> None:
    assert len(parse_feed("rss", RSS)) == 2
    assert len(parse_feed("atom", ATOM)) == 2
    assert parse_feed("json", b'[{"title": "T", "url": "https://x.example/t"}]') == parse_feed(
        "api", b'[{"title": "T", "url": "https://x.example/t"}]'
    )
    assert len(parse_feed("csv", b"title,url\nT,https://x.example/t\n")) == 1
    with pytest.raises(FormatChangedError):
        parse_feed("xml", b"")


@pytest.mark.parametrize("value", ["", "garbage", None, True, 10**30, [1]])
def test_unreadable_dates_are_none(value: object) -> None:
    assert parse_datetime(value) is None


def test_naive_date_is_utc() -> None:
    assert parse_datetime("2026-11-20T10:00:00") == datetime(2026, 11, 20, 10, tzinfo=UTC)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://News.Example.com/a/?utm_source=x&utm_medium=y", "https://news.example.com/a"),
        ("http://news.example.com/a/", "https://news.example.com/a"),
        ("https://news.example.com/a#section", "https://news.example.com/a"),
        ("https://news.example.com/a/amp", "https://news.example.com/a"),
        ("https://news.example.com/amp/a", "https://news.example.com/a"),
        ("https://amp.news.example.com/a", "https://news.example.com/a"),
        ("https://news.example.com/a?amp=1&id=7&fbclid=zz", "https://news.example.com/a?id=7"),
        ("https://news.example.com/a?b=2&a=1", "https://news.example.com/a?a=1&b=2"),
        ("https://news.example.com:443/a", "https://news.example.com/a"),
        ("https://news.example.com:8443/a", "https://news.example.com:8443/a"),
        ("https://news.example.com", "https://news.example.com/"),
        ("https://[2001:db8::1]/a", "https://[2001:db8::1]/a"),
        ("https://[2001:db8::1]:8443/a", "https://[2001:db8::1]:8443/a"),
    ],
)
def test_canonical_url(raw: str, expected: str) -> None:
    assert canonicalize_url(raw) == expected


@pytest.mark.parametrize("raw", ["", "ftp://x.example/a", "/relative", "https://", "https://x.example:99999/a"])
def test_invalid_urls(raw: str) -> None:
    with pytest.raises(InvalidUrlError):
        canonicalize_url(raw)
