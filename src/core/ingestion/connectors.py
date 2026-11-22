"""Feed connectors (ING-01, ING-03): RSS/Atom, JSON and CSV into normalized `FeedItem`s.

Parsers take bytes already fetched by `Fetcher`; they never touch the network. A document that is not in the
expected format raises `FormatChangedError` so the source health can report it (FUE-R2). JSON and CSV feeds
need a `FieldMapping` that says where each field lives.
"""

from __future__ import annotations

import calendar
import csv
import io
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import feedparser

MAX_ITEMS = 2_000


class FormatChangedError(ValueError):
    """The document is not the format the source is configured for."""


@dataclass(frozen=True)
class FeedItem:
    """One entry of a feed, before cleaning. `summary` may contain HTML."""

    title: str
    url: str
    published_at: datetime | None
    summary: str


@dataclass(frozen=True)
class FieldMapping:
    """Where the fields live in a JSON or CSV record. `items_path` is the JSON path to the list of records."""

    title: str = "title"
    url: str = "url"
    published: str | None = "published"
    summary: str | None = "summary"
    items_path: tuple[str, ...] = ()


def parse_datetime(value: Any) -> datetime | None:
    """ISO 8601 text or epoch seconds into an aware UTC datetime; None when it cannot be read."""
    parsed: datetime | None = None
    try:
        if isinstance(value, bool):
            return None
        if isinstance(value, int | float):
            parsed = datetime.fromtimestamp(value, UTC)
        elif isinstance(value, str) and value.strip():
            parsed = datetime.fromisoformat(value.strip())
    except (ValueError, OverflowError, OSError):
        return None
    if parsed is None:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse_rss_atom(body: bytes) -> list[FeedItem]:
    """RSS (`pubDate`) and Atom (`published`, then `updated`) entries."""
    feed = feedparser.parse(io.BytesIO(body))  # a stream: bytes could be read as a local path
    if not feed.get("version"):
        raise FormatChangedError("The document is not a valid RSS or Atom feed")
    items: list[FeedItem] = []
    for entry in feed.entries[:MAX_ITEMS]:
        title = str(entry.get("title", "")).strip()
        link = str(entry.get("link", "")).strip()
        if not title or not link:
            continue
        stamp = entry.get("published_parsed") or entry.get("updated_parsed")
        published = datetime.fromtimestamp(calendar.timegm(stamp), UTC) if stamp else None
        content = entry.get("content")
        summary = str(content[0].get("value", "")) if content else str(entry.get("summary", ""))
        items.append(FeedItem(title=title, url=link, published_at=published, summary=summary))
    return items


def _record_to_item(record: dict[str, Any], mapping: FieldMapping) -> FeedItem | None:
    title = str(record.get(mapping.title) or "").strip()
    url = str(record.get(mapping.url) or "").strip()
    if not title or not url:
        return None
    published = parse_datetime(record.get(mapping.published)) if mapping.published else None
    summary = str(record.get(mapping.summary) or "") if mapping.summary else ""
    return FeedItem(title=title, url=url, published_at=published, summary=summary)


def parse_json_feed(body: bytes, mapping: FieldMapping) -> list[FeedItem]:
    try:
        document: Any = json.loads(body)
    except (ValueError, RecursionError) as exc:
        raise FormatChangedError("The document is not valid JSON") from exc
    for key in mapping.items_path:
        if not isinstance(document, dict) or key not in document:
            raise FormatChangedError("The JSON path to the records no longer exists")
        document = document[key]
    if not isinstance(document, list):
        raise FormatChangedError("The JSON records are not a list")
    items = (_record_to_item(r, mapping) for r in document[:MAX_ITEMS] if isinstance(r, dict))
    return [item for item in items if item is not None]


def parse_csv_feed(body: bytes, mapping: FieldMapping) -> list[FeedItem]:
    try:
        text = body.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise FormatChangedError("The CSV is not UTF-8") from exc
    reader = csv.DictReader(io.StringIO(text))
    try:
        fieldnames = reader.fieldnames
    except csv.Error as exc:
        raise FormatChangedError("The CSV cannot be read") from exc
    if not fieldnames or not {mapping.title, mapping.url} <= set(fieldnames):
        raise FormatChangedError("The CSV header no longer has the mapped columns")
    items: list[FeedItem] = []
    try:
        for index, row in enumerate(reader):
            if index >= MAX_ITEMS:
                break
            item = _record_to_item({k: v for k, v in row.items() if isinstance(k, str)}, mapping)
            if item is not None:
                items.append(item)
    except csv.Error as exc:
        raise FormatChangedError("The CSV cannot be read") from exc
    return items


def parse_feed(kind: str, body: bytes, mapping: FieldMapping | None = None) -> list[FeedItem]:
    """Parse by source kind (`source.kind`)."""
    if kind in ("rss", "atom"):
        return parse_rss_atom(body)
    mapping = mapping or FieldMapping()
    if kind in ("json", "api"):
        return parse_json_feed(body, mapping)
    if kind == "csv":
        return parse_csv_feed(body, mapping)
    raise FormatChangedError(f"Unsupported source kind {kind}")
