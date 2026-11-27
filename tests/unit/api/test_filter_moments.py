"""F18.4: one parser for the RFC 3339 date filters of every list (runs, telemetry, history, vulnerabilities, audit)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

from api.routes import _runs, admin, findings, telemetry
from api.routes.models import parse_moment


def test_a_filter_moment_is_an_aware_datetime_or_none() -> None:
    assert parse_moment(None) is None
    assert parse_moment("") is None
    assert parse_moment("2026-11-27t10:00:00z") == datetime(2026, 11, 27, 10, 0, tzinfo=UTC)  # lower case allowed
    offset = parse_moment("2026-11-27T04:00:00-06:00")
    assert offset == datetime(2026, 11, 27, 10, 0, tzinfo=UTC)
    assert offset is not None and offset.tzinfo == timezone(timedelta(hours=-6))


def test_the_routes_share_the_parser() -> None:
    for module in (_runs, admin, findings, telemetry):
        assert module.parse_moment is parse_moment, module.__name__
