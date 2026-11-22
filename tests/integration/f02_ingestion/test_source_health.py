"""Source health alerts: no data inside source_health_hours or a changed format, alerted once per outage."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from ingestion_support import NOW, Feed
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id
from core.ingestion.health import ALERT_DOWN, ALERT_RECOVERED, check_source_health

pytestmark = pytest.mark.integration


def at(hours_ago: float) -> datetime:
    return NOW - timedelta(hours=hours_ago)


def clock() -> datetime:
    return NOW


def seven_hours_later() -> datetime:
    return NOW + timedelta(hours=7)


def read(feed: Feed, outlet: str, hours_ago: float, status: str = "ok") -> None:
    """A source read `hours_ago` hours before NOW (creates the source on first use)."""
    source = feed.source_for(outlet)
    feed.session.add(
        m.SourceFetch(
            id=new_id(),
            source_id=source.id,
            run_id=feed.run.id,
            started_at=at(hours_ago),
            finished_at=at(hours_ago),
            status=status,
            items_new=0,
        )
    )
    feed.session.flush()


def history(session: Session) -> list[str]:
    return list(session.scalars(select(m.AuditLog.action).order_by(m.AuditLog.created_at, m.AuditLog.id)))


def test_recent_read_is_healthy(session: Session) -> None:
    feed = Feed(session)
    read(feed, "thn", 2)
    assert check_source_health(session, clock) == []
    assert history(session) == []


def test_source_without_data_for_longer_than_the_window_alerts_once(session: Session) -> None:
    feed = Feed(session)
    read(feed, "thn", 7)
    alerts = check_source_health(session, clock)
    assert [(a.source_code, a.reason) for a in alerts] == [("thn", "no_data")]
    assert alerts[0].last_ok_at == at(7)
    assert check_source_health(session, clock) == []  # same outage: no second alert
    assert history(session) == [ALERT_DOWN]
    logged = session.scalars(select(m.AuditLog)).one()
    assert logged.after == {"code": "thn", "reason": "no_data", "last_ok_at": at(7).isoformat(), "hours": 6}


def test_failed_reads_do_not_count_as_data(session: Session) -> None:
    feed = Feed(session)
    read(feed, "thn", 8)
    read(feed, "thn", 1, status="error")
    assert [a.reason for a in check_source_health(session, clock)] == ["no_data"]


def test_changed_format_alerts_even_inside_the_window(session: Session) -> None:
    feed = Feed(session)
    read(feed, "thn", 2)
    read(feed, "thn", 1, status="format_changed")
    assert [a.reason for a in check_source_health(session, clock)] == ["format_changed"]


def test_recovery_closes_the_alert_and_a_new_outage_alerts_again(session: Session) -> None:
    feed = Feed(session)
    read(feed, "thn", 9)
    assert len(check_source_health(session, clock)) == 1
    read(feed, "thn", 0.5)
    assert check_source_health(session, clock) == []
    assert history(session) == [ALERT_DOWN, ALERT_RECOVERED]
    assert len(check_source_health(session, seven_hours_later)) == 1
    assert history(session) == [ALERT_DOWN, ALERT_RECOVERED, ALERT_DOWN]


def test_never_read_source_gets_a_grace_period_from_its_creation(session: Session) -> None:
    feed = Feed(session)
    feed.source_for("fresh")  # a source created at NOW with no read yet
    assert check_source_health(session, clock) == []
    assert [a.reason for a in check_source_health(session, seven_hours_later)] == ["no_data"]


def test_disabled_sources_and_an_explicit_window_are_respected(session: Session) -> None:
    feed = Feed(session)
    read(feed, "thn", 7)
    read(feed, "off", 20)
    source = session.scalars(select(m.Source).where(m.Source.code == "off")).one()
    source.enabled = False
    session.flush()
    assert check_source_health(session, clock, hours=12) == []
    assert [a.source_code for a in check_source_health(session, clock, hours=3)] == ["thn"]
