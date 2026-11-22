"""Source rules (D-041): structural sources stay on, custom feeds enter as N4 over HTTPS, every change is audited."""

from __future__ import annotations

import pytest
from ingestion_support import NOW
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id
from core.ingestion.catalog import sync_default_sources
from core.ingestion.sources import (
    NewSource,
    SourceRuleError,
    add_custom_source,
    set_source_enabled,
    set_trust_tier,
)

pytestmark = pytest.mark.integration
PUBLIC = "93.184.216.34"


def resolve_public(_host: str) -> list[str]:
    return [PUBLIC]


def by_code(session: Session, code: str) -> m.Source:
    return session.scalars(select(m.Source).where(m.Source.code == code)).one()


def actor(session: Session) -> m.AppUser:
    user = m.AppUser(
        id=new_id(), firebase_uid="uid-admin", email="admin@example.com", role="admin", active=True, created_at=NOW
    )
    session.add(user)
    session.flush()
    return user


def test_structural_sources_cannot_be_switched_off(session: Session) -> None:
    sync_default_sources(session, NOW)
    for code in ("nvd", "cve_org", "kev", "epss", "osv"):
        with pytest.raises(SourceRuleError, match="estructurales"):
            set_source_enabled(session, by_code(session, code).id, False, None, NOW)
        assert by_code(session, code).enabled
    set_source_enabled(session, by_code(session, "kev").id, True, None, NOW)  # enabling stays a no-op
    assert session.scalars(select(m.AuditLog)).all() == []


def test_optional_sources_can_be_switched_off_and_on_with_audit(session: Session) -> None:
    sync_default_sources(session, NOW)
    user = actor(session)
    thn = by_code(session, "thn")
    set_source_enabled(session, thn.id, False, user.id, NOW)
    assert not by_code(session, "thn").enabled
    set_source_enabled(session, thn.id, True, user.id, NOW)
    rows = session.scalars(select(m.AuditLog).order_by(m.AuditLog.id)).all()
    assert [r.action for r in rows] == ["source.disable", "source.enable"]
    assert rows[0].before == {"enabled": True}
    assert rows[0].after == {"enabled": False}
    assert rows[0].app_user_id == user.id


def test_unknown_source_is_refused(session: Session) -> None:
    with pytest.raises(SourceRuleError, match="no existe"):
        set_source_enabled(session, new_id(), False, None, NOW)


def test_new_custom_feed_enters_as_n4_over_https(session: Session) -> None:
    user = actor(session)
    source = add_custom_source(
        session,
        NewSource("my_feed", " My feed ", "rss", "https://blog.example.com/feed.xml"),
        user.id,
        NOW,
        resolve_public,
    )
    assert (source.trust_tier, source.is_custom, source.is_structural, source.enabled) == ("N4", True, False, True)
    assert source.name == "My feed"
    assert source.created_by == user.id
    audit = session.scalars(select(m.AuditLog)).one()
    assert audit.action == "source.create"
    assert audit.after["trust_tier"] == "N4"


@pytest.mark.parametrize(
    ("new", "message"),
    [
        (NewSource("bad code", "n", "rss", "https://blog.example.com/f"), "código"),
        (NewSource("ok_code", "n", "xml", "https://blog.example.com/f"), "Tipo"),
        (NewSource("ok_code", "  ", "rss", "https://blog.example.com/f"), "nombre"),
        (NewSource("ok_code", "n", "rss", "http://blog.example.com/f"), "URL no permitida"),
        (NewSource("ok_code", "n", "rss", "https://127.0.0.1/f"), "URL no permitida"),
        (NewSource("ok_code", "n", "rss", "https://user:pw@blog.example.com/f"), "URL no permitida"),
        (NewSource("ok_code", "n", "rss", "https://blog.example.com/" + "a" * 2100), "larga"),
    ],
)
def test_invalid_custom_feeds_are_refused(session: Session, new: NewSource, message: str) -> None:
    with pytest.raises(SourceRuleError, match=message):
        add_custom_source(session, new, None, NOW, resolve_public)
    assert session.scalars(select(m.Source)).all() == []


def test_duplicate_code_is_refused(session: Session) -> None:
    sync_default_sources(session, NOW)
    with pytest.raises(SourceRuleError, match="Ya existe"):
        add_custom_source(
            session, NewSource("thn", "Dup", "rss", "https://blog.example.com/f"), None, NOW, resolve_public
        )


def test_trust_tier_changes_are_audited_and_n1_stays_official(session: Session) -> None:
    user = actor(session)
    custom = add_custom_source(
        session, NewSource("my_feed", "Feed", "rss", "https://blog.example.com/f"), user.id, NOW, resolve_public
    )
    with pytest.raises(SourceRuleError, match="N1"):
        set_trust_tier(session, custom.id, "N1", user.id, NOW)
    with pytest.raises(SourceRuleError, match="desconocido"):
        set_trust_tier(session, custom.id, "N9", user.id, NOW)
    set_trust_tier(session, custom.id, "N3", user.id, NOW)
    set_trust_tier(session, custom.id, "N3", user.id, NOW)  # no change, no second audit row
    assert by_code(session, "my_feed").trust_tier == "N3"
    changes = session.scalars(select(m.AuditLog).where(m.AuditLog.action == "source.trust_tier")).all()
    assert len(changes) == 1
    assert changes[0].before == {"trust_tier": "N4"}
    assert changes[0].after == {"trust_tier": "N3"}
