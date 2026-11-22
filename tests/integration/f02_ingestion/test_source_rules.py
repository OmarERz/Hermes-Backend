"""Source rules (D-041): structural sources stay on, custom feeds enter as N4 over HTTPS, every change is audited."""

from __future__ import annotations

import pytest
from ingestion_support import NOW
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id
from core.ingestion.catalog import sync_default_sources
from core.ingestion.service import news_sources
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


def user(session: Session, role: str, active: bool = True) -> m.AppUser:
    row = m.AppUser(
        id=new_id(), firebase_uid=f"uid-{role}", email=f"{role}@example.com", role=role, active=active, created_at=NOW
    )
    session.add(row)
    session.flush()
    return row


def feed(code: str = "my_feed", url: str = "https://blog.example.com/feed.xml", kind: str = "rss") -> NewSource:
    return NewSource(code, "Feed", kind, url)


def test_structural_sources_cannot_be_switched_off(session: Session) -> None:
    sync_default_sources(session, NOW)
    admin = user(session, "admin")
    for code in ("nvd", "cve_org", "kev", "epss", "osv"):
        with pytest.raises(SourceRuleError, match="estructurales"):
            set_source_enabled(session, by_code(session, code).id, False, admin.id, NOW)
        assert by_code(session, code).enabled
    set_source_enabled(session, by_code(session, "kev").id, True, admin.id, NOW)  # enabling stays a no-op
    assert session.scalars(select(m.AuditLog)).all() == []


def test_optional_sources_can_be_switched_off_and_on_by_an_analyst_with_audit(session: Session) -> None:
    sync_default_sources(session, NOW)
    analyst = user(session, "analyst")
    thn = by_code(session, "thn")
    set_source_enabled(session, thn.id, False, analyst.id, NOW)
    assert not by_code(session, "thn").enabled
    set_source_enabled(session, thn.id, True, analyst.id, NOW)
    rows = session.scalars(select(m.AuditLog).order_by(m.AuditLog.id)).all()
    assert [r.action for r in rows] == ["source.disable", "source.enable"]
    assert rows[0].before == {"enabled": True}
    assert rows[0].after == {"enabled": False}
    assert rows[0].app_user_id == analyst.id


def test_unknown_source_is_refused(session: Session) -> None:
    admin = user(session, "admin")
    with pytest.raises(SourceRuleError, match="no existe"):
        set_source_enabled(session, new_id(), False, admin.id, NOW)


def test_roles_are_checked_by_the_rules_themselves(session: Session) -> None:
    sync_default_sources(session, NOW)
    reader = user(session, "reader")
    analyst = user(session, "analyst")
    thn = by_code(session, "thn")
    for actor in (None, reader.id, new_id()):
        with pytest.raises(SourceRuleError, match="permiso"):
            set_source_enabled(session, thn.id, False, actor, NOW)
    with pytest.raises(SourceRuleError, match="permiso"):
        set_trust_tier(session, thn.id, "N2", analyst.id, NOW)
    with pytest.raises(SourceRuleError, match="permiso"):
        add_custom_source(session, feed(), analyst.id, NOW, resolve_public)
    assert by_code(session, "thn").enabled
    assert by_code(session, "thn").trust_tier == "N3"
    assert session.scalars(select(m.AuditLog)).all() == []


def test_inactive_admin_has_no_permission(session: Session) -> None:
    inactive = user(session, "admin", active=False)
    with pytest.raises(SourceRuleError, match="permiso"):
        add_custom_source(session, feed(), inactive.id, NOW, resolve_public)


def test_new_custom_feed_enters_as_n4_over_https(session: Session) -> None:
    admin = user(session, "admin")
    source = add_custom_source(
        session,
        NewSource("my_feed", " My feed ", "rss", "https://blog.example.com/feed.xml?lang=es"),
        admin.id,
        NOW,
        resolve_public,
    )
    assert (source.trust_tier, source.is_custom, source.is_structural, source.enabled) == ("N4", True, False, True)
    assert source.name == "My feed"
    assert source.created_by == admin.id
    audit = session.scalars(select(m.AuditLog)).one()
    assert audit.action == "source.create"
    assert audit.after == {
        "code": "my_feed",
        "kind": "rss",
        "url": "https://blog.example.com/feed.xml",  # the query string stays out of the audit trail
        "trust_tier": "N4",
    }


def test_custom_api_feed_is_read_by_the_pipeline(session: Session) -> None:
    admin = user(session, "admin")
    add_custom_source(session, feed("api_feed", kind="api"), admin.id, NOW, resolve_public)
    assert [s.code for s in news_sources(session)] == ["api_feed"]


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
        (NewSource("ok_code", "n", "rss", "https://blog.example.com/f?api_key=abc"), "llaves"),
        (NewSource("ok_code", "n", "rss", "https://blog.example.com/f?x=1&access_token=abc"), "llaves"),
    ],
)
def test_invalid_custom_feeds_are_refused(session: Session, new: NewSource, message: str) -> None:
    admin = user(session, "admin")
    with pytest.raises(SourceRuleError, match=message):
        add_custom_source(session, new, admin.id, NOW, resolve_public)
    assert session.scalars(select(m.Source)).all() == []


def test_catalog_codes_are_reserved_even_before_the_catalog_is_loaded(session: Session) -> None:
    admin = user(session, "admin")
    with pytest.raises(SourceRuleError, match="Ya existe"):
        add_custom_source(session, feed("kev"), admin.id, NOW, resolve_public)
    sync_default_sources(session, NOW)
    assert by_code(session, "kev").is_structural
    with pytest.raises(SourceRuleError, match="Ya existe"):
        add_custom_source(session, feed("thn"), admin.id, NOW, resolve_public)


def test_trust_tier_changes_are_audited_and_n1_stays_official(session: Session) -> None:
    sync_default_sources(session, NOW)
    admin = user(session, "admin")
    custom = add_custom_source(session, feed(), admin.id, NOW, resolve_public)
    thn = by_code(session, "thn")
    for source in (custom, thn):
        with pytest.raises(SourceRuleError, match="N1"):
            set_trust_tier(session, source.id, "N1", admin.id, NOW)
    with pytest.raises(SourceRuleError, match="desconocido"):
        set_trust_tier(session, custom.id, "N9", admin.id, NOW)
    set_trust_tier(session, custom.id, "N3", admin.id, NOW)
    set_trust_tier(session, custom.id, "N3", admin.id, NOW)  # no change, no second audit row
    assert by_code(session, "my_feed").trust_tier == "N3"
    changes = session.scalars(select(m.AuditLog).where(m.AuditLog.action == "source.trust_tier")).all()
    assert len(changes) == 1
    assert changes[0].before == {"trust_tier": "N4"}
    assert changes[0].after == {"trust_tier": "N3"}
    assert set_trust_tier(session, by_code(session, "nvd").id, "N1", admin.id, NOW).trust_tier == "N1"
