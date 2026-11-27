"""Which CISA entries without an NVD record the refresh looks up by id (F15.8, feature review)."""

from __future__ import annotations

from datetime import date, timedelta

from core.pipeline.wiring import KEV_RECENT_DAYS, lookup_order

TODAY = date(2026, 11, 27)


def test_recent_entries_go_first_newest_first() -> None:
    pending = [
        ("CVE-2020-0001", date(2025, 1, 1)),
        ("CVE-2026-0002", TODAY - timedelta(days=1)),
        ("CVE-2026-0003", TODAY),
    ]
    assert lookup_order(pending, TODAY, 2) == ["CVE-2026-0003", "CVE-2026-0002"]


def test_older_entries_are_never_excluded_and_rotate_day_by_day() -> None:
    old = TODAY - timedelta(days=KEV_RECENT_DAYS + 1)
    pending = [(f"CVE-2020-{n:04d}", old) for n in range(1, 8)]
    days = [TODAY + timedelta(days=d) for d in range(3)]
    picked = [lookup_order(pending, day, 3) for day in days]
    assert all(len(p) == 3 for p in picked)
    assert {cve for p in picked for cve in p} == {cve for cve, _ in pending}  # 7 entries, 3 a day: all in 3 days
    assert picked[0] != picked[1]


def test_nothing_pending_asks_nothing() -> None:
    assert lookup_order([], TODAY, 20) == []
