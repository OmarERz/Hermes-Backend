"""Scan requests, the run list and the progress stream over the real `run` table (ARQ-04, ARQ-05)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from api.app import create_app
from api.auth import CurrentUser, Role, get_current_user
from api.routes._runs import SqlRunSource
from core.config import Settings
from core.db import models as m

pytestmark = pytest.mark.integration
SETTINGS = Settings(
    _env_file=None,
    database_url=SecretStr("postgresql://a:b@db/h"),
    firebase_project_id="p",
    cursor_signing_key=SecretStr("k" * 40),
)


def api(factory: sessionmaker[Session], uid: str = "uid-analyst") -> TestClient:
    app = create_app(SETTINGS)
    app.state.session_factory = factory
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid=uid, email="analyst@example.test", display_name=None, role=Role.ANALYST
    )
    return TestClient(app)


def test_a_scan_request_is_queued_listed_and_streamed(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        user = session.scalars(select(m.AppUser)).first()
        uid = user.firebase_uid if user is not None else "nobody"
    with api(factory, uid) as client:
        queued = client.post("/api/scans", json={})
        assert queued.status_code == 202
        run = queued.json()
        assert (run["kind"], run["status"], run["progress"]) == ("scan", "queued", 0)
        # HI-10: the answer names the person who launched it, as the list does
        launcher = (user.display_name or "Usuario sin nombre") if user is not None else None
        assert run["triggered_by"] == launcher
        assert run["id"] in [r["id"] for r in client.get("/api/runs").json()["items"]]
        with factory() as session, session.begin():
            row = session.get_one(m.Run, run["id"])
            assert row.triggered_by == (user.id if user is not None else None)
            row.status, row.progress = "succeeded", 100
        events = client.get(f"/api/runs/{run['id']}/events").text
        assert '"status": "succeeded"' in events
        assert '"message": "Terminado"' in events
        assert client.get("/api/runs/not-a-uuid/events").status_code == 422  # F12.3: run ids are UUIDs
        assert client.get("/api/runs/01936b2e-0000-7000-8000-000000000001/events").status_code == 404


def test_the_stream_follows_a_running_run_until_it_ends(factory: sessionmaker[Session]) -> None:
    with factory() as session, session.begin():
        row = m.Run(kind="nightly", status="running", progress=10, trigger_reason="schedule")
        session.add(row)
        session.flush()
        run_id = row.id
    steps = iter([("running", 60), ("running", 60), ("succeeded", 100)])

    def advance(_seconds: float) -> None:
        status, progress = next(steps)
        with factory() as session, session.begin():
            session.execute(update(m.Run).where(m.Run.id == run_id).values(status=status, progress=progress))

    source = SqlRunSource(factory, sleep=advance)
    snapshots = [(r.status, r.progress) for r in source.progress(str(run_id))]
    assert snapshots == [("running", 10), ("running", 60), ("succeeded", 100)]  # repeated states are not resent
    capped = SqlRunSource(factory, sleep=lambda _s: None, max_polls=2)
    with factory() as session, session.begin():
        session.execute(update(m.Run).where(m.Run.id == run_id).values(status="running", progress=5))
    assert [r.progress for r in capped.progress(str(run_id))] == [5]  # gives up after max_polls


def test_the_run_list_pages_in_sql_without_a_size_cap(factory: sessionmaker[Session]) -> None:
    """Not started first, then newest; every run is reachable through the cursor (pending F13.0 #79)."""
    base = datetime(2026, 11, 20, tzinfo=UTC)
    with factory() as session, session.begin():
        session.execute(update(m.Run).values(kind="inventory_sync"))  # runs of other tests stay out of the list
        for i in range(5):
            session.add(
                m.Run(
                    kind="news",
                    status="succeeded",
                    progress=100,
                    trigger_reason="schedule",
                    started_at=base + timedelta(hours=i),
                )
            )
        session.add(m.Run(kind="recalculation", status="queued", progress=0, trigger_reason="formula_change"))
    with api(factory) as client:
        seen: list[dict[str, object]] = []
        cursor = None
        while True:
            body = client.get("/api/runs", params={"limit": 2, **({"cursor": cursor} if cursor else {})}).json()
            seen += body["items"]
            cursor = body["next_cursor"]
            if cursor is None:
                break
    assert [r["kind"] for r in seen] == ["recalculation"] + ["ingestion"] * 5
    starts = [r["started_at"] for r in seen[1:]]
    assert starts == sorted(starts, reverse=True)
