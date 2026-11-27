"""F18.2: the admin user list (app_user joined with a fake Firebase directory) and the error queue (FRO-18)."""

from __future__ import annotations

import base64
from datetime import timedelta
from typing import Any

import pytest
from f18data import NOW, Front, f10data
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from api.auth import AuthUnavailableError, Role
from api.auth.user_list import DirectoryUser
from core.configuration.judge_estimate import JudgeEstimate
from core.db import models as m
from core.judge.catalog import SensitivityProfile

pytestmark = pytest.mark.integration


class FakeLister:
    def __init__(self, users: list[DirectoryUser], error: Exception | None = None) -> None:
        self.users, self.error = users, error

    def list_users(self) -> list[DirectoryUser]:
        if self.error is not None:
            raise self.error
        return self.users


DIRECTORY = [
    DirectoryUser("u-ana", "ana@example.test", "Ana", Role.ADMIN, False),  # claim above the stored analyst
    DirectoryUser("u-new", "beto@example.test", "Beto", Role.READER, False),  # never signed in
    DirectoryUser("u-off", "zoe@example.test", None, Role.ADMIN, True),  # disabled in Firebase
]


@pytest.fixture
def with_directory(admin: TestClient) -> Any:
    state = admin.app.state  # type: ignore[attr-defined]
    previous = state.user_lister
    state.user_lister = FakeLister(DIRECTORY)
    yield state
    state.user_lister = previous


def test_users_join_the_copy_and_the_firebase_directory(admin: TestClient, with_directory: Any) -> None:
    response = admin.get("/api/admin/users")
    assert response.status_code == 200, response.text
    body = response.json()
    by_uid = {u["uid"]: u for u in body["items"]}
    assert [u["uid"] for u in body["items"]] == ["u-ana", "u-new", "u-luis", "u-off"]  # by e-mail
    ana = by_uid["u-ana"]
    assert (ana["role"], ana["claim_role"], ana["effective_role"]) == ("analyst", "admin", "analyst")
    assert ana["signed_in"] and ana["display_name"] == "Ana Analista" and ana["active"]
    new = by_uid["u-new"]
    assert (new["role"], new["effective_role"], new["signed_in"], new["last_login_at"]) == (None, "reader", False, None)
    luis = by_uid["u-luis"]  # copy of an account gone from Firebase
    assert (luis["role"], luis["claim_role"], luis["effective_role"]) == ("analyst", None, None)
    assert luis["active"] is False  # active in Hermes but gone from Firebase (API-04)
    off = by_uid["u-off"]
    assert off["active"] is False and off["effective_role"] is None
    assert body["next_cursor"] is None


def test_users_page_with_a_signed_cursor(admin: TestClient, with_directory: Any) -> None:
    first = admin.get("/api/admin/users", params={"limit": 3}).json()
    assert len(first["items"]) == 3 and first["next_cursor"]
    payload = first["next_cursor"].split(".")[0]
    decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
    assert "@" not in decoded and "u-" not in decoded  # a position: no e-mail or uid in the URL (access logs)
    rest = admin.get("/api/admin/users", params={"limit": 3, "cursor": first["next_cursor"]}).json()
    assert [u["uid"] for u in rest["items"]] == ["u-off"] and rest["next_cursor"] is None
    other = admin.get("/api/error-queue", params={"limit": 1}).json()["next_cursor"]
    assert admin.get("/api/admin/users", params={"cursor": other}).status_code == 400


def test_users_answer_503_when_firebase_fails(admin: TestClient) -> None:
    state = admin.app.state  # type: ignore[attr-defined]
    previous = state.user_lister
    try:
        state.user_lister = FakeLister([], AuthUnavailableError())
        failed = admin.get("/api/admin/users")
        assert failed.status_code == 503 and failed.json()["error"]["code"] == "auth_unavailable"
        state.user_lister = None
        assert admin.get("/api/admin/users").status_code == 503
    finally:
        state.user_lister = previous


def test_admin_screens_need_an_admin(client: TestClient) -> None:
    assert client.get("/api/admin/users").status_code == 403
    assert client.get("/api/error-queue").status_code == 403


def test_error_queue_joins_what_exhausted_its_retries_newest_first(admin: TestClient, front: Front) -> None:
    """The failed event and the failed iTop write are listed; the scenario's LLM item still has a next attempt, so
    the next runs retry it and it stays out (PRE-01)."""
    response = admin.get("/api/error-queue")
    assert response.status_code == 200, response.text
    items = response.json()["items"]
    assert [i["kind"] for i in items] == ["notification", "itop"]
    event, write = items
    assert event["id"] == str(front.event) and event["retryable"] is True
    assert (event["status"], event["attempts"], event["error"], event["component"]) == (
        "failed",
        6,
        "Slack no respondió",
        "new_ticket",
    )
    assert (event["cve"], event["ticket_itop_id"], event["ticket_ref"]) == ("CVE-2026-10001", "777", "R-000777")
    assert event["assessment_id"] == str(front.scenario.assessments["A2"])
    assert (write["component"], write["error"], write["ticket_ref"], write["retryable"]) == (
        "update",
        "iTop respondió 500",
        "R-000777",
        False,
    )
    assert write["assessment_id"] is None  # the urgency raise has no assessment


def test_error_queue_filters_and_pages(admin: TestClient) -> None:
    only = admin.get("/api/error-queue", params={"kind": "itop"}).json()["items"]
    assert [i["kind"] for i in only] == ["itop"]
    assert admin.get("/api/error-queue", params={"kind": "llm_validation"}).json()["items"] == []
    first = admin.get("/api/error-queue", params={"limit": 1}).json()
    assert [i["kind"] for i in first["items"]] == ["notification"]
    rest = admin.get("/api/error-queue", params={"limit": 1, "cursor": first["next_cursor"]}).json()
    assert [i["kind"] for i in rest["items"]] == ["itop"] and rest["next_cursor"] is None
    assert admin.get("/api/error-queue", params={"kind": "slack"}).status_code == 422


def test_error_queue_lists_llm_items_no_run_retries_and_cuts_long_errors(
    admin: TestClient, front: Front, database: tuple[str, Engine]
) -> None:
    """PRE-01: a given-up judge item (with its package's CVE and no next attempt shown, although its writer keeps a
    date) and a pending item with no next attempt are listed; a resolved item and a delivered event are not. The
    stored error is cut to 500 characters."""
    engine = database[1]
    with Session(engine) as session, session.begin():
        package = m.ReviewPackage(
            kind="finding",
            finding_group_id=front.scenario.groups["G2"],
            fingerprint="f18-2-package",
            content={},
            built_at=NOW,
        )
        session.add(package)
        session.flush()
        session.add_all(
            [
                m.ErrorQueue(
                    component="judge",
                    review_package_id=package.id,
                    reason="judge timeout " + "x" * 700,
                    attempts=3,
                    next_attempt_at=NOW,
                    status="gave_up",
                    created_at=NOW - timedelta(minutes=5),
                ),
                m.ErrorQueue(
                    component="news_analyst",
                    cve_id="CVE-2026-10001",
                    reason="L5: la cita no aparece en la fuente",
                    attempts=2,
                    next_attempt_at=None,
                    status="pending",
                    created_at=NOW - timedelta(minutes=6),
                ),
                m.ErrorQueue(
                    component="news_analyst",
                    cve_id="CVE-2026-10001",
                    reason="resuelto",
                    attempts=1,
                    status="resolved",
                    created_at=NOW - timedelta(minutes=4),
                ),
                m.NotificationEvent(
                    contract_version="1.0",
                    event_type="fixed",
                    priority="normal",
                    payload={},
                    status="delivered",
                    attempts=1,
                    delivered_at=NOW - timedelta(minutes=2),
                    created_at=NOW - timedelta(minutes=3),
                ),
            ]
        )
        package_id = package.id
    try:
        items = admin.get("/api/error-queue", params={"kind": "llm_validation"}).json()["items"]
        assert [(i["component"], i["status"]) for i in items] == [("judge", "gave_up"), ("news_analyst", "pending")]
        judge, waiting = items
        assert judge["cve"] == "CVE-2026-10002" and judge["next_attempt_at"] is None and judge["retryable"] is False
        assert len(judge["error"]) == 500 and judge["error"].startswith("judge timeout")
        assert waiting["next_attempt_at"] is None and waiting["cve"] == "CVE-2026-10001"
        assert len(admin.get("/api/error-queue", params={"kind": "notification"}).json()["items"]) == 1
    finally:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "DELETE FROM error_queue WHERE status IN ('gave_up', 'resolved') "
                    "OR (status = 'pending' AND next_attempt_at IS NULL)"
                )
            )
            conn.execute(text("DELETE FROM notification_event WHERE status = 'delivered'"))
            conn.execute(text("DELETE FROM review_package WHERE id = :id"), {"id": package_id})


def _reason(conn: Any, review: object, seq: int, code: str, points: int) -> None:
    conn.execute(
        text(
            "INSERT INTO judge_reason (llm_review_id, seq, reason_code, points, element_id, quote, status) "
            "VALUES (:r, :s, :c, :p, 'cve', 'cita', 'accepted')"
        ),
        {"r": review, "s": seq, "c": code, "p": points},
    )


def test_the_judge_estimate_rescales_reasons_and_combines_the_blind_review(
    front: Front, database: tuple[str, Engine]
) -> None:
    """FRO-04, D-027: A2's review accepted mass_exploitation +8 (normal profile); here it also accepts
    requires_authentication -6, and its blind review accepts mass_exploitation +10. Both are rescaled and combined
    with the judge's rule: rising, at most 10 apart: the average; otherwise the base."""
    broad, minimal = SensitivityProfile.named("broad"), SensitivityProfile.named("minimal")
    engine = database[1]
    first, blind = front.reviews["first"], front.reviews["second"]
    with engine.begin() as conn:
        _reason(conn, first, 9, "requires_authentication", -6)
        _reason(conn, blind, 1, "mass_exploitation", 10)
    try:
        with Session(engine) as session:
            a2 = session.get_one(m.Assessment, front.scenario.assessments["A2"])

            def estimate(profile: SensitivityProfile | None, enabled: dict[str, bool] | None = None) -> int | None:
                return JudgeEstimate(profile, enabled or {})(session, a2)

            assert estimate(None) == 6  # first 8 - 6 = 2, blind 10: the average
            assert estimate(broad) is None  # first 12 - 9 = 3, blind 15: 12 apart, disagreement
            assert estimate(minimal) == 5  # minimal never lowers: 4 and 5, average 4.5 rounds half up
            assert estimate(broad, {"requires_authentication": False}) == 14  # 12 and 15: 13.5 rounds up
            assert estimate(None, {"mass_exploitation": False}) is None  # -6 against 0: opposite directions
            assert JudgeEstimate(None, {}, max_diff=5)(session, a2) is None  # 2 and 10 are more than 5 apart
            a1 = session.get_one(m.Assessment, front.scenario.assessments["A1"])
            assert JudgeEstimate(broad, {})(session, a1) is None  # no review: the stored base stays
            assert JudgeEstimate(broad, {})(session, None) is None
        with engine.begin() as conn:  # without its blind review, the first review alone
            conn.execute(text("UPDATE llm_review SET second_review_of_id = NULL WHERE id = :b"), {"b": blind})
        with Session(engine) as session:
            a2 = session.get_one(m.Assessment, front.scenario.assessments["A2"])
            assert JudgeEstimate(broad, {})(session, a2) == 3
        with engine.begin() as conn:  # a disagreement with no blind review left has nothing to combine
            conn.execute(text("UPDATE llm_review SET status = 'judge_disagreement' WHERE id = :r"), {"r": first})
        with Session(engine) as session:
            a2 = session.get_one(m.Assessment, front.scenario.assessments["A2"])
            assert JudgeEstimate(broad, {})(session, a2) is None
        with engine.begin() as conn:  # a fallback kept the base: nothing to estimate from
            conn.execute(text("UPDATE llm_review SET status = 'no_judge_review' WHERE id = :r"), {"r": first})
        with Session(engine) as session:
            a2 = session.get_one(m.Assessment, front.scenario.assessments["A2"])
            assert JudgeEstimate(broad, {})(session, a2) is None
    finally:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM judge_reason WHERE llm_review_id = :r AND seq = 9"), {"r": first})
            conn.execute(text("DELETE FROM judge_reason WHERE llm_review_id = :b"), {"b": blind})
            conn.execute(text("UPDATE llm_review SET status = 'applied' WHERE id = :r"), {"r": first})
            conn.execute(text("UPDATE llm_review SET second_review_of_id = :r WHERE id = :b"), {"r": first, "b": blind})


def test_a_ci_disagreement_of_the_blind_review_keeps_the_base(front: Front, database: tuple[str, Engine]) -> None:
    """D-027: both reviews agree on the group (+8 and +8), but only the first raises CI-1 (more_critical_asset +10):
    the judge keeps the base, and so does the estimate, unless that reason is switched off."""
    engine = database[1]
    first, blind = front.reviews["first"], front.reviews["second"]
    ci1 = front.scenario.assets["CI-1"]
    with engine.begin() as conn:
        _reason(conn, blind, 1, "mass_exploitation", 8)
        conn.execute(
            text(
                "INSERT INTO judge_reason (llm_review_id, seq, reason_code, points, element_id, quote, asset_id, "
                "status) VALUES (:r, 9, 'more_critical_asset', 10, 'ci', 'cita', :a, 'accepted')"
            ),
            {"r": first, "a": ci1},
        )
    try:
        with Session(engine) as session:
            a2 = session.get_one(m.Assessment, front.scenario.assessments["A2"])
            assert JudgeEstimate(None, {})(session, a2) is None
            assert JudgeEstimate(None, {"more_critical_asset": False})(session, a2) == 8
    finally:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM judge_reason WHERE llm_review_id = :r AND seq = 9"), {"r": first})
            conn.execute(text("DELETE FROM judge_reason WHERE llm_review_id = :b"), {"b": blind})


def _movers(admin: TestClient, changes: dict[str, str]) -> dict[str, tuple[int, int]]:
    """CVE en CI -> (before, after) of the simulation's top movers."""
    response = admin.post("/api/formula/simulate", json={"changes": changes})
    assert response.status_code == 200, response.text
    found = {}
    for line in response.json()["top_movers"]:
        label, _, scores = line.rpartition(": ")
        before, _, after = scores.partition(" a ")
        found[label] = (int(before), int(after))
    return found


def test_simulating_a_reason_switch_moves_the_scores_through_the_api(
    admin: TestClient, front: Front, database: tuple[str, Engine]
) -> None:
    """FRO-04 end to end: A3 (G2, CVE-2026-10002, not in KEV, so no floor) gets an applied review with
    mass_exploitation +8; switching that reason off lowers each of its open findings by 8 in the HTTP answer,
    against the same simulation with the reason on."""
    engine = database[1]
    a3 = front.scenario.assessments["A3"]
    with Session(engine) as session, session.begin():
        review = f10data.add_review(session, mitigation=False)
        session.execute(text("UPDATE assessment SET llm_review_id = :r WHERE id = :a"), {"r": review, "a": a3})
        dead_zone = session.execute(text("SELECT value FROM setting_current WHERE setting_key = 'dead_zone'")).scalar()
    try:
        unchanged = _movers(admin, {"dead_zone": str(dead_zone)})
        switched = _movers(admin, {"reasons.mass_exploitation.enabled": "false"})
        g2 = [label for label in unchanged if label.startswith("CVE-2026-10002")]
        assert g2, unchanged
        assert all(switched[label][1] == unchanged[label][1] - 8 for label in g2), (unchanged, switched)
    finally:
        with engine.begin() as conn:
            conn.execute(text("UPDATE assessment SET llm_review_id = NULL WHERE id = :a"), {"a": a3})
            conn.execute(text("DELETE FROM judge_reason WHERE llm_review_id = :r"), {"r": review})
            conn.execute(text("DELETE FROM llm_review WHERE id = :r"), {"r": review})
