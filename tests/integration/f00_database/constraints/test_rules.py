"""Rules of data model v1 §10, derived views (§11) and roles (§17), on the migrated database.

Ported from the capa 2 validation (docs/datos/validacion/tests).

Tests named test_gap_* document a problem found by the validation: they assert the CURRENT
behaviour of model v1 so the report can cite them; each one maps to an adjustment in informe.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import psycopg
import pytest
from dbsupport import Builder, check_deferred
from psycopg import errors, sql

pytestmark = pytest.mark.integration

Conn = psycopg.Connection[Any]
T0 = datetime(2026, 11, 1, tzinfo=UTC)


def raises(exc: type[Exception], conn: Conn, fn: Any, *args: Any, **kw: Any) -> None:
    """Assert exc inside a savepoint so the test transaction stays usable."""
    with pytest.raises(exc), conn.transaction():
        fn(*args, **kw)
        check_deferred(conn)


# ---------------------------------------------------------------- configuration and formula


def test_company_profile_single_row(build: Builder, conn: Conn) -> None:
    build.insert("company_profile")
    raises(errors.CheckViolation, conn, build.insert, "company_profile", id=2)


def test_one_active_formula_version(build: Builder, conn: Conn) -> None:
    build.insert("formula_version", status="active")
    raises(errors.UniqueViolation, conn, build.insert, "formula_version", status="active")


def five_weights(build: Builder, version: Any, weights: dict[str, str]) -> None:
    for factor, w in weights.items():
        build.insert("formula_weight", formula_version_id=version, factor=factor, weight=w)


def test_weights_sum_to_one_accepted(build: Builder, conn: Conn) -> None:
    v = build.insert("formula_version")["id"]
    five_weights(build, v, {"S": "0.25", "P": "0.30", "T": "0.20", "A": "0.15", "D": "0.10"})
    check_deferred(conn)


def test_weights_not_summing_to_one_rejected(build: Builder, conn: Conn) -> None:
    v = build.insert("formula_version")["id"]
    raises(
        errors.CheckViolation,
        conn,
        five_weights,
        build,
        v,
        {"S": "0.25", "P": "0.30", "T": "0.20", "A": "0.15", "D": "0.15"},
    )


def levels(build: Builder, version: Any, factor: str, rows: list[tuple[str, int, str]]) -> None:
    for code, rank, value in rows:
        build.insert(
            "formula_level", formula_version_id=version, factor=factor, level_code=code, rank=rank, value=value
        )


def test_monotone_levels_accepted_and_bonus_skipped(build: Builder, conn: Conn) -> None:
    v = build.insert("formula_version")["id"]
    levels(
        build,
        v,
        "D",
        [("highly_classified", 1, "0.8"), ("classified", 2, "0.5"), ("unclassified", 3, "0.5"), ("public", 4, "0.1")],
    )
    build.insert(
        "formula_level",
        formula_version_id=v,
        factor="D",
        level_code="personal_data_bonus",
        rank=5,
        value="0.2",
        is_bonus=True,
    )
    check_deferred(conn)


def test_non_monotone_levels_rejected(build: Builder, conn: Conn) -> None:
    v = build.insert("formula_version")["id"]
    raises(
        errors.CheckViolation,
        conn,
        levels,
        build,
        v,
        "P",
        [("kev_or_exploited", 1, "1.0"), ("poc", 2, "0.4"), ("epss_p90", 3, "0.5")],
    )


def test_urgency_bands_must_decrease(build: Builder, conn: Conn) -> None:
    v = build.insert("formula_version")["id"]

    def bands(scores: list[int]) -> None:
        for urgency, score in enumerate(scores, start=1):
            build.insert("formula_urgency_band", formula_version_id=v, urgency=urgency, min_score=score)

    raises(errors.CheckViolation, conn, bands, [90, 75, 80, 0])
    bands([90, 75, 50, 0])
    check_deferred(conn)


def test_reason_range_min_le_max(build: Builder, conn: Conn) -> None:
    raises(errors.CheckViolation, conn, build.insert, "formula_reason_range", min_points=5, max_points=2)


def test_setting_value_unique_version(build: Builder, conn: Conn) -> None:
    key = build.insert("setting_definition")["key"]
    build.insert("setting_value", setting_key=key, version=1)
    raises(errors.UniqueViolation, conn, build.insert, "setting_value", setting_key=key, version=1)


def test_judge_reason_type_asset_flag(build: Builder, conn: Conn) -> None:
    raises(
        errors.CheckViolation, conn, build.insert, "judge_reason_type", code="mass_exploitation", applies_to_asset=True
    )
    raises(
        errors.CheckViolation,
        conn,
        build.insert,
        "judge_reason_type",
        code="more_critical_asset",
        applies_to_asset=False,
    )


# ---------------------------------------------------------------- context, inventory, knowledge


def test_single_default_team_and_primary_sector(build: Builder, conn: Conn) -> None:
    build.insert("team", is_default=True)
    raises(errors.UniqueViolation, conn, build.insert, "team", is_default=True)
    build.insert("profile_sector", is_primary=True)
    raises(errors.UniqueViolation, conn, build.insert, "profile_sector", is_primary=True)


@pytest.mark.parametrize("table", ["actor_alias", "peer_company_alias"])
def test_aliases_unique_after_normalization(build: Builder, conn: Conn, table: str) -> None:
    build.insert(table, alias="Lázarus  Group")
    raises(errors.UniqueViolation, conn, build.insert, table, alias=" lazarus group")


def test_verified_relationship_unique_normalized(build: Builder, conn: Conn) -> None:
    build.insert("verified_relationship", subject="OpenSSL", relationship_type="fork", object="LibreSSL")
    raises(
        errors.UniqueViolation,
        conn,
        build.insert,
        "verified_relationship",
        subject="openssl",
        relationship_type="FORK",
        object="libressl ",
    )


def test_cpe_mapping_needs_a_pair(build: Builder, conn: Conn) -> None:
    raises(errors.CheckViolation, conn, build.insert, "cpe_mapping", nvd_vendor=None, nvd_product=None)
    build.insert("cpe_mapping", nvd_vendor=None, nvd_product=None, cna_vendor="v", cna_product="p")


def test_cpe_mapping_pairs_complete(build: Builder, conn: Conn) -> None:
    """A-6: a product without its vendor is rejected."""
    raises(
        errors.CheckViolation,
        conn,
        build.insert,
        "cpe_mapping",
        nvd_vendor=None,
        nvd_product="openssl",
        cna_vendor="v",
        cna_product="p",
    )


@pytest.mark.parametrize("bad", ["CVE-26-1234", "cve-2026-1234", "CVE-2026-123", "CVE-2026-12345 "])
def test_cve_id_format(build: Builder, conn: Conn, bad: str) -> None:
    raises(errors.CheckViolation, conn, build.insert, "cve", id=bad)


def test_cve_reference_unique_url(build: Builder, conn: Conn) -> None:
    ref = build.insert("cve_reference", url="https://x.example/a")
    raises(errors.UniqueViolation, conn, build.insert, "cve_reference", cve_id=ref["cve_id"], url="https://x.example/a")


def test_ioc_unique_type_value_source(build: Builder, conn: Conn) -> None:
    ioc = build.insert("ioc", ioc_type="domain", value="evil.example")
    raises(
        errors.UniqueViolation,
        conn,
        build.insert,
        "ioc",
        ioc_type="domain",
        value="evil.example",
        source_id=ioc["source_id"],
    )


# ---------------------------------------------------------------- detection


def test_single_running_scan(build: Builder, conn: Conn) -> None:
    build.insert("run", kind="scan", status="running")
    build.insert("run", kind="news", status="running")
    raises(errors.UniqueViolation, conn, build.insert, "run", kind="scan", status="running")


def test_finding_group_unique(build: Builder, conn: Conn) -> None:
    g = build.insert("finding_group")
    raises(
        errors.UniqueViolation,
        conn,
        build.insert,
        "finding_group",
        cve_id=g["cve_id"],
        software_product_id=g["software_product_id"],
    )


def test_finding_instance_must_match_group_product(build: Builder, conn: Conn) -> None:
    group = build.insert("finding_group")
    other_instance = build.insert("installed_software")
    raises(
        errors.CheckViolation,
        conn,
        build.insert,
        "finding",
        finding_group_id=group["id"],
        installed_software_id=other_instance["id"],
    )


def test_instance_product_locked_once_it_has_findings(build: Builder, conn: Conn) -> None:
    f = build.insert("finding")
    other_product = build.insert("software_product")["id"]
    raises(
        errors.CheckViolation,
        conn,
        conn.execute,
        "UPDATE installed_software SET software_product_id = %s WHERE id = %s",
        (other_product, f["installed_software_id"]),
    )


def test_single_active_suppression(build: Builder, conn: Conn) -> None:
    s = build.insert("suppression")
    raises(errors.UniqueViolation, conn, build.insert, "suppression", finding_id=s["finding_id"])
    conn.execute("UPDATE suppression SET lifted_at = now() WHERE id = %s", (s["id"],))
    build.insert("suppression", finding_id=s["finding_id"])


# ---------------------------------------------------------------- correlation, judge, scoring


def test_correlation_unique(build: Builder, conn: Conn) -> None:
    c = build.insert("correlation")
    raises(
        errors.UniqueViolation,
        conn,
        build.insert,
        "correlation",
        finding_group_id=c["finding_group_id"],
        story_id=c["story_id"],
        match_type=c["match_type"],
    )


def test_inferred_alert_needs_review_and_relationship(build: Builder, conn: Conn) -> None:
    raises(errors.CheckViolation, conn, build.insert, "alert", relevance="inferred")
    review = build.insert("llm_review")["id"]
    build.insert("alert", relevance="inferred", llm_review_id=review, relationship_type="fork")


@pytest.mark.parametrize(
    ("kind", "ref"), [("finding", "alert_id"), ("alert", "story_id"), ("dismissal", "finding_group_id")]
)
def test_review_package_reference_by_kind(build: Builder, conn: Conn, kind: str, ref: str) -> None:
    target = {"alert_id": "alert", "story_id": "story", "finding_group_id": "finding_group"}[ref]
    raises(errors.CheckViolation, conn, build.insert, "review_package", kind=kind, **{ref: build.insert(target)["id"]})


def test_judge_reason_asset_iff_more_critical(build: Builder, conn: Conn) -> None:
    mca = build.insert("judge_reason_type", code="more_critical_asset", applies_to_asset=True)["code"]
    raises(errors.CheckViolation, conn, build.insert, "judge_reason", reason_code=mca)
    asset = build.insert("asset")["id"]
    raises(errors.CheckViolation, conn, build.insert, "judge_reason", asset_id=asset)
    r = build.insert("judge_reason", reason_code=mca, asset_id=asset)
    raises(errors.UniqueViolation, conn, build.insert, "judge_reason", llm_review_id=r["llm_review_id"], seq=r["seq"])


def test_assessment_exclusive_arc(build: Builder, conn: Conn) -> None:
    group = build.insert("finding_group")["id"]
    alert = build.insert("alert")["id"]
    raises(errors.CheckViolation, conn, build.insert, "assessment", finding_group_id=group, alert_id=alert)
    raises(errors.CheckViolation, conn, build.insert, "assessment", finding_group_id=None, alert_id=None)


def test_error_queue_exactly_one_reference(build: Builder, conn: Conn) -> None:
    story = build.insert("story")["id"]
    cve = build.insert("cve")["id"]
    raises(errors.CheckViolation, conn, build.insert, "error_queue", story_id=story, cve_id=cve)


# ---------------------------------------------------------------- tickets, notifications, feedback


def test_ticket_unique_per_group_and_custodian(build: Builder, conn: Conn) -> None:
    t = build.insert("ticket")
    raises(
        errors.UniqueViolation,
        conn,
        build.insert,
        "ticket",
        finding_group_id=t["finding_group_id"],
        custodian_team_id=t["custodian_team_id"],
    )


def test_finding_in_one_open_ticket(build: Builder, conn: Conn) -> None:
    tf = build.insert("ticket_finding")
    raises(errors.UniqueViolation, conn, build.insert, "ticket_finding", finding_id=tf["finding_id"])
    conn.execute("UPDATE ticket_finding SET removed_at = now(), removal_reason = 'moved' WHERE id = %s", (tf["id"],))
    build.insert("ticket_finding", finding_id=tf["finding_id"])


def test_ticket_finding_group_must_match(build: Builder, conn: Conn) -> None:
    """A-5: a finding of group G1 cannot be linked to a ticket of group G2, and links lock both groups."""
    ticket = build.insert("ticket")
    finding = build.insert("finding")
    raises(
        errors.CheckViolation, conn, build.insert, "ticket_finding", ticket_id=ticket["id"], finding_id=finding["id"]
    )
    same = build.insert(
        "ticket",
        finding_group_id=conn.execute(
            "SELECT finding_group_id FROM finding WHERE id = %s", (finding["id"],)
        ).fetchone()[0],
    )  # type: ignore[index]
    build.insert("ticket_finding", ticket_id=same["id"], finding_id=finding["id"])
    raises(
        errors.CheckViolation,
        conn,
        conn.execute,
        "UPDATE ticket SET finding_group_id = %s WHERE id = %s",
        (ticket["finding_group_id"], same["id"]),
    )


@pytest.mark.parametrize(
    ("table", "values"),
    [
        ("ticket", {"status": "closed", "itop_ticket_id": "x-1"}),
        ("ticket", {"status": "open"}),
        ("ticket", {"status": "resolved", "itop_ticket_id": "x-2"}),
        ("itop_outbox", {"status": "done"}),
        ("notification_event", {"status": "delivered"}),
    ],
)
def test_state_and_date_consistency(build: Builder, conn: Conn, table: str, values: dict[str, Any]) -> None:
    """A-7: a closed/resolved ticket, done outbox or delivered event without its date is rejected."""
    vals = build.values(table)
    vals.update(values)
    for col in ("closed_at", "resolved_at", "done_at", "delivered_at", "itop_ticket_id"):
        if col in vals and col not in values:
            vals[col] = None
    raises(errors.CheckViolation, conn, build.insert_values, table, vals)


def test_outbox_idempotency(build: Builder, conn: Conn) -> None:
    o = build.insert("itop_outbox")
    raises(errors.UniqueViolation, conn, build.insert, "itop_outbox", idempotency_key=o["idempotency_key"])
    raises(errors.UniqueViolation, conn, build.insert, "itop_outbox", ticket_update_id=o["ticket_update_id"])


def test_single_current_feedback(build: Builder, conn: Conn) -> None:
    f = build.insert("feedback")
    raises(
        errors.UniqueViolation,
        conn,
        build.insert,
        "feedback",
        assessment_id=f["assessment_id"],
        app_user_id=f["app_user_id"],
    )
    conn.execute("UPDATE feedback SET superseded_at = now() WHERE id = %s", (f["id"],))
    build.insert("feedback", assessment_id=f["assessment_id"], app_user_id=f["app_user_id"])


# ---------------------------------------------------------------- views


def test_setting_current_default_and_latest(build: Builder, conn: Conn) -> None:
    d = build.insert("setting_definition", default_value=psycopg.types.json.Jsonb(4))
    row = conn.execute("SELECT value, is_default FROM setting_current WHERE setting_key = %s", (d["key"],)).fetchone()
    assert row == (4, True)
    for v, val in [(1, 6), (2, 2)]:
        build.insert("setting_value", setting_key=d["key"], version=v, value=psycopg.types.json.Jsonb(val))
    row = conn.execute("SELECT value, version FROM setting_current WHERE setting_key = %s", (d["key"],)).fetchone()
    assert row == (2, 2)


def status_change(build: Builder, finding: Any, status: str, at: datetime, version: str = "1.0") -> None:
    build.insert("finding_status_change", finding_id=finding, status=status, changed_at=at, observed_version=version)


def test_finding_current(build: Builder, conn: Conn) -> None:
    f = build.insert("finding")["id"]
    status_change(build, f, "new", T0)
    status_change(build, f, "persistent", T0 + timedelta(days=1))
    status_change(build, f, "fixed", T0 + timedelta(days=2), "1.1")
    row = conn.execute(
        "SELECT status, detected_at, fixed_at, observed_version FROM finding_current WHERE finding_id = %s", (f,)
    ).fetchone()
    assert row == ("fixed", T0, T0 + timedelta(days=2), "1.1")


@dataclass(frozen=True)
class Score:
    kev: bool
    exposed: bool
    base: int
    judge: int
    final: int


def score_setup(build: Builder, score: Score) -> dict[str, Any]:
    v = build.insert("formula_version", kev_exposed_floor=90)["id"]
    for urgency, band_min in enumerate([90, 75, 50, 0], start=1):
        build.insert("formula_urgency_band", formula_version_id=v, urgency=urgency, min_score=band_min)
    a = build.insert(
        "assessment",
        formula_version_id=v,
        raw_in_kev=score.kev,
        judge_adjustment=score.judge,
        factor_s=Decimal("0.9800"),
    )
    asset = build.insert("asset")["id"]
    build.insert(
        "asset_score",
        assessment_id=a["id"],
        asset_id=asset,
        base=score.base,
        ci_adjustment=0,
        final=score.final,
        snap_exposed=score.exposed,
    )
    return {"assessment": a, "asset": asset}


def test_asset_score_detail_floor_case_from_docs_06(build: Builder, conn: Conn) -> None:
    """docs/06 §8: KEV + exposed CI, base 70, judge -15 → final 90 (floor) and suggestion 55."""
    s = score_setup(build, Score(kev=True, exposed=True, base=70, judge=-15, final=90))
    row = conn.execute(
        "SELECT urgency, level, floor_applied, blocked_suggestion, raw_value "
        "FROM asset_score_detail WHERE assessment_id = %s",
        (s["assessment"]["id"],),
    ).fetchone()
    assert row == (1, "critical", True, 55, 98)


def test_asset_score_detail_no_floor(build: Builder, conn: Conn) -> None:
    s = score_setup(build, Score(kev=False, exposed=True, base=70, judge=-15, final=55))
    row = conn.execute(
        "SELECT urgency, floor_applied, blocked_suggestion FROM asset_score_detail WHERE assessment_id = %s",
        (s["assessment"]["id"],),
    ).fetchone()
    assert row == (3, False, None)


def test_ticket_score_uses_current_cis_of_latest_assessment(build: Builder, conn: Conn) -> None:
    inst_a = build.insert("installed_software")
    inst_b = build.insert("installed_software", software_product_id=inst_a["software_product_id"])
    group = build.insert("finding_group", software_product_id=inst_a["software_product_id"])["id"]
    fa = build.insert("finding", finding_group_id=group, installed_software_id=inst_a["id"])["id"]
    fb = build.insert("finding", finding_group_id=group, installed_software_id=inst_b["id"])["id"]
    status_change(build, fa, "new", T0)
    status_change(build, fb, "new", T0)
    ticket = build.insert("ticket", finding_group_id=group)["id"]
    for f in (fa, fb):
        build.insert("ticket_finding", ticket_id=ticket, finding_id=f)
    old = build.insert("assessment", finding_group_id=group, assessed_at=T0)["id"]
    new = build.insert("assessment", finding_group_id=group, assessed_at=T0 + timedelta(hours=1))["id"]
    build.insert("asset_score", assessment_id=old, asset_id=inst_a["asset_id"], base=99, ci_adjustment=0, final=99)
    build.insert("asset_score", assessment_id=new, asset_id=inst_a["asset_id"], base=80, ci_adjustment=0, final=80)
    build.insert("asset_score", assessment_id=new, asset_id=inst_b["asset_id"], base=60, ci_adjustment=0, final=60)
    assert conn.execute(
        "SELECT score, driving_asset_id FROM ticket_score WHERE ticket_id = %s", (ticket,)
    ).fetchone() == (80, inst_a["asset_id"])
    status_change(build, fa, "fixed", T0 + timedelta(days=1))  # EVA-08: the driving CI is fixed
    assert conn.execute(
        "SELECT score, driving_asset_id FROM ticket_score WHERE ticket_id = %s", (ticket,)
    ).fetchone() == (60, inst_b["asset_id"])


def test_finding_group_status(build: Builder, conn: Conn) -> None:
    f = build.insert("finding")
    group = conn.execute("SELECT finding_group_id FROM finding WHERE id = %s", (f["id"],)).fetchone()[0]  # type: ignore[index]

    def status() -> str:
        return conn.execute("SELECT status FROM finding_group_status WHERE finding_group_id = %s", (group,)).fetchone()[
            0
        ]  # type: ignore[index,no-any-return]

    status_change(build, f["id"], "new", T0)
    assert status() == "active"
    sup = build.insert("suppression", finding_id=f["id"])
    assert status() == "suppressed"
    conn.execute("UPDATE suppression SET lifted_at = now() WHERE id = %s", (sup["id"],))
    status_change(build, f["id"], "fixed", T0 + timedelta(days=1))
    assert status() == "fixed"
    build.insert("ticket", finding_group_id=group, status="closed")
    assert status() == "closed"


def test_inventory_issue_and_ladder_default(build: Builder, conn: Conn) -> None:
    product = build.insert("software_product")["id"]
    asset = build.insert("asset", confidentiality="unclassified")["id"]
    issues = {
        r[0]
        for r in conn.execute(
            "SELECT issue FROM inventory_issue WHERE asset_id = %s OR software_product_id = %s", (asset, product)
        )
    }
    assert issues == {"software_unmapped", "exposure_unknown", "unclassified", "owner_missing", "custodian_missing"}
    assert conn.execute("SELECT level FROM judge_ladder_current").fetchone() == (0,)


def test_source_health_consecutive_failures(build: Builder, conn: Conn) -> None:
    src = build.insert("source")["id"]
    for i, st in enumerate(["ok", "error", "error"]):
        build.insert(
            "source_fetch",
            source_id=src,
            status=st,
            started_at=T0 + timedelta(hours=i),
            finished_at=T0 + timedelta(hours=i),
        )
    assert conn.execute(
        "SELECT last_ok_at, consecutive_failures FROM source_health WHERE source_id = %s", (src,)
    ).fetchone() == (T0, 2)


def test_all_views_query(conn: Conn) -> None:
    for (view,) in conn.execute("SELECT viewname FROM pg_views WHERE schemaname = 'public'").fetchall():
        conn.execute(sql.SQL("SELECT * FROM {} LIMIT 1").format(sql.Identifier(view)))


# ---------------------------------------------------------------- roles


@pytest.mark.parametrize("table", ["audit_log", "finding_status_change", "assessment", "asset_score", "judge_reason"])
def test_app_cannot_update_append_only(build: Builder, conn: Conn, table: str) -> None:
    build.insert(table)
    col = build.catalog[table].pk[0]
    conn.execute("SET LOCAL ROLE app")
    update = sql.SQL("UPDATE {t} SET {c} = {c}").format(t=sql.Identifier(table), c=sql.Identifier(col))
    raises(errors.InsufficientPrivilege, conn, conn.execute, update)
    raises(errors.InsufficientPrivilege, conn, conn.execute, sql.SQL("DELETE FROM {}").format(sql.Identifier(table)))


def test_app_can_write_domain_tables(build: Builder, conn: Conn) -> None:
    vals = build.values("audit_log")
    conn.execute("SET LOCAL ROLE app")
    build.insert_values("audit_log", vals)


def test_app_cannot_update_llm_review(build: Builder, conn: Conn) -> None:
    """A-2: llm_review stays append-only; a queued review is stored again as a new row when it runs."""
    r = build.insert("llm_review", status="queued")
    conn.execute("SET LOCAL ROLE app")
    raises(
        errors.InsufficientPrivilege,
        conn,
        conn.execute,
        "UPDATE llm_review SET status = 'applied' WHERE id = %s",
        (r["id"],),
    )


def test_retention_has_no_direct_writes(build: Builder, conn: Conn) -> None:
    art = build.insert("raw_article", clean_text="body")
    conn.execute("SET LOCAL ROLE retention")
    raises(
        errors.InsufficientPrivilege,
        conn,
        conn.execute,
        "UPDATE raw_article SET clean_text = NULL WHERE id = %s",
        (art["id"],),
    )
    raises(errors.InsufficientPrivilege, conn, conn.execute, "DELETE FROM notification_event")


def test_retention_purges_only_eligible_rows(build: Builder, conn: Conn) -> None:
    old = datetime.now(UTC) - timedelta(days=400)
    art_old = build.insert("raw_article", clean_text="body", captured_at=old)["id"]
    art_new = build.insert("raw_article", clean_text="body")["id"]
    delivered_old = build.insert("notification_event", status="delivered", delivered_at=old)["id"]
    delivered_new = build.insert("notification_event", status="delivered", delivered_at=datetime.now(UTC))["id"]
    pending_old = build.insert("notification_event", status="pending", created_at=old)["id"]
    done_old = build.insert("itop_outbox", status="done", done_at=old)["id"]
    pending_outbox = build.insert("itop_outbox", status="pending", created_at=old)["id"]
    conn.execute("SET LOCAL ROLE retention")
    conn.execute("SELECT * FROM purge_retention()")
    conn.execute("RESET ROLE")
    texts = dict(
        conn.execute("SELECT id, clean_text FROM raw_article WHERE id = ANY(%s)", ([art_old, art_new],)).fetchall()
    )
    assert texts == {art_old: None, art_new: "body"}
    events = {
        r[0]
        for r in conn.execute(
            "SELECT id FROM notification_event WHERE id = ANY(%s)", ([delivered_old, delivered_new, pending_old],)
        )
    }
    assert events == {delivered_new, pending_old}
    outbox = {
        r[0] for r in conn.execute("SELECT id FROM itop_outbox WHERE id = ANY(%s)", ([done_old, pending_outbox],))
    }
    assert outbox == {pending_outbox}


def test_retention_deletes_reviewed_package(build: Builder, conn: Conn) -> None:
    """A-1: the purge deletes an old package; its review stays with review_package_id NULL."""
    pkg = build.insert("review_package", built_at=datetime.now(UTC) - timedelta(days=400))["id"]
    review = build.insert("llm_review", review_package_id=pkg)["id"]
    build.insert("error_queue", review_package_id=pkg, status="gave_up")
    conn.execute("SET LOCAL ROLE retention")
    conn.execute("SELECT * FROM purge_retention()")
    conn.execute("RESET ROLE")
    assert conn.execute("SELECT count(*) FROM review_package WHERE id = %s", (pkg,)).fetchone() == (0,)
    assert conn.execute("SELECT review_package_id FROM llm_review WHERE id = %s", (review,)).fetchone() == (None,)


def test_uuidv7_default(conn: Conn) -> None:
    """A-4: primary keys default to uuidv7()."""
    row = conn.execute(
        "INSERT INTO actor (name) VALUES ('default-id') RETURNING id, uuid_extract_version(id)"
    ).fetchone()
    assert row is not None and row[1] == 7


# ---------------------------------------------------------------- review round 1 (Codex) regressions


def test_moving_a_weight_rechecks_the_source_version(build: Builder, conn: Conn) -> None:
    v1 = build.insert("formula_version")["id"]
    v2 = build.insert("formula_version")["id"]
    five_weights(build, v1, {"S": "0.6", "P": "0.4"})
    check_deferred(conn)

    def move() -> None:
        conn.execute(
            "UPDATE formula_weight SET formula_version_id = %s WHERE formula_version_id = %s AND factor = 'P'", (v2, v1)
        )
        build.insert("formula_weight", formula_version_id=v2, factor="S", weight="0.6")

    raises(errors.CheckViolation, conn, move)


def test_group_product_locked_once_it_has_findings(build: Builder, conn: Conn) -> None:
    f = build.insert("finding")
    other_product = build.insert("software_product")["id"]
    raises(
        errors.CheckViolation,
        conn,
        conn.execute,
        "UPDATE finding_group SET software_product_id = %s WHERE id = %s",
        (other_product, f["finding_group_id"]),
    )


def test_concurrent_product_change_waits_for_new_finding(catalog: Any, dsn: str) -> None:
    """A finding insert in flight blocks a concurrent product change of its instance (FOR SHARE)."""
    with psycopg.connect(dsn, autocommit=True) as setup:
        b = Builder(setup, catalog)
        inst = b.insert("installed_software")
        group = b.insert("finding_group", software_product_id=inst["software_product_id"])
        other = b.insert("software_product")["id"]
        try:
            with psycopg.connect(dsn) as tx_b, psycopg.connect(dsn) as tx_a:
                Builder(tx_b, catalog).insert("finding", finding_group_id=group["id"], installed_software_id=inst["id"])
                tx_a.execute("SET lock_timeout = '500ms'")
                with pytest.raises(errors.LockNotAvailable):
                    tx_a.execute(
                        "UPDATE installed_software SET software_product_id = %s WHERE id = %s", (other, inst["id"])
                    )
                tx_a.rollback()
                tx_b.rollback()
        finally:
            setup.execute("DELETE FROM finding_group WHERE id = %s", (group["id"],))
            setup.execute("DELETE FROM installed_software WHERE id = %s", (inst["id"],))


def test_every_foreign_key_has_a_full_index(conn: Conn) -> None:
    missing = conn.execute("""
        SELECT c.conrelid::regclass || '.' || a.attname
        FROM pg_constraint c JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
        WHERE c.contype = 'f' AND c.connamespace = 'public'::regnamespace
          AND NOT EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.conrelid AND i.indkey[0] = c.conkey[1]
                          AND i.indpred IS NULL AND i.indexprs IS NULL)""").fetchall()
    assert missing == []


def test_proposed_adjustment_is_reconstructible(build: Builder, conn: Conn) -> None:
    """A-8: proposed adjustment = accepted group-level reasons (more_critical_asset applies to one CI)."""
    review = build.insert("llm_review", proposed_adjustment=12)["id"]
    up = build.insert("judge_reason_type", code="mass_exploitation")["code"]
    mca = build.insert("judge_reason_type", code="more_critical_asset", applies_to_asset=True)["code"]
    asset = build.insert("asset")["id"]
    for seq, (code, pts, st, a) in enumerate(
        [
            (up, 12, "accepted", None),
            (up, 8, "rejected", None),
            (up, 5, "withdrawn", None),
            (mca, 6, "accepted", asset),
        ],
        start=1,
    ):
        build.insert("judge_reason", llm_review_id=review, seq=seq, reason_code=code, points=pts, status=st, asset_id=a)
    derived = conn.execute(
        "SELECT COALESCE(sum(points), 0) FROM judge_reason "
        "WHERE llm_review_id = %s AND status = 'accepted' AND reason_code <> 'more_critical_asset'",
        (review,),
    ).fetchone()[0]  # type: ignore[index]
    assert derived == 12


# ---------------------------------------------------------------- review round 2 (Codex) regressions


def test_purge_keeps_pending_package_and_purges_the_rest(build: Builder, conn: Conn) -> None:
    old = datetime.now(UTC) - timedelta(days=400)
    kept = build.insert("review_package", built_at=old)["id"]
    build.insert("error_queue", review_package_id=kept, status="pending")
    gone = build.insert("review_package", built_at=old)["id"]
    event = build.insert("notification_event", status="delivered", delivered_at=old)["id"]
    conn.execute("SET LOCAL ROLE retention")
    conn.execute("SELECT * FROM purge_retention()")
    conn.execute("RESET ROLE")
    left = {r[0] for r in conn.execute("SELECT id FROM review_package WHERE id = ANY(%s)", ([kept, gone],))}
    assert left == {kept}
    assert conn.execute("SELECT count(*) FROM notification_event WHERE id = %s", (event,)).fetchone() == (0,)


def test_empty_version_cannot_be_activated(build: Builder, conn: Conn) -> None:
    raises(errors.CheckViolation, conn, build.insert, "formula_version", status="active")


def test_active_version_cannot_lose_its_weights(build: Builder, conn: Conn) -> None:
    v = build.insert("formula_version", status="draft")["id"]
    five_weights(build, v, {"S": "0.25", "P": "0.30", "T": "0.20", "A": "0.15", "D": "0.10"})
    conn.execute("UPDATE formula_version SET status = 'active' WHERE id = %s", (v,))
    check_deferred(conn)
    raises(errors.CheckViolation, conn, conn.execute, "DELETE FROM formula_weight WHERE formula_version_id = %s", (v,))


def test_concurrent_level_writes_serialize(catalog: Any, dsn: str) -> None:
    """Two transactions writing levels of the same version wait for each other (row lock on the version)."""
    with psycopg.connect(dsn, autocommit=True) as setup:
        v = Builder(setup, catalog).insert("formula_version")["id"]
        try:
            with psycopg.connect(dsn) as tx_a, psycopg.connect(dsn) as tx_b:
                Builder(tx_a, catalog).insert(
                    "formula_level", formula_version_id=v, factor="P", level_code="poc", rank=2, value="0.75"
                )
                tx_b.execute("SET lock_timeout = '500ms'")
                with pytest.raises(errors.LockNotAvailable):
                    Builder(tx_b, catalog).insert(
                        "formula_level", formula_version_id=v, factor="P", level_code="epss", rank=3, value="0.9"
                    )
                tx_b.rollback()
                tx_a.rollback()
        finally:
            setup.execute("DELETE FROM formula_version WHERE id = %s", (v,))


def test_suppression_has_exactly_one_author(build: Builder, conn: Conn) -> None:
    """A-13: the author comes from the feedback or from created_by, never both and never neither."""
    fb = build.insert("feedback")
    user = build.insert("app_user")["id"]
    raises(errors.CheckViolation, conn, build.insert, "suppression", feedback_id=fb["id"], created_by=user)
    raises(errors.CheckViolation, conn, build.insert, "suppression", feedback_id=None, created_by=None)
    build.insert("suppression", feedback_id=fb["id"], created_by=None)


# ---------------------------------------------------------------- review round 3 (Codex) regressions


def test_active_version_needs_all_five_factors(build: Builder, conn: Conn) -> None:
    v = build.insert("formula_version", status="draft")["id"]
    build.insert("formula_weight", formula_version_id=v, factor="S", weight="1")
    check_deferred(conn)
    raises(
        errors.CheckViolation, conn, conn.execute, "UPDATE formula_version SET status = 'active' WHERE id = %s", (v,)
    )


def test_ordinary_level_cannot_be_a_bonus(build: Builder, conn: Conn) -> None:
    raises(errors.CheckViolation, conn, build.insert, "formula_level", factor="P", level_code="poc", is_bonus=True)
    raises(
        errors.CheckViolation,
        conn,
        build.insert,
        "formula_level",
        factor="D",
        level_code="personal_data_bonus",
        is_bonus=False,
    )


@pytest.mark.parametrize("bad", ["NaN", "Infinity"])
def test_numeric_rejects_nan_and_infinity(build: Builder, conn: Conn, bad: str) -> None:
    # numeric(p,s) already refuses infinity (NumericValueOutOfRange); the CHECK covers NaN and unbounded numeric
    with pytest.raises((errors.CheckViolation, errors.NumericValueOutOfRange)), conn.transaction():
        build.insert("llm_review", cost_usd=bad)
    raises(errors.CheckViolation, conn, build.insert, "daily_metric", value=bad)


def test_concurrent_level_writes_under_repeatable_read(catalog: Any, dsn: str) -> None:
    """Two REPEATABLE READ writers of one version: the second fails instead of committing a non-monotone pair."""
    with psycopg.connect(dsn, autocommit=True) as setup:
        b = Builder(setup, catalog)
        v = b.insert("formula_version")["id"]
        b.insert("formula_level", formula_version_id=v, factor="P", level_code="kev", rank=1, value="1.0")
        try:
            with psycopg.connect(dsn) as tx_a, psycopg.connect(dsn) as tx_b:
                for tx in (tx_a, tx_b):
                    tx.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                    tx.execute(
                        "SELECT count(*) FROM formula_level WHERE formula_version_id = %s", (v,)
                    )  # take the snapshot
                Builder(tx_a, catalog).insert(
                    "formula_level", formula_version_id=v, factor="P", level_code="poc", rank=2, value="0.4"
                )
                tx_a.commit()
                with pytest.raises(errors.SerializationFailure):
                    Builder(tx_b, catalog).insert(
                        "formula_level", formula_version_id=v, factor="P", level_code="epss", rank=3, value="0.5"
                    )
                tx_b.rollback()
        finally:
            setup.execute("DELETE FROM formula_level WHERE formula_version_id = %s", (v,))
            setup.execute("DELETE FROM formula_version WHERE id = %s", (v,))


# ---------------------------------------------------------------- review round 4 (Codex) regressions


def test_bonus_only_in_factor_d(build: Builder, conn: Conn) -> None:
    raises(
        errors.CheckViolation,
        conn,
        build.insert,
        "formula_level",
        factor="P",
        level_code="personal_data_bonus",
        is_bonus=True,
    )


def test_deferred_activation_checks_final_state(build: Builder, conn: Conn) -> None:
    """Activate, supersede and drop the weights in one transaction: the final state (not active) is valid."""
    v = build.insert("formula_version", status="draft")["id"]
    five_weights(build, v, {"S": "0.25", "P": "0.30", "T": "0.20", "A": "0.15", "D": "0.10"})
    conn.execute("UPDATE formula_version SET status = 'active' WHERE id = %s", (v,))
    conn.execute("UPDATE formula_version SET status = 'superseded' WHERE id = %s", (v,))
    conn.execute("DELETE FROM formula_weight WHERE formula_version_id = %s", (v,))
    check_deferred(conn)


def _rr(conn: Conn) -> None:
    conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
    conn.execute("SELECT 1 FROM finding LIMIT 1")  # take the snapshot now


def test_rr_finding_insert_vs_product_change(catalog: Any, dsn: str) -> None:
    """REPEATABLE READ: a product change racing a committed finding insert fails instead of breaking the rule."""
    with psycopg.connect(dsn, autocommit=True) as setup:
        b = Builder(setup, catalog)
        inst = b.insert("installed_software")
        group = b.insert("finding_group", software_product_id=inst["software_product_id"])
        other = b.insert("software_product")["id"]
        try:
            with psycopg.connect(dsn) as tx_a, psycopg.connect(dsn) as tx_b:
                _rr(tx_a)
                _rr(tx_b)
                Builder(tx_a, catalog).insert("finding", finding_group_id=group["id"], installed_software_id=inst["id"])
                tx_a.commit()
                with pytest.raises(errors.SerializationFailure):
                    tx_b.execute(
                        "UPDATE installed_software SET software_product_id = %s WHERE id = %s", (other, inst["id"])
                    )
                tx_b.rollback()
        finally:
            setup.execute("DELETE FROM finding WHERE finding_group_id = %s", (group["id"],))
            setup.execute("DELETE FROM finding_group WHERE id = %s", (group["id"],))
            setup.execute("DELETE FROM installed_software WHERE id = %s", (inst["id"],))


def test_rr_ticket_link_vs_group_change(catalog: Any, dsn: str) -> None:
    """REPEATABLE READ: a ticket group change racing a committed ticket_finding insert fails."""
    with psycopg.connect(dsn, autocommit=True) as setup:
        b = Builder(setup, catalog)
        finding = b.insert("finding")
        group = setup.execute("SELECT finding_group_id FROM finding WHERE id = %s", (finding["id"],)).fetchone()[0]  # type: ignore[index]
        ticket = b.insert("ticket", finding_group_id=group)
        other_group = b.insert("finding_group")["id"]
        try:
            with psycopg.connect(dsn) as tx_a, psycopg.connect(dsn) as tx_b:
                _rr(tx_a)
                _rr(tx_b)
                Builder(tx_a, catalog).insert("ticket_finding", ticket_id=ticket["id"], finding_id=finding["id"])
                tx_a.commit()
                with pytest.raises(errors.SerializationFailure):
                    tx_b.execute("UPDATE ticket SET finding_group_id = %s WHERE id = %s", (other_group, ticket["id"]))
                tx_b.rollback()
        finally:
            setup.execute("DELETE FROM ticket_finding WHERE ticket_id = %s", (ticket["id"],))
            setup.execute("DELETE FROM ticket WHERE id = %s", (ticket["id"],))
            setup.execute("DELETE FROM finding WHERE id = %s", (finding["id"],))


# ---------------------------------------------------------------- F0.6-T3 review round 2 regressions


def test_decommissioned_asset_stops_counting_for_the_group(build: Builder, conn: Conn) -> None:
    """ARQ-03 / EVA-08: decommissioning the only CI with a current finding takes the group out of 'active'."""
    f = build.insert("finding")
    group, inst = conn.execute(
        "SELECT finding_group_id, installed_software_id FROM finding WHERE id = %s", (f["id"],)
    ).fetchone()  # type: ignore[misc]
    status_change(build, f["id"], "new", T0)

    def status() -> str:
        row = conn.execute("SELECT status FROM finding_group_status WHERE finding_group_id = %s", (group,)).fetchone()
        assert row is not None
        return str(row[0])

    assert status() == "active"
    conn.execute(
        "UPDATE asset SET decommissioned_at = now() WHERE id = (SELECT asset_id FROM installed_software WHERE id = %s)",
        (inst,),
    )
    assert status() == "fixed"
