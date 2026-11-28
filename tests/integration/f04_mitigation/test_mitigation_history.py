"""Mitigation and history against PostgreSQL, over the demo seed plus the data each case needs."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from core.db.seeds import seed
from core.mitigation.builder import build_mitigation
from core.mitigation.history import score_history

pytestmark = pytest.mark.integration
T0 = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)


def run(engine: Engine, statement: str, params: dict[str, Any] | None = None) -> None:
    with engine.begin() as conn:
        conn.execute(text(statement), params or {})


def one(engine: Engine, statement: str) -> Any:
    with engine.connect() as conn:
        return conn.execute(text(statement)).scalar_one()


@pytest.fixture
def demo(engine: Engine) -> Engine:
    with Session(engine) as session, session.begin():
        seed(session, "demo")
    return engine


def group_id(engine: Engine) -> uuid.UUID:
    with engine.connect() as conn:
        return conn.execute(text("SELECT id FROM finding_group ORDER BY created_at, id LIMIT 1")).scalar_one()


def test_mitigation_is_built_from_ranges_kev_workarounds_references_and_iocs(demo: Engine) -> None:
    gid = group_id(demo)
    cve = one(demo, "SELECT cve_id FROM finding_group LIMIT 1")
    run(
        demo,
        "UPDATE kev_entry SET required_action = 'Apply the vendor patch', due_date = '2026-12-10' WHERE cve_id = :c",
        {"c": cve},
    )
    run(demo, "INSERT INTO cve_workaround (cve_id, text, source) VALUES (:c, 'Disable the module', 'cna')", {"c": cve})
    for url, tag in (("https://vendor.example/patch", "Patch"), ("https://vendor.example/advisory", "Vendor Advisory")):
        run(demo, "INSERT INTO cve_reference (cve_id, url) VALUES (:c, :u)", {"c": cve, "u": url})
        run(
            demo,
            "INSERT INTO cve_reference_tag (reference_id, tag) SELECT id, :t FROM cve_reference WHERE url = :u",
            {"t": tag, "u": url},
        )
    with Session(demo) as session:
        result = build_mitigation(session, gid)
    assert result is not None and result.cve_id == cve
    assert any(step.startswith("CISA KEV exige: Apply the vendor patch") for step in result.temporal)
    assert "Alternativa publicada por el CNA: Disable the module" in result.temporal
    assert result.patch_references == ("https://vendor.example/patch",)
    assert result.advisory_references == ("https://vendor.example/advisory",)
    assert result.detection == () and len(result.verification) == 2


def test_fixed_versions_come_from_the_range_that_matches_the_mapping(demo: Engine) -> None:
    gid = group_id(demo)
    cve = one(demo, "SELECT cve_id FROM finding_group LIMIT 1")
    run(
        demo,
        "INSERT INTO cpe_mapping (software_product_id, nvd_part, nvd_vendor, nvd_product, origin, mapped_at) "
        "SELECT software_product_id, 'a', 'acme', 'tool', 'manual', now() FROM finding_group WHERE id = :g "
        "ON CONFLICT (software_product_id) DO UPDATE SET nvd_part = 'a', nvd_vendor = 'acme', nvd_product = 'tool'",
        {"g": gid},
    )
    for vendor, start, end, inclusive in (
        ("acme", None, "2.4.1", False),
        ("other", None, "9.9", False),
        ("acme", "2.5", "3.0", True),
    ):
        run(
            demo,
            "INSERT INTO cve_affected_range (cve_id, source, vendor, product, version_start, start_inclusive, "
            "version_end, end_inclusive) VALUES (:c, 'nvd_cpe', :v, 'tool', :s, :si, :e, :i)",
            {"c": cve, "v": vendor, "s": start, "si": None if start is None else True, "e": end, "i": inclusive},
        )
    with Session(demo) as session:
        result = build_mitigation(session, gid)
    # [2.5, 3.0] of the same product comes after 2.4.1: «or higher» stops before it (F15.9, T4 review r3)
    assert result is not None and result.correction == ("Actualizar a 2.4.1 o posterior, sin llegar a 2.5.",)


def test_indicators_linked_to_the_cve_become_detection_steps(demo: Engine) -> None:
    gid = group_id(demo)
    cve = one(demo, "SELECT cve_id FROM finding_group LIMIT 1")
    source, ioc = uuid.uuid4(), uuid.uuid4()
    run(
        demo,
        "INSERT INTO source (id, code, name, kind, url, trust_tier, is_structural, is_custom, enabled, created_at) "
        "VALUES (:s, 'threatfox', 'ThreatFox', 'api', 'https://threatfox.example', 'N1', true, false, true, now())",
        {"s": source},
    )
    run(
        demo,
        "INSERT INTO ioc (id, ioc_type, value, source_id, first_seen_at, last_seen_at) "
        "VALUES (:i, 'domain', 'evil.example', :s, now(), now())",
        {"i": ioc, "s": source},
    )
    run(demo, "INSERT INTO ioc_cve (ioc_id, cve_id) VALUES (:i, :c)", {"i": ioc, "c": cve})
    other_source, other_ioc = uuid.uuid4(), uuid.uuid4()
    run(
        demo,
        "INSERT INTO source (id, code, name, kind, url, trust_tier, is_structural, is_custom, enabled, created_at) "
        "VALUES (:s, 'blog', 'Blog', 'rss', 'https://blog.example/feed', 'N4', false, true, true, now())",
        {"s": other_source},
    )
    run(
        demo,
        "INSERT INTO ioc (id, ioc_type, value, source_id, first_seen_at, last_seen_at) "
        "VALUES (:i, 'domain', 'from-a-blog.example', :s, now(), now())",
        {"i": other_ioc, "s": other_source},
    )
    run(demo, "INSERT INTO ioc_cve (ioc_id, cve_id) VALUES (:i, :c)", {"i": other_ioc, "c": cve})
    with Session(demo) as session:
        result = build_mitigation(session, gid)
    assert result is not None
    assert result.detection == ("Buscar en registros y tráfico el indicador domain:evil.example.",)


def test_unknown_group_has_no_mitigation(demo: Engine) -> None:
    with Session(demo) as session:
        assert build_mitigation(session, uuid.uuid4()) is None


def seed_assessments(engine: Engine) -> tuple[uuid.UUID, list[uuid.UUID], list[uuid.UUID]]:
    gid = group_id(engine)
    with engine.connect() as conn:
        assets = [r[0] for r in conn.execute(text("SELECT id FROM asset ORDER BY name"))]
        run_id = conn.execute(text("SELECT id FROM run LIMIT 1")).scalar_one()
        formula = conn.execute(text("SELECT id FROM formula_version WHERE status = 'active'")).scalar_one()
    ids = [uuid.uuid4(), uuid.uuid4()]
    for n, (assessment, final) in enumerate(zip(ids, (70, 86), strict=True)):
        run(
            engine,
            'INSERT INTO assessment (id, finding_group_id, run_id, formula_version_id, "trigger", factor_s, factor_p, '
            "factor_t, judge_adjustment, raw_cvss_score, raw_in_kev, assessed_at) VALUES "
            "(:id, :g, :r, :f, 'new_finding', 0.75, 0.5, 0.5, :adj, 7.5, true, :at)",
            {"id": assessment, "g": gid, "r": run_id, "f": formula, "adj": final - 70, "at": T0 + timedelta(days=n)},
        )
        for asset in assets[:2]:
            run(
                engine,
                "INSERT INTO asset_score (assessment_id, asset_id, factor_a, factor_d, version_factor, base, "
                "ci_adjustment, "
                "final, snap_criticality, snap_confidentiality, snap_exposed) VALUES "
                "(:a, :s, 0.8, 0.7, 1, 70, 0, :final, 'high', 'classified', true)",
                {"a": assessment, "s": asset, "final": final},
            )
    return gid, ids, assets


def test_history_lists_each_assessment_per_ci_oldest_first(demo: Engine) -> None:
    gid, ids, assets = seed_assessments(demo)
    with Session(demo) as session:
        by_group = score_history(session, finding_group_id=gid)
        assert [(p.assessment_id, p.final) for p in by_group[::2]] == [(ids[0], 70), (ids[1], 86)]
        assert len(by_group) == 4 and by_group[0].assessed_at < by_group[-1].assessed_at
        first = by_group[0]
        assert (first.base, first.judge_adjustment, first.trigger, first.raw_in_kev) == (70, 0, "new_finding", True)
        assert set(first.factors) == {"S", "P", "T", "A", "D"} and first.level is not None
        by_asset = score_history(session, asset_id=assets[0])
        assert [p.final for p in by_asset] == [70, 86] and {p.asset_id for p in by_asset} == {assets[0]}
        assert len(score_history(session, finding_group_id=gid, asset_id=assets[1], limit=1)) == 1
        assert score_history(session, finding_group_id=uuid.uuid4()) == []
        assert all(p.no_judge_review for p in by_group)  # the seeded assessments have no judge review
        # the newest point survives a small limit; `before` pages back to older ones
        newest = score_history(session, finding_group_id=gid, asset_id=assets[0], limit=1)
        assert [p.final for p in newest] == [86]
        older = score_history(session, finding_group_id=gid, asset_id=assets[0], limit=1, before=newest[0].assessed_at)
        assert [p.final for p in older] == [70]


@pytest.mark.parametrize(
    "kwargs", [{}, {"asset_id": uuid.uuid4(), "limit": 0}, {"asset_id": uuid.uuid4(), "limit": 1001}]
)
def test_history_rejects_bad_arguments(demo: Engine, kwargs: dict[str, Any]) -> None:
    with Session(demo) as session, pytest.raises(ValueError):
        score_history(session, **kwargs)
