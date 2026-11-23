"""STIX export against PostgreSQL over the demo seed: scopes, TLP, exclusion and what must never leave."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
import stix2
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.seeds import NOW, seed
from core.stix.export import ExportOptions, ExportScope, StixExportError, export_bundle

pytestmark = pytest.mark.integration
CVE = "CVE-2026-10001"


def run(engine: Engine, statement: str, params: dict[str, Any] | None = None) -> None:
    with engine.begin() as conn:
        conn.execute(text(statement), params or {})


def rows(engine: Engine, statement: str) -> list[tuple[Any, ...]]:
    with engine.connect() as conn:
        return [tuple(r) for r in conn.execute(text(statement))]


def add_intelligence(engine: Engine) -> None:
    """Indicators, a news report with an actor and a victim sector, an assessment and a ticket for the demo CVE."""
    with Session(engine) as session, session.begin():
        threatfox = m.Source(
            code="threatfox",
            name="ThreatFox",
            kind="api",
            url="https://threatfox.example",
            trust_tier="N3",
            is_structural=False,
            is_custom=False,
            enabled=True,
            created_at=NOW,
        )
        blog = m.Source(
            code="blog",
            name="Blog",
            kind="rss",
            url="https://blog.example",
            trust_tier="N4",
            is_structural=False,
            is_custom=True,
            enabled=True,
            created_at=NOW,
        )
        scan = session.scalars(text("SELECT id FROM run LIMIT 1")).one()
        session.add_all([threatfox, blog])
        session.flush()
        fetch = m.SourceFetch(source_id=blog.id, run_id=scan, started_at=NOW, status="ok", items_new=1)
        session.add(fetch)
        session.flush()
        article = m.RawArticle(
            source_fetch_id=fetch.id,
            canonical_url="https://news.example/exploit",
            title="Explotan OpenSSL",
            published_at=NOW - timedelta(hours=5),
            captured_at=NOW,
            is_suspicious=False,
            clean_text="TEXTO COMPLETO QUE NUNCA DEBE SALIR",
        )
        session.add(article)
        session.flush()
        story = m.Story(representative_article_id=article.id, relevance_status="relevant", created_at=NOW)
        session.add(story)
        session.flush()
        review = m.LlmReview(
            agent="news_analyst",
            model="m",
            response_model={},
            prompt_version="1",
            prompt_hash="h",
            schema_version="1",
            schema_hash="h",
            parameters={},
            input_ref="x",
            calls=[],
            status="applied",
            attempts=1,
            tokens_input=0,
            tokens_cached=0,
            tokens_output=0,
            tokens_reasoning=0,
            cost_usd=Decimal(0),
            latency_ms=1,
            ladder_level=0,
            created_at=NOW,
        )
        session.add(review)
        session.flush()
        analysis = m.NewsAnalysis(
            story_id=story.id,
            llm_review_id=review.id,
            summary="s",
            event_type="exploitation",
            output={},
            created_at=NOW,
        )
        sector = session.scalars(text("SELECT code FROM sector ORDER BY code LIMIT 1")).one()
        actor = m.Actor(name="APT-X")
        session.add_all([analysis, actor])
        session.flush()
        session.add_all(
            [
                m.NewsCveMention(analysis_id=analysis.id, cve_id=CVE, quote="q"),
                m.NewsActorMention(analysis_id=analysis.id, actor_id=actor.id, quote="q"),
                m.ActorAlias(actor_id=actor.id, alias="Group X"),
                m.NewsVictim(analysis_id=analysis.id, name="Banco Secreto S.A.", sector_code=sector, quote="q"),
            ]
        )
        for kind, value, family in (("domain", "evil.example", "Mirai"), ("ip", "203.0.113.7", None)):
            ioc = m.Ioc(
                ioc_type=kind,
                value=value,
                malware_family=family,
                source_id=threatfox.id,
                first_seen_at=NOW,
                last_seen_at=NOW + timedelta(days=1),
            )
            session.add(ioc)
            session.flush()
            session.add(m.IocCve(ioc_id=ioc.id, cve_id=CVE))
        stray = m.Ioc(
            ioc_type="domain", value="blog-indicator.example", source_id=blog.id, first_seen_at=NOW, last_seen_at=NOW
        )
        session.add(stray)
        session.flush()
        session.add(m.IocCve(ioc_id=stray.id, cve_id=CVE))


def add_scores(engine: Engine) -> None:
    group = rows(engine, "SELECT id FROM finding_group")[0][0]
    assets = rows(engine, "SELECT id, itop_ci_id FROM asset ORDER BY itop_ci_id")
    formula = rows(engine, "SELECT id FROM formula_version WHERE status = 'active'")[0][0]
    scan = rows(engine, "SELECT id FROM run")[0][0]
    assessment = uuid.uuid4()
    run(
        engine,
        'INSERT INTO assessment (id, finding_group_id, run_id, formula_version_id, "trigger", factor_s, factor_p, '
        "factor_t, judge_adjustment, assessed_at) VALUES (:id, :g, :r, :f, 'new_finding', 0.9, 0.9, 0.5, 12, :at)",
        {"id": assessment, "g": group, "r": scan, "f": formula, "at": NOW},
    )
    for (asset, _ci), (base, final) in zip(assets, ((74, 86), (60, 72)), strict=True):
        run(
            engine,
            "INSERT INTO asset_score (assessment_id, asset_id, factor_a, factor_d, version_factor, base, "
            "ci_adjustment, final, snap_criticality, snap_confidentiality) "
            "VALUES (:a, :s, 0.8, 0.7, 1, :b, 0, :f, 'high', 'classified')",
            {"a": assessment, "s": asset, "b": base, "f": final},
        )
    run(
        engine,
        "INSERT INTO ticket (finding_group_id, custodian_team_id, itop_ticket_id, itop_ref, status, "
        "suggestions_enabled, created_at) "
        "SELECT :g, id, '1', 'R-000001', 'open', true, now() FROM team WHERE is_default",
        {"g": group},
    )


@pytest.fixture
def world(engine: Engine) -> Engine:
    with Session(engine) as session, session.begin():
        seed(session, "demo")
    add_intelligence(engine)
    add_scores(engine)
    return engine


def export(engine: Engine, scope: ExportScope, options: ExportOptions | None = None) -> Any:
    with Session(engine) as session:
        return export_bundle(session, scope, options)


def by_type(bundle: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [o for o in bundle["objects"] if o["type"] == kind]


BY_CVE = ExportScope("vulnerability", vulnerability_id=CVE)


def test_the_bundle_has_every_object_kind_and_validates(world: Engine) -> None:
    result = export(world, BY_CVE)
    bundle = result.bundle
    assert bundle["type"] == "bundle" and bundle["id"].startswith("bundle--")
    kinds = {o["type"] for o in bundle["objects"]}
    assert {"vulnerability", "software", "indicator", "malware", "intrusion-set", "identity", "report"} <= kinds
    assert {"marking-definition", "relationship"} <= kinds
    relationships = {(r["relationship_type"]) for r in by_type(bundle, "relationship")}
    assert relationships == {"has", "indicates", "exploits", "targets"}
    vuln = by_type(bundle, "vulnerability")[0]
    assert vuln["name"] == CVE and vuln["x_base_score"] == 74 and vuln["x_final_score"] == 86
    assert vuln["x_judge_adjustment"] == 12 and vuln["x_affected_assets"] == 2
    assert vuln["x_ticket_status"] == ["open"] and vuln["x_classification"] == "highly_classified"
    patterns = sorted(i["pattern"] for i in by_type(bundle, "indicator"))
    assert patterns == ["[domain-name:value = 'evil.example']", "[ipv4-addr:value = '203.0.113.7']"]  # not the blog's
    assert by_type(bundle, "intrusion-set")[0]["aliases"] == ["Group X"]
    assert by_type(bundle, "identity")[0]["name"] == rows(world, "SELECT name FROM sector ORDER BY code LIMIT 1")[0][0]
    report = by_type(bundle, "report")[0]
    assert report["external_references"][0]["url"] == "https://news.example/exploit"
    assert vuln["id"] in report["object_refs"]
    assert stix2.parse(json.dumps(bundle), allow_custom=True).type == "bundle"


def test_the_same_data_gives_the_same_bundle(world: Engine) -> None:
    first = export(world, BY_CVE).bundle
    second = export(world, BY_CVE).bundle
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["id"] == second["id"]


def test_nothing_that_identifies_the_company_leaves(world: Engine) -> None:
    text_out = json.dumps(export(world, BY_CVE).bundle, ensure_ascii=False)
    secrets = [r[0] for r in rows(world, "SELECT name FROM asset")]
    secrets += [r[0] for r in rows(world, "SELECT name FROM team")] + [
        r[0] for r in rows(world, "SELECT email FROM person")
    ]
    secrets += [r[0] for r in rows(world, "SELECT itop_ci_id FROM asset")] + [
        "Banco Secreto",
        "TEXTO COMPLETO",
        "owner@example.test",
    ]
    assert not [s for s in secrets if s and s in text_out]


def test_tlp_follows_the_most_sensitive_asset_and_the_exclusion_lowers_it(world: Engine) -> None:
    full = export(world, BY_CVE)
    assert full.tlp == "TLP:RED"
    marking = by_type(full.bundle, "marking-definition")[0]
    assert marking["id"] == stix2.TLP_RED.id
    assert all(
        o["object_marking_refs"] == [marking["id"]] for o in full.bundle["objects"] if o["type"] == "vulnerability"
    )
    reduced = export(world, BY_CVE, ExportOptions(exclude_ultra_classified=True))
    assert reduced.tlp == "TLP:AMBER"
    vuln = by_type(reduced.bundle, "vulnerability")[0]
    assert vuln["x_affected_assets"] == 1 and vuln["x_classification"] == "classified"
    assert (vuln["x_base_score"], vuln["x_final_score"]) == (60, 72)  # the excluded asset's scores are gone too


def test_personal_data_is_at_least_amber_and_public_is_clear(world: Engine) -> None:
    run(world, "UPDATE asset SET confidentiality = 'public', personal_data = false")
    assert export(world, BY_CVE).tlp == "TLP:CLEAR"
    run(world, "UPDATE asset SET personal_data = true WHERE itop_ci_id = 'CI-2'")
    assert export(world, BY_CVE).tlp == "TLP:AMBER"


def test_a_group_that_only_touches_excluded_assets_is_left_out(world: Engine) -> None:
    run(world, "UPDATE asset SET confidentiality = 'highly_classified'")
    result = export(world, BY_CVE, ExportOptions(exclude_ultra_classified=True))
    assert result.skipped_groups == 1 and result.bundle["objects"] == [] and result.tlp == "TLP:CLEAR"


def test_scopes_by_group_run_and_date_range(world: Engine) -> None:
    group = rows(world, "SELECT id FROM finding_group")[0][0]
    scan = rows(world, "SELECT id FROM run")[0][0]
    expected = export(world, BY_CVE).bundle["id"]
    assert export(world, ExportScope("vulnerability", vulnerability_id=str(group))).bundle["id"] == expected
    assert export(world, ExportScope("run", run_id=str(scan))).bundle["id"] == expected
    day = NOW.date().isoformat()
    assert export(world, ExportScope("date_range", date_from=day, date_to=day)).bundle["id"] == expected
    assert export(world, ExportScope("run", run_id=str(uuid.uuid4()))).bundle["objects"] == []
    later = (NOW + timedelta(days=30)).date().isoformat()
    assert export(world, ExportScope("date_range", date_from=later, date_to=later)).bundle["objects"] == []
    assert export(world, ExportScope("vulnerability", vulnerability_id="CVE-2000-0001")).bundle["objects"] == []


@pytest.mark.parametrize(
    "scope",
    [
        ExportScope("vulnerability", vulnerability_id="not-an-id"),
        ExportScope("vulnerability"),
        ExportScope("run", run_id="nope"),
        ExportScope("date_range", date_from="yesterday", date_to="2026-01-01"),
        ExportScope("date_range", date_from="2026-02-01", date_to="2026-01-01"),
    ],
)
def test_bad_scope_data_is_refused(world: Engine, scope: ExportScope) -> None:
    with pytest.raises(StixExportError):
        export(world, scope)


def test_a_bundle_with_no_findings_still_exports_the_cve(world: Engine) -> None:
    run(
        world,
        "INSERT INTO finding_status_change (finding_id, run_id, status, observed_version, changed_at) "
        "SELECT finding_id, :r, 'fixed', '3.0.8', now() FROM finding_current",
        {"r": rows(world, "SELECT id FROM run")[0][0]},
    )
    bundle = export(world, BY_CVE).bundle
    vuln = by_type(bundle, "vulnerability")[0]
    assert vuln["x_affected_assets"] == 0 and "x_classification" not in vuln


def test_when_the_clock_moves_the_bundle_does_not(world: Engine) -> None:
    before = export(world, BY_CVE).bundle
    assert datetime.now(UTC) > NOW  # the export never reads the clock
    assert json.dumps(before, sort_keys=True) == json.dumps(export(world, BY_CVE).bundle, sort_keys=True)


def test_unclassified_assets_fail_closed_to_amber(world: Engine) -> None:
    run(world, "UPDATE asset SET confidentiality = 'unclassified', personal_data = false")
    result = export(world, BY_CVE)
    assert result.tlp == "TLP:AMBER"
    assert by_type(result.bundle, "vulnerability")[0]["x_classification"] == "unclassified"


def test_one_cve_in_two_products_is_one_vulnerability_with_the_totals(world: Engine) -> None:
    group = rows(world, "SELECT id FROM finding_group")[0][0]
    run(
        world,
        "INSERT INTO asset (itop_ci_id, itop_class, name, criticality, confidentiality, synced_at) "
        "VALUES ('CI-9', 'Server', 'srv-extra', 'low', 'public', now())",
    )
    run(
        world,
        "INSERT INTO software_product (itop_name, first_seen_at) VALUES ('nginx', now())",
    )
    run(
        world,
        "INSERT INTO installed_software (itop_instance_id, asset_id, software_product_id, version, synced_at) "
        "SELECT 'SI-9', a.id, p.id, '1.0', now() FROM asset a, software_product p WHERE a.itop_ci_id = 'CI-9' "
        "AND p.itop_name = 'nginx'",
    )
    run(
        world,
        "INSERT INTO finding_group (cve_id, software_product_id, created_at) "
        "SELECT :c, id, now() FROM software_product WHERE itop_name = 'nginx'",
        {"c": CVE},
    )
    run(
        world,
        "INSERT INTO finding (finding_group_id, installed_software_id, match_source, created_at) "
        "SELECT g.id, i.id, 'nvd_cpe', now() FROM finding_group g, installed_software i "
        "WHERE i.itop_instance_id = 'SI-9' AND g.id <> :g",
        {"g": group},
    )
    run(
        world,
        "INSERT INTO finding_status_change (finding_id, run_id, status, observed_version, changed_at) "
        "SELECT f.id, (SELECT id FROM run LIMIT 1), 'new', '1.0', now() FROM finding f "
        "JOIN installed_software i ON i.id = f.installed_software_id WHERE i.itop_instance_id = 'SI-9'",
    )
    bundle = export(world, BY_CVE).bundle
    vulnerabilities = by_type(bundle, "vulnerability")
    assert len(vulnerabilities) == 1
    assert (
        vulnerabilities[0]["x_affected_assets"] == 3 and vulnerabilities[0]["x_classification"] == "highly_classified"
    )
    assert vulnerabilities[0]["x_final_score"] == 86  # the highest of the groups that were assessed
    assert {s["name"] for s in by_type(bundle, "software")} == {"OpenSSL", "nginx"}
    again = export(world, BY_CVE).bundle
    assert json.dumps(bundle, sort_keys=True) == json.dumps(again, sort_keys=True)


def test_exclusion_also_hides_the_ticket_states_of_the_excluded_assets(world: Engine) -> None:
    ultra_finding = rows(
        world,
        "SELECT f.id FROM finding f JOIN installed_software i ON i.id = f.installed_software_id "
        "JOIN asset a ON a.id = i.asset_id WHERE a.confidentiality = 'highly_classified'",
    )[0][0]
    ticket = rows(world, "SELECT id FROM ticket")[0][0]
    run(
        world,
        "INSERT INTO ticket_finding (ticket_id, finding_id, added_at) VALUES (:t, :f, now())",
        {"t": ticket, "f": ultra_finding},
    )
    assert by_type(export(world, BY_CVE).bundle, "vulnerability")[0]["x_ticket_status"] == ["open"]
    reduced = export(world, BY_CVE, ExportOptions(exclude_ultra_classified=True)).bundle
    assert "x_ticket_status" not in by_type(reduced, "vulnerability")[0]
