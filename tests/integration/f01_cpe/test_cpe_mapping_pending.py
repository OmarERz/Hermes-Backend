"""Mapping, candidate search and pending list against PostgreSQL."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from core.cpe.candidates import CpeDictionaryClient, find_candidates, local_candidates
from core.cpe.mapping import MappingError, MappingInput, remove_mapping, set_mapping
from core.inventory.pending import count_pending, first_pending, list_pending
from core.vulndata.http import JsonSource

pytestmark = pytest.mark.integration
T0 = datetime(2026, 11, 22, tzinfo=UTC)


def run(engine: Engine, statement: str, params: dict[str, Any] | None = None) -> None:
    with engine.begin() as conn:
        conn.execute(text(statement), params or {})


def seed_ranges(engine: Engine) -> None:
    run(engine, "INSERT INTO cve (id) VALUES ('CVE-2026-0001'), ('CVE-2026-0002')")
    run(
        engine,
        "INSERT INTO cve_affected_range (cve_id, source, vendor, product) VALUES "
        "('CVE-2026-0001', 'nvd_cpe', 'f5', 'nginx'), ('CVE-2026-0002', 'nvd_cpe', 'f5', 'nginx'), "
        "('CVE-2026-0002', 'nvd_cpe', 'openbsd', 'openssh'), ('CVE-2026-0002', 'cna_affected', 'F5', 'NGINX Plus')",
    )


def seed_inventory(engine: Engine) -> dict[str, uuid.UUID]:
    ids = {name: uuid.uuid4() for name in ("web", "orphan", "nginx", "openssl")}
    run(engine, "INSERT INTO team (itop_team_id, name, is_default, synced_at) VALUES ('t1', 'Ops', false, now())")
    run(engine, "INSERT INTO person (itop_person_id, name, synced_at) VALUES ('p1', 'Ana', now())")
    complete = {"id": ids["web"], "ci": "web", "name": "web-01", "exposed": False, "conf": "classified", "full": True}
    orphan = {
        "id": ids["orphan"],
        "ci": "orphan",
        "name": "orphan-01",
        "exposed": None,
        "conf": "unclassified",
        "full": False,
    }
    for params in (complete, orphan):
        run(
            engine,
            "INSERT INTO asset (id, itop_ci_id, itop_class, name, criticality, exposed, confidentiality, synced_at, "
            "custodian_team_id, owner_person_id) VALUES (:id, :ci, 'Server', :name, 'high', :exposed, :conf, now(), "
            "CASE WHEN :full THEN (SELECT id FROM team) END, CASE WHEN :full THEN (SELECT id FROM person) END)",
            params,
        )
    run(
        engine,
        "INSERT INTO software_product (id, itop_name, first_seen_at) "
        "VALUES (:a, 'nginx', now()), (:b, 'OpenSSL', now())",
        {"a": ids["nginx"], "b": ids["openssl"]},
    )
    run(
        engine,
        "INSERT INTO installed_software (itop_instance_id, asset_id, software_product_id, version, synced_at) "
        "VALUES ('i1', :asset, :p, '1.24.0', now())",
        {"asset": ids["web"], "p": ids["nginx"]},
    )
    return ids


def issues(engine: Engine) -> set[tuple[str, str]]:
    with Session(engine) as session:
        return {(i.issue, i.asset_name or i.software_name or "") for i in list_pending(session, limit=200)}


def test_pending_list_counts_and_filters(engine: Engine) -> None:
    seed_inventory(engine)
    assert issues(engine) == {
        ("software_unmapped", "nginx"),
        ("software_unmapped", "OpenSSL"),
        ("exposure_unknown", "orphan-01"),
        ("unclassified", "orphan-01"),
        ("owner_missing", "orphan-01"),
        ("custodian_missing", "orphan-01"),
    }
    with Session(engine) as session:
        only = list_pending(session, "software_unmapped")
        assert {(p.software_name, p.installations) for p in only} == {("nginx", 1), ("OpenSSL", 0)}
        assert [p.software_name for p in list_pending(session, "software_unmapped", limit=1)] == ["nginx"]
        assert [p.software_name for p in list_pending(session, "software_unmapped", limit=1, offset=1)] == ["OpenSSL"]
        counts = count_pending(session)
    assert counts["software_unmapped"] == 2 and counts["custodian_missing"] == 1 and counts["exposure_unknown"] == 1


def test_the_first_page_of_a_type_comes_with_its_total(engine: Engine) -> None:
    """F18.6: the list and its total come from one statement, so they always agree (feature review P1)."""
    seed_inventory(engine)
    with Session(engine) as session:
        items, total = first_pending(session, "software_unmapped", limit=1)
        assert ([p.software_name for p in items], total) == (["nginx"], 2)  # cut at the limit, total past it
        everything, all_total = first_pending(session, "software_unmapped")
        assert (len(everything), all_total) == (2, 2)
        run(engine, "UPDATE asset SET exposed = true")
        assert first_pending(session, "exposure_unknown") == ([], 0)  # an empty type totals 0
        with pytest.raises(ValueError):
            first_pending(session, "nope")


@pytest.mark.parametrize("kwargs", [{"issue": "nope"}, {"limit": 0}, {"limit": 201}, {"offset": -1}])
def test_pending_list_rejects_bad_arguments(engine: Engine, kwargs: dict[str, Any]) -> None:
    with Session(engine) as session, pytest.raises(ValueError):
        list_pending(session, **kwargs)


def test_mapping_removes_the_pending_item_and_can_be_replaced_or_removed(engine: Engine) -> None:
    ids = seed_inventory(engine)
    with Session(engine) as session, session.begin():
        row = set_mapping(session, ids["nginx"], MappingInput("F5", "NGINX", "F5 Networks", "NGINX"), now=T0)
        assert (row.nvd_vendor, row.origin, row.mapped_at) == ("f5", "manual", T0)
    assert ("software_unmapped", "nginx") not in issues(engine)
    with Session(engine) as session, session.begin():
        set_mapping(session, ids["nginx"], MappingInput(None, None, "F5", "nginx"), now=T0)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT nvd_product, cna_product FROM cpe_mapping")).all() == [(None, "nginx")]
    with Session(engine) as session, session.begin():
        assert remove_mapping(session, ids["nginx"]) is True
        assert remove_mapping(session, ids["nginx"]) is False
    assert ("software_unmapped", "nginx") in issues(engine)


def test_two_analysts_saving_the_first_mapping_do_not_collide(engine: Engine) -> None:
    ids = seed_inventory(engine)
    first, second = Session(engine), Session(engine)
    try:
        set_mapping(first, ids["nginx"], MappingInput("f5", "nginx"), now=T0)
        first.commit()
        set_mapping(second, ids["nginx"], MappingInput("nginx", "nginx"), now=T0)  # sees the row: updates it
        second.commit()
    finally:
        first.close()
        second.close()
    with engine.connect() as conn:
        assert conn.execute(text("SELECT nvd_vendor FROM cpe_mapping")).all() == [("nginx",)]


def test_mapping_errors(engine: Engine) -> None:
    ids = seed_inventory(engine)
    with Session(engine) as session:
        with pytest.raises(MappingError):
            set_mapping(session, ids["nginx"], MappingInput("f5", None))
        with pytest.raises(LookupError):
            set_mapping(session, uuid.uuid4(), MappingInput("f5", "nginx"))


def test_local_candidates_come_from_loaded_ranges(engine: Engine) -> None:
    seed_ranges(engine)
    with Session(engine) as session:
        found = local_candidates(session, "nginx")
        assert [(c.vendor, c.product, c.cve_count, c.source) for c in found] == [("f5", "nginx", 2, "local")]
        assert local_candidates(session, "!!!") == []
        assert local_candidates(session, "open (ssh")[0].product == "openssh"  # regex characters are escaped, not run


def test_find_candidates_merges_and_survives_a_dictionary_outage(engine: Engine) -> None:
    seed_ranges(engine)

    def client(status: int, body: Any) -> CpeDictionaryClient:
        http = httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(status, json=body)))
        return CpeDictionaryClient(JsonSource(http=http, max_attempts=1, sleep=lambda _s: None), SecretStr("k"))

    body = {
        "products": [
            {"cpe": {"cpeName": "cpe:2.3:a:f5:nginx:1:*:*:*:*:*:*:*", "titles": [{"lang": "en", "title": "F5 NGINX"}]}},
            {"cpe": {"cpeName": "cpe:2.3:a:nginx:nginx:1:*:*:*:*:*:*:*"}},
        ]
    }
    with Session(engine) as session:
        merged = find_candidates(session, "nginx", client(200, body))
        assert [(c.vendor, c.product, c.source, c.cve_count, c.title) for c in merged] == [
            ("nginx", "nginx", "nvd_dictionary", None, None),
            ("f5", "nginx", "nvd_dictionary", 2, "F5 NGINX"),
        ]
        for status in (503, 403):  # an outage and a rejected key both keep the local candidates
            offline = find_candidates(session, "nginx", client(status, {}))
            assert [(c.vendor, c.source) for c in offline] == [("f5", "local")]
        assert [c.vendor for c in find_candidates(session, "nginx")] == ["f5"]
