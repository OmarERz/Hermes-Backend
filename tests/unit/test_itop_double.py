from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from doubles.itop import ENDPOINT, ItopDouble, parse_literals, split_and


def call(double: ItopDouble, op: dict[str, Any], *, credential: str | None = "test-token") -> dict[str, Any]:
    headers = {"Auth-Token": credential} if credential else {}
    with double.client() as client:
        response = client.post(ENDPOINT, params={"version": "1.3"}, data={"json_data": json.dumps(op)}, headers=headers)
    body: dict[str, Any] = response.json()
    return body


def get(double: ItopDouble, class_name: str, key: object, fields: str = "*") -> dict[str, Any]:
    return call(double, {"operation": "core/get", "class": class_name, "key": key, "output_fields": fields})


@pytest.fixture
def itop() -> ItopDouble:
    return ItopDouble.from_fixture()


def names(result: dict[str, Any]) -> set[str]:
    return {o["fields"]["name"] for o in (result["objects"] or {}).values()}


def test_rejects_bad_credentials_and_records_nothing(itop: ItopDouble) -> None:
    get(itop, "Server", "SELECT Server")
    bad = call(itop, {"operation": "list_operations"}, credential="wrong")
    assert bad["code"] == 1
    assert itop.operations == ["core/get"]
    assert itop.calls[0].auth == "token"


def test_basic_auth_is_accepted() -> None:
    itop = ItopDouble.from_fixture(token=None)
    with itop.client() as client:
        response = client.post(
            ENDPOINT,
            data={"auth_user": "svc", "auth_pwd": "pw", "json_data": json.dumps({"operation": "list_operations"})},
        )
    assert response.json()["code"] == 0
    assert itop.calls[0].auth == "basic"


def test_list_operations(itop: ItopDouble) -> None:
    verbs = {o["verb"] for o in call(itop, {"operation": "list_operations"})["operations"]}
    assert {"core/get", "core/create", "core/update", "core/apply_stimulus"} <= verbs


def test_unknown_operation(itop: ItopDouble) -> None:
    assert call(itop, {"operation": "core/delete", "class": "Server", "key": 1})["code"] == 3


def test_get_by_id_and_output_fields(itop: ItopDouble) -> None:
    result = get(itop, "Server", 100, "name,internet_exposed")
    assert result["objects"]["Server::100"]["fields"] == {"name": "web-frontend-01", "internet_exposed": "yes"}


def test_oql_equals_in_and_not_in(itop: ItopDouble) -> None:
    assert names(get(itop, "Server", "SELECT Server WHERE name = 'db-host-01'")) == {"db-host-01"}
    assert names(get(itop, "Server", "SELECT Server WHERE name IN ('db-host-01', 'k8s-node-01')")) == {
        "db-host-01",
        "k8s-node-01",
    }
    assert names(get(itop, "Server", "SELECT Server WHERE name NOT IN ('db-host-01')")) == {
        "web-frontend-01",
        "k8s-node-01",
    }


def test_oql_and_over_functional_ci_inheritance(itop: ItopDouble) -> None:
    query = "SELECT FunctionalCI WHERE business_criticity = 'high' AND internet_exposed = 'no'"
    assert names(get(itop, "FunctionalCI", query)) == {"k8s-node-01", "db-host-01"}
    everything = names(get(itop, "FunctionalCI", "SELECT FunctionalCI"))
    assert {"web-frontend-01", "vm-legacy-01", "nginx 1.24.0 @ web-frontend-01"} <= everything


def test_software_instances_are_selected_through_their_parent(itop: ItopDouble) -> None:
    found = names(get(itop, "SoftwareInstance", "SELECT SoftwareInstance WHERE system_id = '102'"))
    assert found == {"PostgreSQL 15.4 @ db-host-01"}


def test_oql_quoted_values_with_escapes_and_ands(itop: ItopDouble) -> None:
    itop.add("Team", 12, name="O'Brien and AND co")
    assert names(get(itop, "Team", r"SELECT Team WHERE name = 'O\'Brien and AND co'")) == {"O'Brien and AND co"}


def test_unsupported_oql_is_an_error_not_a_silent_empty_result(itop: ItopDouble) -> None:
    assert get(itop, "Server", "SELECT Server WHERE name LIKE 'x%'")["code"] == 100
    assert get(itop, "Server", "SELECT Person")["code"] == 100


def test_get_without_matches_returns_no_objects(itop: ItopDouble) -> None:
    result = get(itop, "Server", "SELECT Server WHERE name = 'nope'")
    assert result["code"] == 0
    assert result["objects"] is None


def test_extension_attributes_are_enums_on_every_ci_class(itop: ItopDouble) -> None:
    create = call(
        itop,
        {
            "operation": "core/create",
            "class": "Server",
            "fields": {"name": "x", "org_id": "1", "confidentiality": "secret"},
        },
    )
    assert create["code"] == 100
    ok = call(
        itop,
        {
            "operation": "core/create",
            "class": "VirtualMachine",
            "fields": {"name": "y", "org_id": "1", "personal_data": "unknown", "internet_exposed": "no"},
        },
    )
    assert ok["code"] == 0


def test_create_requires_mandatory_fields(itop: ItopDouble) -> None:
    result = call(itop, {"operation": "core/create", "class": "WebServer", "fields": {"name": "w", "org_id": "1"}})
    assert result["code"] == 100
    assert "system_id" in result["message"]


def ticket_fields(**extra: Any) -> dict[str, Any]:
    return {"org_id": "1", "caller_id": "22", "title": "CVE-2026-0001 on web", "description": "d", **extra}


def create_ticket(itop: ItopDouble, **extra: Any) -> str:
    result = call(itop, {"operation": "core/create", "class": "UserRequest", "fields": ticket_fields(**extra)})
    assert result["code"] == 0, result
    (obj,) = result["objects"].values()
    assert obj["fields"]["status"] == "new"
    assert obj["fields"]["ref"].startswith("R-")
    return str(obj["key"])


def links(itop: ItopDouble, ticket_id: str) -> set[str]:
    rows = get(itop, "lnkFunctionalCIToTicket", f"SELECT lnkFunctionalCIToTicket WHERE ticket_id = '{ticket_id}'")
    return {o["fields"]["functionalci_id"] for o in (rows["objects"] or {}).values()}


def test_ticket_creation_creates_ci_links_and_update_replaces_them(itop: ItopDouble) -> None:
    ticket = create_ticket(itop, functionalcis_list=[{"functionalci_id": "100"}, {"functionalci_id": "101"}])
    assert links(itop, ticket) == {"100", "101"}
    call(
        itop,
        {
            "operation": "core/update",
            "class": "UserRequest",
            "key": ticket,
            "fields": {"functionalcis_list": [{"functionalci_id": "102"}]},
        },
    )
    assert links(itop, ticket) == {"102"}  # replaced, not merged (analysis §5.7)


def test_update_changes_fields_and_reports_missing_object(itop: ItopDouble) -> None:
    ticket = create_ticket(itop)
    call(itop, {"operation": "core/update", "class": "UserRequest", "key": ticket, "fields": {"title": "new"}})
    assert get(itop, "UserRequest", ticket)["objects"][f"UserRequest::{ticket}"]["fields"]["title"] == "new"
    missing = call(itop, {"operation": "core/update", "class": "UserRequest", "key": 999999, "fields": {}})
    assert missing["code"] == 100


def stimulus(itop: ItopDouble, ticket: str, name: str, **fields: Any) -> dict[str, Any]:
    return call(
        itop,
        {"operation": "core/apply_stimulus", "class": "UserRequest", "key": ticket, "stimulus": name, "fields": fields},
    )


def status(itop: ItopDouble, ticket: str) -> str:
    return str(get(itop, "UserRequest", ticket)["objects"][f"UserRequest::{ticket}"]["fields"]["status"])


def test_assign_requires_team_and_agent_of_that_team(itop: ItopDouble) -> None:
    ticket = create_ticket(itop)
    assert stimulus(itop, ticket, "ev_assign")["code"] == 100
    wrong_team = stimulus(itop, ticket, "ev_assign", team_id="11", agent_id="20")
    assert wrong_team["code"] == 100
    assert "belong" in wrong_team["message"]
    assert status(itop, ticket) == "new"
    assert stimulus(itop, ticket, "ev_assign", team_id="10", agent_id="20")["code"] == 0
    assert status(itop, ticket) == "assigned"


def test_assign_is_valid_from_pending_but_not_from_assigned_or_resolved(itop: ItopDouble) -> None:
    ticket = create_ticket(itop)
    stimulus(itop, ticket, "ev_assign", team_id="10", agent_id="20")
    again = stimulus(itop, ticket, "ev_assign", team_id="10", agent_id="20")
    assert again["code"] == 100  # ev_assign only from new/escalated_tto/approved/pending
    assert stimulus(itop, ticket, "ev_pending")["code"] == 0
    assert stimulus(itop, ticket, "ev_assign", team_id="10", agent_id="20")["code"] == 0
    assert status(itop, ticket) == "assigned"


def test_resolve_needs_service_code_and_solution_then_close_and_reopen(itop: ItopDouble) -> None:
    ticket = create_ticket(itop)
    stimulus(itop, ticket, "ev_assign", team_id="10", agent_id="20")
    assert stimulus(itop, ticket, "ev_resolve", service_id="5")["code"] == 100
    assert (
        stimulus(itop, ticket, "ev_resolve", service_id="5", resolution_code="fixed", solution="patched")["code"] == 0
    )
    assert status(itop, ticket) == "resolved"
    assert stimulus(itop, ticket, "ev_reopen")["code"] == 0
    assert status(itop, ticket) == "assigned"
    assert stimulus(itop, ticket, "ev_close")["code"] == 100


def test_unknown_stimulus_and_non_ticket(itop: ItopDouble) -> None:
    ticket = create_ticket(itop)
    assert stimulus(itop, ticket, "ev_nonsense")["code"] == 100
    on_server = call(itop, {"operation": "core/apply_stimulus", "class": "Server", "key": 100, "stimulus": "ev_assign"})
    assert on_server["code"] == 100


def test_down_switch_raises_a_transport_error(itop: ItopDouble) -> None:
    itop.down = True
    with pytest.raises(httpx.ConnectError):
        call(itop, {"operation": "list_operations"})
    assert itop.calls == []


def test_race_hook_runs_before_writes_only(itop: ItopDouble) -> None:
    ticket = create_ticket(itop)
    seen: list[str] = []

    def steal(op: dict[str, Any]) -> None:
        seen.append(op["operation"])
        itop.data["UserRequest"][ticket].update({"status": "assigned", "agent_id": "21", "team_id": "11"})

    itop.before_write = steal
    get(itop, "UserRequest", ticket)
    assert seen == []
    result = stimulus(itop, ticket, "ev_assign", team_id="10", agent_id="20")
    assert seen == ["core/apply_stimulus"]
    assert result["code"] == 100  # the other actor won the race


def test_calls_are_recorded_and_writes_filtered(itop: ItopDouble) -> None:
    create_ticket(itop)
    get(itop, "Server", 100)
    assert itop.operations == ["core/create", "core/get"]
    assert [w.operation for w in itop.writes] == ["core/create"]


def test_non_rest_paths_are_404(itop: ItopDouble) -> None:
    with itop.client() as client:
        assert client.get("/other").status_code == 404


def test_oql_helpers() -> None:
    assert parse_literals("('a', 'b\\'c', 5)") == ["a", "b'c", "5"]
    assert split_and("a = 'x AND y' AND b IN ('p AND q')") == ["a = 'x AND y'", "b IN ('p AND q')"]
