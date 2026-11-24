"""harness.itop_load (F16.2): the inventory loader against the iTop REST double and a fake Hermes API."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from doubles.itop import ItopDouble
from harness import itop_load

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]
STACK = ROOT / "docker" / "itop" / "stack.yaml"
CPE_PG = "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"


def provisioned(**kwargs: Any) -> ItopDouble:
    """A double holding what provision.php creates before the loader runs: the system person."""
    double = ItopDouble(**kwargs)
    double.add("Person", 900, name="Hermes System", first_name="Hermes")
    return double


def loader_for(double: ItopDouble) -> itop_load.ItopRest:
    return itop_load.ItopRest("http://127.0.0.1", "test-token", transport=double.transport)


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "inventory.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def rows(double: ItopDouble, class_name: str) -> list[dict[str, Any]]:
    return list(double.data.get(class_name, {}).values())


# --- the synthetic stack -------------------------------------------------------------------------------------------


def test_dry_run_writes_nothing_and_says_what_it_would_do(capsys: pytest.CaptureFixture[str]) -> None:
    double = provisioned()
    assert itop_load.run([str(STACK)], itop=loader_for(double)) == 0
    assert double.writes == []
    out = capsys.readouterr().out
    assert "dry run" in out
    assert "+ create    Server 'web-frontend-01'" in out
    assert "summary: 23 to create, 0 to update, 0 unchanged, 0 already in iTop" in out


def test_apply_loads_the_synthetic_stack_with_extension_attributes() -> None:
    double = provisioned()
    assert itop_load.run([str(STACK), "--apply"], itop=loader_for(double)) == 0
    servers = {row["name"]: row for row in rows(double, "Server")}
    web = servers["web-frontend-01"]
    assert (web["internet_exposed"], web["confidentiality"], web["personal_data"]) == ("yes", "public", "no")
    person_id = next(r["id"] for r in rows(double, "Person") if r["name"] == "Rivera")
    team_id = next(r["id"] for r in rows(double, "Team") if r["name"] == "Platform Ops")
    assert web["owner_id"] == person_id
    assert web["custodian_id"] == team_id
    legacy = next(r for r in rows(double, "VirtualMachine") if r["name"] == "vm-legacy-01")
    assert "owner_id" not in legacy  # incomplete on purpose (inventory pending)
    installs = [r for table in ("WebServer", "DBServer", "OtherSoftware") for r in rows(double, table)]
    assert len(installs) == 4
    nginx = next(r["id"] for r in rows(double, "Software") if r["name"] == "nginx")
    assert {r["software_id"] for r in rows(double, "WebServer")} == {nginx}


def test_second_apply_creates_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    double = provisioned()
    itop_load.run([str(STACK), "--apply"], itop=loader_for(double))
    writes = len(double.writes)
    capsys.readouterr()
    assert itop_load.run([str(STACK), "--apply"], itop=loader_for(double)) == 0
    assert len(double.writes) == writes
    assert "summary: 0 created, 0 updated, 0 unchanged, 23 already in iTop" in capsys.readouterr().out


def test_the_env_section_prints_the_ids_for_the_hermes_env_file(capsys: pytest.CaptureFixture[str]) -> None:
    double = provisioned()
    assert itop_load.run([str(STACK)], itop=loader_for(double)) == 0
    dry = capsys.readouterr().out
    assert "ITOP_CALLER_ID=900" in dry  # created by provision.php, so it already exists
    assert "ITOP_ORG_ID=  # @Organization:Demo-Lab is not in iTop yet" in dry
    assert itop_load.run([str(STACK), "--apply"], itop=loader_for(double)) == 0
    org = next(r["id"] for r in rows(double, "Organization"))
    service = next(r["id"] for r in rows(double, "Service"))
    out = capsys.readouterr().out
    assert f"ITOP_ORG_ID={org}\n" in out
    assert f"ITOP_SERVICE_ID={service}\n" in out


def test_sample_ticket_has_the_d036_shape() -> None:
    double = provisioned()
    itop_load.run([str(STACK), "--apply"], itop=loader_for(double))
    (ticket,) = rows(double, "UserRequest")
    team_id = next(r["id"] for r in rows(double, "Team") if r["name"] == "Platform Ops")
    assert ticket["status"] == "new"
    assert ticket["team_id"] == team_id
    assert ticket["caller_id"] == "900"
    assert ticket["agent_id"] == ""
    assert ticket["service_id"]
    assert len(ticket["contacts_list"]) == 1
    links = [r for r in rows(double, "lnkFunctionalCIToTicket") if r["ticket_id"] == ticket["id"]]
    assert {link["impact_code"] for link in links} == {"manual"}
    assert len(links) == 2


# --- identity keys, update mode and the report -----------------------------------------------------------------------

TWO_VERSIONS = """
objects:
  - { class: Organization, name: Org }
  - { class: Software, name: PostgreSQL, fields: { vendor: PostgreSQL, version: "15.4", type: DBServer } }
  - { class: Software, name: PostgreSQL, fields: { vendor: PostgreSQL, version: "16.1", type: DBServer } }
  - class: Server
    name: db-1
    fields: { org_id: "@Organization:Org" }
  - class: DBServer
    name: pg15 @ db-1
    fields: { org_id: "@Organization:Org", system_id: "@Server:db-1", software_id: "@Software:PostgreSQL 15.4" }
  - class: DBServer
    name: pg16 @ db-1
    fields: { org_id: "@Organization:Org", system_id: "@Server:db-1", software_id: "@Software:PostgreSQL 16.1" }
"""


def test_two_versions_of_one_product_are_two_catalogue_entries(tmp_path: Path) -> None:
    double = ItopDouble()
    assert itop_load.run([str(write(tmp_path, TWO_VERSIONS)), "--apply"], itop=loader_for(double)) == 0
    software = {row["version"]: row["id"] for row in rows(double, "Software")}
    assert set(software) == {"15.4", "16.1"}
    installs = {row["name"]: row["software_id"] for row in rows(double, "DBServer")}
    assert installs == {"pg15 @ db-1": software["15.4"], "pg16 @ db-1": software["16.1"]}
    find = next(c.payload for c in double.calls if c.payload.get("class") == "Software")
    assert find["key"] == "SELECT Software WHERE name = 'PostgreSQL' AND version = '15.4'"


def test_update_writes_only_the_fields_that_differ(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    double = ItopDouble()
    base = "objects:\n  - class: Organization\n    name: Org\n    fields: { code: A, status: active }\n"
    itop_load.run([str(write(tmp_path, base)), "--apply"], itop=loader_for(double))
    capsys.readouterr()
    changed = base.replace("code: A", "code: B")
    assert itop_load.run([str(write(tmp_path, changed)), "--update"], itop=loader_for(double)) == 0
    assert "~ update    Organization 'Org': code" in capsys.readouterr().out
    assert rows(double, "Organization")[0]["code"] == "A"  # dry run
    writes = len(double.writes)
    assert itop_load.run([str(write(tmp_path, changed)), "--apply", "--update"], itop=loader_for(double)) == 0
    (update,) = double.writes[writes:]
    assert update.payload["fields"] == {"code": "B"}
    assert rows(double, "Organization")[0]["code"] == "B"
    capsys.readouterr()
    itop_load.run([str(write(tmp_path, changed)), "--update"], itop=loader_for(double))
    assert "= unchanged Organization 'Org'" in capsys.readouterr().out


def test_link_lists_compare_as_sets_of_linked_objects(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    double = ItopDouble()
    text = """
objects:
  - { class: Organization, name: Org }
  - { class: Person, name: Ana, fields: { org_id: "@Organization:Org" } }
  - { class: Person, name: Luis, fields: { org_id: "@Organization:Org" } }
  - class: Team
    name: T
    fields:
      org_id: "@Organization:Org"
      persons_list: [ { person_id: "@Person:Ana" }, { person_id: "@Person:Luis" } ]
"""
    itop_load.run([str(write(tmp_path, text)), "--apply"], itop=loader_for(double))
    capsys.readouterr()
    ana, luis = '{ person_id: "@Person:Ana" }', '{ person_id: "@Person:Luis" }'
    reordered = text.replace(f"{ana}, {luis}", f"{luis}, {ana}")
    itop_load.run([str(write(tmp_path, reordered)), "--update"], itop=loader_for(double))
    assert "= unchanged Team 'T'" in capsys.readouterr().out
    fewer = text.replace(', { person_id: "@Person:Luis" }', "")
    itop_load.run([str(write(tmp_path, fewer)), "--update"], itop=loader_for(double))
    assert "~ update    Team 'T': persons_list" in capsys.readouterr().out


def test_an_object_created_in_the_same_run_resolves_in_an_update(tmp_path: Path) -> None:
    double = ItopDouble()
    base = "objects:\n  - { class: Organization, name: Org }\n  - { class: Server, name: s, fields: { org_id: '1' } }\n"
    itop_load.run([str(write(tmp_path, base)), "--apply"], itop=loader_for(double))
    moved = base.replace("- { class: Server", "- { class: Organization, name: New }\n  - { class: Server").replace(
        "org_id: '1'", 'org_id: "@Organization:New"'
    )
    assert itop_load.run([str(write(tmp_path, moved)), "--apply", "--update"], itop=loader_for(double)) == 0
    new_org = next(r["id"] for r in rows(double, "Organization") if r["name"] == "New")
    assert rows(double, "Server")[0]["org_id"] == new_org


def test_custom_ref_and_key(tmp_path: Path) -> None:
    double = ItopDouble()
    text = """
objects:
  - { class: Organization, name: Org }
  - class: Person
    name: Garcia
    ref: ana
    key: [name, first_name]
    fields: { first_name: Ana, org_id: "@Organization:Org" }
  - class: Person
    name: Garcia
    ref: luis
    key: [name, first_name]
    fields: { first_name: Luis, org_id: "@Organization:Org" }
  - { class: Team, name: T, fields: { org_id: "@Organization:Org", persons_list: [ { person_id: "@Person:luis" } ] } }
"""
    assert itop_load.run([str(write(tmp_path, text)), "--apply"], itop=loader_for(double)) == 0
    luis = next(r["id"] for r in rows(double, "Person") if r["first_name"] == "Luis")
    assert rows(double, "Team")[0]["persons_list"] == [{"person_id": luis}]
    assert len(rows(double, "Person")) == 2


def test_a_key_that_matches_several_objects_is_an_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    double = ItopDouble()
    double.add("Person", 1, name="Garcia")
    double.add("Person", 2, name="Garcia")
    path = write(tmp_path, "objects:\n  - { class: Person, name: Garcia }\n")
    assert itop_load.run([str(path)], itop=loader_for(double)) == 1
    assert "2 Person objects match" in capsys.readouterr().err


# --- broken references and failures -------------------------------------------------------------------------------


def test_broken_reference_writes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    double = ItopDouble()
    path = write(tmp_path, 'objects:\n  - class: Server\n    name: s\n    fields: { org_id: "@Organization:Nope" }\n')
    assert itop_load.run([str(path), "--apply"], itop=loader_for(double)) == 1
    assert double.writes == []
    assert "Nope" in capsys.readouterr().err


def test_a_composite_key_reference_must_be_in_the_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    double = ItopDouble()
    double.add("Software", 5, name="nginx", version="1.24.0")
    text = 'objects:\n  - { class: WebServer, name: w, fields: { software_id: "@Software:nginx 1.24.0" } }\n'
    path = write(tmp_path, text)
    assert itop_load.run([str(path), "--apply"], itop=loader_for(double)) == 1
    assert "name + version identify it: define it in the file" in capsys.readouterr().err


def test_itop_rejection_is_reported(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write(tmp_path, "objects:\n  - class: Server\n    name: s\n    fields: { org_id: '1', status: weird }\n")
    assert itop_load.run([str(path), "--apply"], itop=loader_for(ItopDouble())) == 1
    assert "iTop failed" in capsys.readouterr().err


def test_unreachable_itop_is_reported(capsys: pytest.CaptureFixture[str]) -> None:
    assert itop_load.run([str(STACK)], itop=loader_for(provisioned(down=True))) == 1
    assert "could not talk to iTop" in capsys.readouterr().err


@pytest.mark.parametrize(
    "text",
    [
        "objects: []\n",
        "- just a list\n",
        "objects:\n  - class: Server\n",
        "objects:\n  - { class: Server, name: a, extra: 1 }\n",
        "objects:\n  - { class: Server, name: a }\n  - { class: Server, name: a }\n",
        "objects:\n  - { class: 'Bad Class', name: a }\n",
        "objects:\n  - { class: Server, name: a, fields: [1] }\n",
        "objects:\n  - { class: Server, name: a, key: [] }\n",
        "objects:\n  - { class: Software, name: nginx }\n",  # the version is part of its key
        "objects:\n  - { class: Server, name: a, fields: { 'bad name': 1 } }\n",
        "objects: [\n",
        "unknown: 1\nobjects:\n  - { class: Server, name: a }\n",
        "env: { lower: '@Server:a' }\nobjects:\n  - { class: Server, name: a }\n",
        "env: { ITOP_ORG_ID: '3' }\nobjects:\n  - { class: Server, name: a }\n",
        "cpe: [a]\nobjects:\n  - { class: Server, name: a }\n",
        "cpe: { nginx: 'cpe:2.3:a:f5:nginx' }\nobjects:\n  - { class: Server, name: a }\n",
        "objects:\n  - { class: Server, name: a, fields: { internet_exposed: no } }\n",  # YAML boolean
        "objects:\n  - { class: SoftwareLicence, name: l, fields: { start_date: 2024-01-15 } }\n",  # YAML date
        "objects:\n  - { class: Team, name: t, fields: { persons_list: [ { person_id: true } ] } }\n",
        'objects:\n  - { class: Server, name: "a\\u0007b" }\n',  # control character in a key value
        'objects:\n  - { class: Server, name: a, fields: { description: "x\\u0000y" } }\n',
        "objects:\n  - { class: Person, name: Garcia, ref: a }\n  - { class: Person, name: Garcia, ref: b }\n",
    ],
)
def test_invalid_files_are_rejected(tmp_path: Path, text: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert itop_load.run([str(write(tmp_path, text))], itop=loader_for(ItopDouble())) == 2
    assert "invalid file" in capsys.readouterr().err


def test_a_missing_file_is_rejected(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert itop_load.run([str(tmp_path / "nope.yaml")], itop=loader_for(ItopDouble())) == 2
    assert "invalid file" in capsys.readouterr().err


def test_cli_needs_url_and_token(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.delenv("ITOP_URL", raising=False)
    monkeypatch.delenv("ITOP_TOKEN", raising=False)
    assert itop_load.run([str(STACK)]) == 2
    assert "ITOP_URL and ITOP_TOKEN" in capsys.readouterr().err


def test_cli_refuses_plain_http_to_a_remote_host(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ITOP_URL", "http://itop.example.com")
    monkeypatch.setenv("ITOP_TOKEN", "t")
    assert itop_load.run([str(STACK)]) == 2
    assert "plain http" in capsys.readouterr().err


@pytest.mark.parametrize("url", ["https://itop.example.com", "http://localhost:8080", "http://127.0.0.1:8080"])
def test_https_and_this_machine_are_accepted(url: str) -> None:
    itop_load.ItopRest(url, "t")


@pytest.mark.parametrize("url", ["http://itop:8080", "http://api:8000", "http://host.docker.internal:8080"])
def test_container_names_get_no_token_over_plain_http(url: str) -> None:
    # The loader runs on this machine: there a bare name may resolve through the DNS search domain to another host.
    with pytest.raises(ValueError, match="plain http"):
        itop_load.ItopRest(url, "t")


def test_a_url_that_is_not_http_is_refused() -> None:
    with pytest.raises(ValueError, match="not an http"):
        itop_load.ItopRest("ftp://itop", "t")


# --- CPE mapping through the Hermes API ---------------------------------------------------------------------------


class FakeApi:
    """Stands in for GET /api/pending/inventory and PUT /api/mappings/{id}; records what it receives."""

    def __init__(self, pending: dict[str, str], status: int = 200) -> None:
        self.pending, self.status = pending, status
        self.puts: list[tuple[str, dict[str, Any]]] = []
        self.auth: list[str] = []
        self.transport = httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.auth.append(request.headers.get("Authorization", ""))
        if self.status != 200:
            return httpx.Response(self.status, json={"message": "Datos inválidos."})
        if request.method == "GET" and request.url.path == "/api/pending/inventory":
            items = [{"ci_id": pid, "name": name, "detail": "Software sin CPE"} for name, pid in self.pending.items()]
            return httpx.Response(200, json={"software_without_cpe": items})
        if request.method == "PUT" and request.url.path.startswith("/api/mappings/"):
            body = json.loads(request.content)
            self.puts.append((request.url.path.rsplit("/", 1)[1], body))
            return httpx.Response(200, json={"software": "x", "cpe": body["cpe"]})
        return httpx.Response(404, json={"message": "No existe."})

    def api(self) -> itop_load.HermesApi:
        return itop_load.HermesApi("http://127.0.0.1:8000", "analyst-token", transport=self.transport)


CPE_FILE = f"""
cpe:
  PostgreSQL: "{CPE_PG}"
  Redshift: null
  Envoy: "cpe:2.3:a:envoyproxy:envoy:*:*:*:*:*:*:*:*"
objects:
  - {{ class: Organization, name: Org }}
"""


def test_map_cpe_sets_the_pending_products_of_the_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeApi({"PostgreSQL": "p-1", "Redshift": "p-2", "Kafka": "p-3"})
    itop = provisioned()
    assert itop_load.run([str(write(tmp_path, CPE_FILE)), "--map-cpe"], itop=loader_for(itop), api=fake.api()) == 0
    assert fake.puts == [("p-1", {"cpe": CPE_PG})]
    assert set(fake.auth) == {"Bearer analyst-token"}
    assert itop.calls == []  # the CPE step never talks to iTop
    out = capsys.readouterr().out
    assert "+ mapped    PostgreSQL" in out
    assert "- no CPE    Redshift" in out
    assert "? skipped   Envoy: not waiting for a CPE" in out
    assert "! pending   Kafka: no CPE for it in the file" in out
    assert "summary: 1 mapped" in out


@pytest.mark.parametrize(("status", "expected"), [(401, "refused the token"), (422, "answered 422")])
def test_map_cpe_reports_api_refusals(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], status: int, expected: str
) -> None:
    fake = FakeApi({}, status=status)
    assert itop_load.run([str(write(tmp_path, CPE_FILE)), "--map-cpe"], api=fake.api()) == 1
    assert expected in capsys.readouterr().err


def test_map_cpe_needs_a_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("HERMES_API_TOKEN", raising=False)
    assert itop_load.run([str(write(tmp_path, CPE_FILE)), "--map-cpe"]) == 2
    assert "HERMES_API_URL and HERMES_API_TOKEN" in capsys.readouterr().err


def test_map_cpe_reports_an_unreachable_api(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    api = itop_load.HermesApi("http://127.0.0.1:8000", "t", transport=httpx.MockTransport(refuse))
    assert itop_load.run([str(write(tmp_path, CPE_FILE)), "--map-cpe"], api=api) == 1
    assert "could not talk to the Hermes API" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("current", "wanted", "expected"),
    [
        ("<p>Synthetic ticket.</p>", "Synthetic ticket.", True),  # iTop wraps an HTML field in a paragraph
        ("Synthetic ticket.", "Other.", False),
        (None, "", True),
        ("2", 2, True),
        (
            [{"functionalci_id": "9", "impact_code": "computed"}, {"functionalci_id": "2", "impact_code": "manual"}],
            [{"functionalci_id": "2", "impact_code": "manual"}],
            True,  # links computed by iTop's impact analysis are not the file's business
        ),
        ([{"person_id": "1"}], [{"person_id": "1"}, {"person_id": "2"}], False),
        ("x", [{"person_id": "1"}], False),
        ({"a": 1}, {"a": 1}, False),  # nested mappings are always written
    ],
)
def test_same(current: Any, wanted: Any, expected: bool) -> None:
    assert itop_load.same(current, wanted) is expected


INSTALLED = """
objects:
  - { class: Organization, name: Org }
  - { class: Software, name: Redis, fields: { vendor: Redis, version: "7.2.0", type: DBServer } }
  - class: SoftwareLicence
    name: BSD-3-Clause · Redis 7.2.0
    fields: { org_id: "@Organization:Org", software_id: "@Software:Redis 7.2.0", perpetual: "yes" }
  - class: VirtualMachine
    name: cache-1
    fields: { org_id: "@Organization:Org", description: Nodo de caché, cpu: "8", ram: "32 GB" }
  - class: DBServer
    name: Redis 7.2.0 @ cache-1
    fields:
      org_id: "@Organization:Org"
      system_id: "@VirtualMachine:cache-1"
      software_id: "@Software:Redis 7.2.0"
      softwarelicence_id: "@SoftwareLicence:BSD-3-Clause · Redis 7.2.0"
      status: active
"""


def test_category_status_licence_description_and_sizing_are_loaded_and_updated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # What the iTop console shows of a software installation (F18.3): the product's category, the installation's
    # status and licence, and the host's description, CPU and RAM. They are plain iTop fields of the file.
    double = ItopDouble()
    assert itop_load.run([str(write(tmp_path, INSTALLED)), "--apply"], itop=loader_for(double)) == 0
    (software,) = rows(double, "Software")
    (licence,) = rows(double, "SoftwareLicence")
    (host,) = rows(double, "VirtualMachine")
    (install,) = rows(double, "DBServer")
    assert software["type"] == "DBServer"
    assert licence["software_id"] == software["id"]
    assert (host["description"], host["cpu"], host["ram"]) == ("Nodo de caché", "8", "32 GB")
    assert (install["status"], install["softwarelicence_id"]) == ("active", licence["id"])
    capsys.readouterr()
    changed = INSTALLED.replace('ram: "32 GB"', 'ram: "64 GB"').replace("status: active", "status: inactive")
    assert itop_load.run([str(write(tmp_path, changed)), "--apply", "--update"], itop=loader_for(double)) == 0
    out = capsys.readouterr().out
    assert "~ update    VirtualMachine 'cache-1': ram" in out
    assert "~ update    DBServer 'Redis 7.2.0 @ cache-1': status" in out
    assert (rows(double, "VirtualMachine")[0]["ram"], rows(double, "DBServer")[0]["status"]) == ("64 GB", "inactive")


def test_an_apply_that_stops_halfway_reports_what_it_wrote(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    text = (
        "objects:\n  - { class: Organization, name: Org }\n  - { class: Server, name: s, fields: { status: weird } }\n"
    )
    assert itop_load.run([str(write(tmp_path, text)), "--apply"], itop=loader_for(ItopDouble())) == 1
    captured = capsys.readouterr()
    assert "written before iTop failed:" in captured.out
    assert "+ create    Organization 'Org'" in captured.out
    assert "Server" not in captured.out
    assert "iTop failed" in captured.err


@pytest.mark.parametrize(
    ("current", "wanted"),
    [("<p>Tom &amp; Jerry</p>", "Tom & Jerry"), ("0", ""), (0, "")],
)
def test_same_ignores_html_entities_and_unset_external_keys(current: Any, wanted: Any) -> None:
    assert itop_load.same(current, wanted)


INVENTORY = ROOT / "inventories" / "lyft-challenge.yaml"


def test_the_approved_inventory_loads_and_a_second_run_changes_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    # D-087: the inventory the user approved, against a double holding what provision.php creates
    double = provisioned()
    double.add("Organization", 901, name="Demo-Lab")
    assert itop_load.run([str(INVENTORY), "--apply", "--update"], itop=loader_for(double)) == 0
    first = capsys.readouterr().out
    assert "summary: 124 created, 1 updated, 0 unchanged" in first  # the organization gets its delivery model
    assert "ITOP_ORG_ID=901\n" in first and "ITOP_CALLER_ID=900\n" in first
    writes = len(double.writes)
    assert itop_load.run([str(INVENTORY), "--apply", "--update"], itop=loader_for(double)) == 0
    assert len(double.writes) == writes
    assert "summary: 0 created, 0 updated, 125 unchanged" in capsys.readouterr().out
    cis = {row["name"]: row for table in ("ApplicationSolution", "VirtualMachine") for row in rows(double, table)}
    assert "internet_exposed" not in cis["svc-reportes-legado"] and "owner_id" not in cis["svc-reportes-legado"]
    assert "custodian_id" not in cis["emr-nodo-02"] and "owner_id" not in cis["emr-nodo-02"]
    assert "internet_exposed" not in cis["superset-bi"]


def test_the_approved_inventory_maps_the_kernel_cpe_of_one_node_only() -> None:
    inventory = itop_load.parse_inventory(INVENTORY)
    assert inventory.cpe["Linux Kernel"] == "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
    assert inventory.cpe["Kernel de Amazon Linux 2023"] is None
    kernels = {
        spec.fields["system_id"]: spec.fields["software_id"]
        for spec in inventory.specs
        if spec.class_name == "OtherSoftware" and "ernel" in spec.fields["software_id"]
    }
    assert [host for host, product in kernels.items() if product == "@Software:Linux Kernel 6.1.0"] == [
        "@VirtualMachine:eks-nodo-01"
    ]
    products = {spec.key["name"] for spec in inventory.specs if spec.class_name == "Software"}
    assert products == set(inventory.cpe)  # every product has a CPE decision, nothing extra
