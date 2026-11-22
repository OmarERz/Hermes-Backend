from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from doubles.itop import ItopDouble
from harness import itop_seed

ROOT = Path(__file__).resolve().parents[2]
STACK = ROOT / "docker" / "itop" / "stack.yaml"


def provisioned(**kwargs: Any) -> ItopDouble:
    """A double holding what provision.php creates before the seed runs: the system person."""
    double = ItopDouble(**kwargs)
    double.add("Person", 900, name="Hermes System", first_name="Hermes")
    return double


def loader_for(double: ItopDouble) -> itop_seed.ItopRest:
    return itop_seed.ItopRest("http://127.0.0.1", "test-token", transport=double.transport)


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "stack.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_dry_run_writes_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    double = provisioned()
    assert itop_seed.run([str(STACK)], itop=loader_for(double)) == 0
    assert double.writes == []
    assert "dry run" in capsys.readouterr().out


def test_apply_loads_the_synthetic_stack_with_extension_attributes() -> None:
    double = provisioned()
    assert itop_seed.run([str(STACK), "--apply"], itop=loader_for(double)) == 0
    servers = {row["name"]: row for row in double.data["Server"].values()}
    web = servers["web-frontend-01"]
    assert (web["internet_exposed"], web["confidentiality"], web["personal_data"]) == ("yes", "public", "no")
    person_id = next(r["id"] for r in double.data["Person"].values() if r["name"] == "Rivera")
    team_id = next(r["id"] for r in double.data["Team"].values() if r["name"] == "Platform Ops")
    assert web["owner_id"] == person_id
    assert web["custodian_id"] == team_id
    legacy = next(r for r in double.data["VirtualMachine"].values() if r["name"] == "vm-legacy-01")
    assert "owner_id" not in legacy  # incomplete on purpose (inventory pending)
    installs = [r for table in ("WebServer", "DBServer", "OtherSoftware") for r in double.data[table].values()]
    assert len(installs) == 4
    assert all(r["system_id"] and r["software_id"] for r in installs)


def test_second_apply_creates_nothing() -> None:
    double = provisioned()
    itop_seed.run([str(STACK), "--apply"], itop=loader_for(double))
    writes = len(double.writes)
    assert itop_seed.run([str(STACK), "--apply"], itop=loader_for(double)) == 0
    assert len(double.writes) == writes


def test_update_rewrites_existing_fields(tmp_path: Path) -> None:
    double = ItopDouble()
    itop = loader_for(double)
    base = "objects:\n  - class: Organization\n    name: Demo-Lab\n"
    itop_seed.run([str(write(tmp_path, base)), "--apply"], itop=itop)
    changed = base + "    fields: { code: X }\n"
    itop_seed.run([str(write(tmp_path, changed)), "--apply", "--update"], itop=itop)
    assert next(iter(double.data["Organization"].values()))["code"] == "X"


def test_broken_reference_writes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    double = ItopDouble()
    path = write(tmp_path, 'objects:\n  - class: Server\n    name: s\n    fields: { org_id: "@Organization:Nope" }\n')
    assert itop_seed.run([str(path), "--apply"], itop=loader_for(double)) == 1
    assert double.writes == []
    assert "Nope" in capsys.readouterr().err


def test_itop_rejection_is_reported(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write(tmp_path, "objects:\n  - class: Server\n    name: s\n    fields: { org_id: '1', status: weird }\n")
    assert itop_seed.run([str(path), "--apply"], itop=loader_for(ItopDouble())) == 1
    assert "iTop failed" in capsys.readouterr().err


def test_unreachable_itop_is_reported(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    double = provisioned(down=True)
    assert itop_seed.run([str(STACK)], itop=loader_for(double)) == 1
    assert "could not talk to iTop" in capsys.readouterr().err


@pytest.mark.parametrize(
    "text",
    [
        "objects: []\n",
        "objects:\n  - class: Server\n",
        "objects:\n  - { class: Server, name: a, extra: 1 }\n",
        "objects:\n  - { class: Server, name: a }\n  - { class: Server, name: a }\n",
        "objects:\n  - { class: 'Bad Class', name: a }\n",
        "objects: [\n",
    ],
)
def test_invalid_files_are_rejected(tmp_path: Path, text: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert itop_seed.run([str(write(tmp_path, text))], itop=loader_for(ItopDouble())) == 2
    assert "invalid file" in capsys.readouterr().err


def test_cli_needs_url_and_token(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.delenv("ITOP_URL", raising=False)
    monkeypatch.delenv("ITOP_TOKEN", raising=False)
    assert itop_seed.run([str(STACK)]) == 2
    assert "ITOP_URL and ITOP_TOKEN" in capsys.readouterr().err


def test_cli_refuses_plain_http_to_a_remote_host(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ITOP_URL", "http://itop.example.com")
    monkeypatch.setenv("ITOP_TOKEN", "t")
    assert itop_seed.run([str(STACK)]) == 2
    assert "plain http" in capsys.readouterr().err


def test_https_and_loopback_are_accepted() -> None:
    itop_seed.ItopRest("https://itop.example.com", "t")
    itop_seed.ItopRest("http://localhost:8080", "t")
    itop_seed.ItopRest("http://127.0.0.1:8080", "t")


def test_oql_quoting() -> None:
    assert itop_seed.select_by("Person", "name", "O'Brien") == "SELECT Person WHERE name = 'O\\'Brien'"
    with pytest.raises(ValueError, match="control"):
        itop_seed.quote("a\nb")
    with pytest.raises(ValueError, match="invalid"):
        itop_seed.select_by("Person; DROP", "name", "x")


def test_sample_ticket_has_the_d036_shape() -> None:
    double = provisioned()
    itop_seed.run([str(STACK), "--apply"], itop=loader_for(double))
    (ticket,) = double.data["UserRequest"].values()
    team_id = next(r["id"] for r in double.data["Team"].values() if r["name"] == "Platform Ops")
    system = next(r["id"] for r in double.data["Person"].values() if r["name"] == "Hermes System")
    assert ticket["status"] == "new"
    assert ticket["team_id"] == team_id
    assert ticket["caller_id"] == system
    assert ticket["agent_id"] == ""
    assert ticket["service_id"]
    assert len(ticket["contacts_list"]) == 1
    links = [r for r in double.data["lnkFunctionalCIToTicket"].values() if r["ticket_id"] == ticket["id"]]
    assert len(links) == 2
    assert {link["impact_code"] for link in links} == {"manual"}
