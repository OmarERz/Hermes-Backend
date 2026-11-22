from __future__ import annotations

import json

import httpx
import pytest

from core.devtools import emulator


class FakeEmulator:
    """Minimal in-memory model of the Auth emulator REST endpoints used by the CLI."""

    def __init__(self, *, existing: bool = False, fail_update: bool = False) -> None:
        self.users: dict[str, str] = {"analyst@hermes.test": "uid-1"} if existing else {}
        self.claims: dict[str, str] = {}
        self.calls: list[tuple[str, str]] = []
        self.fail_update = fail_update

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path))
        body = json.loads(request.content)
        if path.endswith("accounts:signUp"):
            if body["email"] in self.users:
                return httpx.Response(400, json={"error": {"message": "EMAIL_EXISTS"}})
            self.users[body["email"]] = f"uid-{len(self.users) + 1}"
            return httpx.Response(200, json={"localId": self.users[body["email"]], "idToken": "early"})
        if path.endswith("accounts:signInWithPassword"):
            uid = self.users[body["email"]]
            return httpx.Response(200, json={"localId": uid, "idToken": f"token-{uid}-{self.claims.get(uid, '')}"})
        if path.endswith("accounts:update"):
            assert request.headers["Authorization"] == "Bearer owner"
            if self.fail_update:
                return httpx.Response(500)
            self.claims[body["localId"]] = body["customAttributes"]
            return httpx.Response(200, json={})
        return httpx.Response(404)


def run(
    monkeypatch: pytest.MonkeyPatch, fake: FakeEmulator, role: str = "analyst", host: str | None = "emu:9099"
) -> int:
    monkeypatch.delenv("FIREBASE_AUTH_EMULATOR_HOST", raising=False)
    if host:
        monkeypatch.setenv("FIREBASE_AUTH_EMULATOR_HOST", host)
    return emulator.main(["token", "--role", role], transport=httpx.MockTransport(fake))


def test_creates_user_sets_claim_and_prints_only_the_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeEmulator()
    assert run(monkeypatch, fake) == 0
    out = capsys.readouterr().out
    assert out == 'token-uid-1-{"role": "analyst"}\n'
    assert fake.claims == {"uid-1": '{"role": "analyst"}'}


def test_reuses_an_existing_user(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeEmulator(existing=True)
    assert run(monkeypatch, fake) == 0
    assert capsys.readouterr().out.startswith("token-uid-1-")
    assert len(fake.users) == 1


def test_refuses_without_emulator_host(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeEmulator()
    assert run(monkeypatch, fake, host=None) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "refusing" in captured.err
    assert fake.calls == []


def test_reports_emulator_failure_without_stdout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(monkeypatch, FakeEmulator(fail_update=True)) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "could not get a test token" in captured.err


def test_rejects_unknown_role() -> None:
    with pytest.raises(emulator.EmulatorError):
        emulator.fetch_token(httpx.Client(transport=httpx.MockTransport(FakeEmulator())), "p", "root")
