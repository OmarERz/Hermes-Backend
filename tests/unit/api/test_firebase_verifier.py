"""FirebaseTokenVerifier: error mapping and claim checks with firebase-admin stubbed (no network)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest
from firebase_admin import auth
from firebase_admin import exceptions as firebase_exceptions
from google.auth.exceptions import DefaultCredentialsError

from api.auth import AuthUnavailableError, FirebaseTokenVerifier, Role, TokenError
from api.auth import firebase as firebase_module

GOOD = {"uid": "u1", "sub": "u1", "exp": 4102444800, "email": " ana@example.com ", "name": "Ana", "role": "analyst"}


@pytest.fixture(autouse=True)
def no_emulator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FIREBASE_AUTH_EMULATOR_HOST", raising=False)


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"result": dict(GOOD), "calls": []}

    def fake_verify(token: str, app: Any = None, check_revoked: bool = False) -> dict[str, Any]:
        state["calls"].append((token, check_revoked))
        result = state["result"]
        if isinstance(result, Exception):
            raise result
        return dict(result)

    monkeypatch.setattr(firebase_module.auth, "verify_id_token", fake_verify)
    monkeypatch.setattr(FirebaseTokenVerifier, "_get_app", lambda self: object())
    return state


def test_valid_token_returns_identity_and_checks_revocation(stub: dict[str, Any]) -> None:
    identity = FirebaseTokenVerifier("demo-hermes").verify("tok")
    assert (identity.uid, identity.email, identity.display_name, identity.role) == (
        "u1",
        "ana@example.com",
        "Ana",
        Role.ANALYST,
    )
    assert stub["calls"] == [("tok", True)]


def test_empty_token_is_rejected_without_calling_firebase(stub: dict[str, Any]) -> None:
    with pytest.raises(TokenError) as info:
        FirebaseTokenVerifier("demo-hermes").verify("")
    assert info.value.reason == "token_missing"
    assert stub["calls"] == []


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (auth.ExpiredIdTokenError("m", None), "token_expired"),
        (auth.RevokedIdTokenError("m"), "token_revoked"),
        (auth.UserDisabledError("m"), "user_disabled"),
        (auth.UserNotFoundError("m"), "user_not_found"),
        (auth.InvalidIdTokenError("m"), "token_invalid"),
        (ValueError("bad"), "token_invalid"),
        (TypeError("bad header"), "token_invalid"),
    ],
)
def test_sdk_errors_map_to_token_errors(stub: dict[str, Any], error: Exception, reason: str) -> None:
    stub["result"] = error
    with pytest.raises(TokenError) as info:
        FirebaseTokenVerifier("demo-hermes").verify("tok")
    assert info.value.reason == reason


@pytest.mark.parametrize(
    "error",
    [
        auth.CertificateFetchError("m", None),
        firebase_exceptions.UnavailableError("m"),
        DefaultCredentialsError("no default credentials"),
        OSError("disk"),
    ],
)
def test_backend_failures_fail_closed_as_unavailable(
    stub: dict[str, Any], error: Exception, caplog: pytest.LogCaptureFixture
) -> None:
    stub["result"] = error
    with caplog.at_level(logging.WARNING), pytest.raises(AuthUnavailableError):
        FirebaseTokenVerifier("demo-hermes").verify("tok-xyz")
    assert "tok-xyz" not in caplog.text


@pytest.mark.parametrize(
    ("claims", "reason"),
    [
        ({**GOOD, "role": None}, "role_missing"),
        ({**GOOD, "role": "superuser"}, "role_missing"),
        ({k: v for k, v in GOOD.items() if k != "role"}, "role_missing"),
        ({k: v for k, v in GOOD.items() if k != "email"}, "token_incomplete"),
        ({**GOOD, "email": "  "}, "token_incomplete"),
        ({**GOOD, "uid": ""}, "token_incomplete"),
    ],
)
def test_incomplete_or_roleless_claims_are_rejected(stub: dict[str, Any], claims: dict[str, Any], reason: str) -> None:
    stub["result"] = claims
    with pytest.raises(TokenError) as info:
        FirebaseTokenVerifier("demo-hermes").verify("tok")
    assert info.value.reason == reason


def test_name_claim_is_optional(stub: dict[str, Any]) -> None:
    stub["result"] = {k: v for k, v in GOOD.items() if k != "name"}
    assert FirebaseTokenVerifier("demo-hermes").verify("tok").display_name is None


def test_blank_project_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="empty"):
        FirebaseTokenVerifier("  ")


def test_emulator_is_refused_for_a_real_project(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIREBASE_AUTH_EMULATOR_HOST", "localhost:9099")
    with pytest.raises(ValueError, match="demo-"):
        FirebaseTokenVerifier("my-real-project")
    FirebaseTokenVerifier("demo-hermes")


def test_app_is_created_once_with_project_id(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    created: list[tuple[Any, dict[str, str], str]] = []

    def fake_init(cred: Any, options: dict[str, str], name: str) -> object:
        created.append((cred, options, name))
        return object()

    monkeypatch.setattr(firebase_module.firebase_admin, "initialize_app", fake_init)
    verifier = FirebaseTokenVerifier("demo-hermes")
    first = verifier._get_app()
    assert verifier._get_app() is first
    assert len(created) == 1
    assert created[0][0] is None
    assert created[0][1] == {"projectId": "demo-hermes"}

    monkeypatch.setattr(firebase_module.credentials, "Certificate", lambda path: ("cert", path))
    FirebaseTokenVerifier("demo-hermes", tmp_path / "sa.json")._get_app()
    assert created[1][0] == ("cert", str(tmp_path / "sa.json"))


def test_expired_claim_is_rejected_even_when_the_sdk_does_not_check_it(stub: dict[str, Any]) -> None:
    for exp in (1, None, "soon", True):
        stub["result"] = {**GOOD, "exp": exp}
        with pytest.raises(TokenError) as info:
            FirebaseTokenVerifier("demo-hermes").verify("tok")
        assert info.value.reason == "token_expired"


def test_unreadable_credentials_fail_closed_as_unavailable(tmp_path: Path) -> None:
    verifier = FirebaseTokenVerifier("demo-hermes", tmp_path / "missing.json")
    with pytest.raises(AuthUnavailableError):
        verifier.verify("tok")
