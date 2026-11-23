"""Firebase ID token verification and role enforcement against the real Auth emulator (docs/14 §4.2).

Needs Docker; the emulator image is built from docker/auth-emulator (layers are cached after the first build).
Tokens are minted through the emulator REST API: sign up, set the custom claim, sign in again.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from firebase_admin import auth, initialize_app
from pydantic import SecretStr
from testcontainers.core.config import testcontainers_config

from api.app import create_app
from api.auth import FirebaseTokenVerifier, InMemoryUserDirectory, TokenError
from api.auth.role_admin import FirebaseRoleManager
from core.config import Settings

testcontainers_config.ryuk_disabled = True

pytestmark = pytest.mark.integration

PROJECT = "demo-hermes"
IDP = "identitytoolkit.googleapis.com/v1"


@pytest.fixture(autouse=True)
def emulator_env(emulator_host: str, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("FIREBASE_AUTH_EMULATOR_HOST", emulator_host)
    return emulator_host


@pytest.fixture(scope="module")
def admin_app(emulator_host: str) -> Any:
    mp = pytest.MonkeyPatch()
    mp.setenv("FIREBASE_AUTH_EMULATOR_HOST", emulator_host)
    try:
        yield initialize_app(options={"projectId": PROJECT}, name=f"test-{secrets.token_hex(4)}")
    finally:
        mp.undo()


def unsigned_jwt(claims: dict[str, Any]) -> str:
    """Emulator-style unsigned token, built by hand to exercise the issuer and audience checks."""

    def part(data: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    return f"{part({'alg': 'none', 'typ': 'JWT'})}.{part(claims)}."


def mint(host: str, admin_app: Any, role: str | None, email: str | None = None) -> tuple[str, str]:
    """Create a user, set its role claim and return (uid, fresh ID token carrying the claim)."""
    email = email or f"{secrets.token_hex(4)}@example.com"
    password = secrets.token_urlsafe(16)
    base = f"http://{host}/{IDP}"
    signup = httpx.post(
        f"{base}/accounts:signUp?key=fake",
        json={"email": email, "password": password, "returnSecureToken": True},
        timeout=30,
    )
    signup.raise_for_status()
    uid = signup.json()["localId"]
    if role is not None:
        auth.set_custom_user_claims(uid, {"role": role}, app=admin_app)
    signin = httpx.post(
        f"{base}/accounts:signInWithPassword?key=fake",
        json={"email": email, "password": password, "returnSecureToken": True},
        timeout=30,
    )
    signin.raise_for_status()
    return uid, str(signin.json()["idToken"])


def test_missing_or_unknown_role_claim_is_rejected(emulator_host: str, admin_app: Any) -> None:
    verifier = FirebaseTokenVerifier(PROJECT)
    for role in (None, "superuser"):
        _, token = mint(emulator_host, admin_app, role)
        with pytest.raises(TokenError) as info:
            verifier.verify(token)
        assert info.value.reason == "role_missing"


def test_revoked_token_is_rejected(emulator_host: str, admin_app: Any) -> None:
    verifier = FirebaseTokenVerifier(PROJECT)
    uid, token = mint(emulator_host, admin_app, "admin")
    assert verifier.verify(token).uid == uid
    time.sleep(1.1)  # token iat has one-second resolution
    auth.revoke_refresh_tokens(uid, app=admin_app)
    with pytest.raises(TokenError) as info:
        verifier.verify(token)
    assert info.value.reason == "token_revoked"


def test_disabled_user_is_rejected(emulator_host: str, admin_app: Any) -> None:
    verifier = FirebaseTokenVerifier(PROJECT)
    uid, token = mint(emulator_host, admin_app, "reader")
    auth.update_user(uid, disabled=True, app=admin_app)
    with pytest.raises(TokenError) as info:
        verifier.verify(token)
    assert info.value.reason == "user_disabled"


def test_deleted_user_is_rejected(emulator_host: str, admin_app: Any) -> None:
    verifier = FirebaseTokenVerifier(PROJECT)
    uid, token = mint(emulator_host, admin_app, "reader")
    auth.delete_user(uid, app=admin_app)
    with pytest.raises(TokenError) as info:
        verifier.verify(token)
    assert info.value.reason == "user_not_found"


@pytest.mark.parametrize(
    ("aud", "iss"),
    [
        ("other-project", f"https://securetoken.google.com/{PROJECT}"),
        (PROJECT, "https://securetoken.google.com/other-project"),
    ],
)
def test_wrong_audience_or_issuer_is_rejected(emulator_host: str, aud: str, iss: str) -> None:
    now = int(time.time())
    claims = {
        "aud": aud,
        "iss": iss,
        "sub": "u1",
        "iat": now,
        "exp": now + 3600,
        "email": "a@example.com",
        "role": "admin",
    }
    token = unsigned_jwt(claims)
    with pytest.raises(TokenError) as info:
        FirebaseTokenVerifier(PROJECT).verify(token)
    assert info.value.reason == "token_invalid"


def test_expired_token_is_rejected_although_the_emulator_skips_the_check(emulator_host: str, admin_app: Any) -> None:
    uid, _ = mint(emulator_host, admin_app, "admin")
    now = int(time.time())
    claims = {
        "aud": PROJECT,
        "iss": f"https://securetoken.google.com/{PROJECT}",
        "sub": uid,
        "iat": now,
        "exp": now - 10,
        "email": "a@example.com",
        "role": "admin",
    }
    with pytest.raises(TokenError) as info:
        FirebaseTokenVerifier(PROJECT).verify(unsigned_jwt(claims))
    assert info.value.reason == "token_expired"


def client_for() -> TestClient:
    settings = Settings(
        _env_file=None,
        cursor_signing_key=SecretStr("k" * 40),
        database_url=SecretStr("postgresql://app:pw@db/hermes"),
        firebase_project_id=PROJECT,
    )
    verifier = FirebaseTokenVerifier(PROJECT)
    return TestClient(
        create_app(
            settings,
            token_verifier=verifier,
            user_directory=InMemoryUserDirectory(),
            role_manager=FirebaseRoleManager(verifier),
        )
    )


def test_roles_through_the_api(emulator_host: str, admin_app: Any) -> None:
    client = client_for()
    for role in ("reader", "analyst", "admin"):
        _, token = mint(emulator_host, admin_app, role)
        response = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200, response.text
        assert response.json()["role"] == role


def test_api_rejects_missing_garbage_and_roleless_tokens(emulator_host: str, admin_app: Any) -> None:
    client = client_for()
    assert client.get("/api/me").status_code == 401
    assert client.get("/api/me", headers={"Authorization": "Bearer not-a-jwt"}).status_code == 401
    _, roleless = mint(emulator_host, admin_app, None)
    assert client.get("/api/me", headers={"Authorization": f"Bearer {roleless}"}).status_code == 401


def test_reader_is_forbidden_on_the_admin_route(emulator_host: str, admin_app: Any) -> None:
    client = client_for()
    target, _ = mint(emulator_host, admin_app, "reader")
    _, reader_token = mint(emulator_host, admin_app, "reader")
    response = client.put(
        f"/api/admin/users/{target}/role", json={"role": "admin"}, headers={"Authorization": f"Bearer {reader_token}"}
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


def test_admin_assigns_a_role_and_revokes_the_old_sessions(emulator_host: str, admin_app: Any) -> None:
    client = client_for()
    target, target_token = mint(emulator_host, admin_app, "analyst")
    _, admin_token = mint(emulator_host, admin_app, "admin")
    assert client.get("/api/me", headers={"Authorization": f"Bearer {target_token}"}).status_code == 200
    # No wait here: the role manager itself revokes after the next full second (second-granular revocation).

    response = client.put(
        f"/api/admin/users/{target}/role", json={"role": "reader"}, headers={"Authorization": f"Bearer {admin_token}"}
    )

    assert response.status_code == 200, response.text
    assert response.json() == {"uid": target, "role": "reader", "sessions_revoked": True, "known_user": True}
    assert auth.get_user(target, app=admin_app).custom_claims == {"role": "reader"}
    # The analyst token issued before the change is revoked.
    assert client.get("/api/me", headers={"Authorization": f"Bearer {target_token}"}).status_code == 401


def test_unknown_uid_is_not_found(emulator_host: str, admin_app: Any) -> None:
    client = client_for()
    _, admin_token = mint(emulator_host, admin_app, "admin")
    response = client.put(
        "/api/admin/users/no-such-user/role",
        json={"role": "reader"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 404
