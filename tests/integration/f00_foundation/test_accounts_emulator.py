"""FirebaseAccountManager against the real Auth emulator (D-105, F18.8): an account created without a password gets the
password e-mail through Identity Toolkit, the person chooses a password with the code and signs in with the role; an
account switched off cannot sign in and its live token is refused.

Needs Docker (the emulator container); no network and no real Firebase project. The emulator keeps the out-of-band
codes it would e-mail, which stands in for the person's mailbox.
"""

from __future__ import annotations

import secrets
from typing import Any

import httpx
import pytest
from firebase_admin import auth
from testcontainers.core.config import testcontainers_config

from api.auth import FirebaseTokenVerifier, Role, TokenError
from api.auth.accounts import AccountInfo, EmailInUseError, FirebaseAccountManager, new_uid
from api.auth.role_admin import UnknownUserError

testcontainers_config.ryuk_disabled = True

pytestmark = pytest.mark.integration

PROJECT = "demo-hermes"
IDP = "identitytoolkit.googleapis.com/v1"


@pytest.fixture
def verifier(emulator_host: str, monkeypatch: pytest.MonkeyPatch) -> FirebaseTokenVerifier:
    monkeypatch.setenv("FIREBASE_AUTH_EMULATOR_HOST", emulator_host)
    return FirebaseTokenVerifier(PROJECT)


def _mailbox(host: str, email: str) -> list[dict[str, Any]]:
    """The out-of-band codes the emulator would have e-mailed to ``email``."""
    response = httpx.get(f"http://{host}/emulator/v1/projects/{PROJECT}/oobCodes", timeout=30)
    response.raise_for_status()
    return [code for code in response.json()["oobCodes"] if code["email"] == email]


def _sign_in(host: str, email: str, password: str) -> httpx.Response:
    return httpx.post(
        f"http://{host}/{IDP}/accounts:signInWithPassword?key=fake",
        json={"email": email, "password": password, "returnSecureToken": True},
        timeout=30,
    )


def test_a_new_account_chooses_its_password_from_the_email_and_signs_in_with_its_role(
    emulator_host: str, verifier: FirebaseTokenVerifier
) -> None:
    manager = FirebaseAccountManager(verifier)
    email = f"new-{secrets.token_hex(4)}@example.com"

    account = manager.create(new_uid(), email, Role.ANALYST)

    user = auth.get_user(account.uid, app=verifier.sdk_app())
    assert (account.email, user.email_verified, user.custom_claims) == (email, False, {"role": "analyst"})
    assert user.provider_data == []  # no password: nobody can sign in until the person chooses one
    assert _sign_in(emulator_host, email, secrets.token_urlsafe(12)).status_code == 400

    manager.send_password_setup(email, "127.0.0.1")

    [code] = _mailbox(emulator_host, email)
    assert code["requestType"] == "PASSWORD_RESET"
    password = secrets.token_urlsafe(16)
    reset = httpx.post(
        f"http://{emulator_host}/{IDP}/accounts:resetPassword?key=fake",
        json={"oobCode": code["oobCode"], "newPassword": password},
        timeout=30,
    )
    reset.raise_for_status()
    signed_in = _sign_in(emulator_host, email, password)
    signed_in.raise_for_status()
    identity = verifier.verify(signed_in.json()["idToken"])
    assert (identity.uid, identity.role) == (account.uid, Role.ANALYST)


def test_an_account_switched_off_cannot_sign_in_and_its_token_is_refused(
    emulator_host: str, verifier: FirebaseTokenVerifier
) -> None:
    manager = FirebaseAccountManager(verifier)
    email = f"off-{secrets.token_hex(4)}@example.com"
    account = manager.create(new_uid(), email, Role.READER)
    password = secrets.token_urlsafe(16)
    auth.update_user(account.uid, password=password, app=verifier.sdk_app())  # as if the person chose it
    token = _sign_in(emulator_host, email, password).json()["idToken"]

    assert manager.set_disabled(account.uid, True) is True

    assert manager.lookup(account.uid) == AccountInfo(uid=account.uid, email=email, disabled=True)
    with pytest.raises(TokenError) as refused:
        verifier.verify(token)
    assert refused.value.reason in {"user_disabled", "token_revoked"}
    assert _sign_in(emulator_host, email, password).json()["error"]["message"] == "USER_DISABLED"

    assert manager.set_disabled(account.uid, True) is True  # again: the revocation is repeated, nothing else
    assert manager.set_disabled(account.uid, False) is True
    signed_in = _sign_in(emulator_host, email, password)
    assert signed_in.status_code == 200
    # The session of before the switch-off does not come back to life with the account.
    with pytest.raises(TokenError) as still_refused:
        verifier.verify(token)
    assert still_refused.value.reason == "token_revoked"
    # A repeated switch-on already applied (on in Hermes too) leaves the session opened since alone...
    fresh = signed_in.json()["idToken"]
    assert manager.set_disabled(account.uid, False, on_in_hermes=True) is False
    assert verifier.verify(fresh).uid == account.uid
    # ...while a switch-on after a switch-off that never reached Firebase revokes the sessions of before.
    assert manager.set_disabled(account.uid, False, on_in_hermes=False) is True
    with pytest.raises(TokenError) as revoked:
        verifier.verify(fresh)
    assert revoked.value.reason == "token_revoked"


def test_a_taken_email_is_refused_and_a_discarded_account_is_gone(verifier: FirebaseTokenVerifier) -> None:
    manager = FirebaseAccountManager(verifier)
    email = f"dup-{secrets.token_hex(4)}@example.com"
    account = manager.create(new_uid(), email, Role.READER)

    with pytest.raises(EmailInUseError):
        manager.create(new_uid(), email, Role.ADMIN)

    manager.discard(account.uid)
    manager.discard(account.uid)  # gone already: no error
    with pytest.raises(UnknownUserError):
        manager.lookup(account.uid)
    with pytest.raises(UnknownUserError):
        manager.set_disabled(account.uid, True)
