"""Production path (no emulator): the SDK really checks the RS256 signature, using a local test certificate."""

from __future__ import annotations

import datetime
import time
from typing import Any

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from firebase_admin import _auth_client, credentials, initialize_app
from google.auth.credentials import AnonymousCredentials
from google.oauth2 import id_token

from api.auth import FirebaseTokenVerifier, Role, TokenError

PROJECT = "hermes-prod-test"
KID = "test-kid"


class _FakeCredential(credentials.Base):
    def get_credential(self) -> AnonymousCredentials:
        return AnonymousCredentials()


def _key_and_cert() -> tuple[rsa.RSAPrivateKey, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return key, cert.public_bytes(serialization.Encoding.PEM).decode()


def _token(key: rsa.RSAPrivateKey) -> str:
    now = int(time.time())
    claims = {
        "aud": PROJECT,
        "iss": f"https://securetoken.google.com/{PROJECT}",
        "sub": "u1",
        "iat": now,
        "exp": now + 3600,
        "email": "ana@example.com",
        "role": "admin",
    }
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": KID})


@pytest.fixture
def verifier(monkeypatch: pytest.MonkeyPatch) -> tuple[FirebaseTokenVerifier, rsa.RSAPrivateKey]:
    monkeypatch.delenv("FIREBASE_AUTH_EMULATOR_HOST", raising=False)
    key, cert = _key_and_cert()
    monkeypatch.setattr(id_token, "_fetch_certs", lambda request, certs_url: {KID: cert})
    monkeypatch.setattr(_auth_client.Client, "_check_jwt_revoked_or_disabled", lambda *args, **kwargs: None)
    instance = FirebaseTokenVerifier(PROJECT)
    app = initialize_app(_FakeCredential(), {"projectId": PROJECT}, name=f"sig-{time.time_ns()}")
    monkeypatch.setattr(instance, "_get_app", lambda: app)
    return instance, key


def test_valid_signature_is_accepted(verifier: tuple[FirebaseTokenVerifier, rsa.RSAPrivateKey]) -> None:
    instance, key = verifier
    identity = instance.verify(_token(key))
    assert identity.role is Role.ADMIN


def test_signature_from_another_key_is_rejected(verifier: tuple[FirebaseTokenVerifier, rsa.RSAPrivateKey]) -> None:
    instance, _ = verifier
    other, _cert = _key_and_cert()
    with pytest.raises(TokenError) as info:
        instance.verify(_token(other))
    assert info.value.reason == "token_invalid"


def test_unsigned_token_is_rejected(verifier: tuple[FirebaseTokenVerifier, rsa.RSAPrivateKey]) -> None:
    instance, key = verifier
    head, body, _sig = _token(key).split(".")
    with pytest.raises(TokenError):
        instance.verify(f"{head}.{body}.")


def test_tampered_payload_is_rejected(verifier: tuple[FirebaseTokenVerifier, rsa.RSAPrivateKey]) -> None:
    instance, key = verifier
    head, _body, sig = _token(key).split(".")
    forged: Any = jwt.utils.base64url_encode(b'{"aud":"hermes-prod-test","sub":"x"}').decode()
    with pytest.raises(TokenError):
        instance.verify(f"{head}.{forged}.{sig}")
