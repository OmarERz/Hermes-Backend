"""SCRAM-SHA-256 verifiers are computed on the client in PostgreSQL's format."""

from __future__ import annotations

import base64
import hashlib
import hmac

import psycopg
import pytest

from core.db.provision import libpq_url, main, provision, scram_sha256_verifier


def test_verifier_format_and_keys() -> None:
    salt = b"0123456789abcdef"
    verifier = scram_sha256_verifier("s3cret", salt=salt, iterations=4096)
    method, rest = verifier.split("$", 1)
    params, keys = rest.split("$")
    iterations, salt_b64 = params.split(":")
    stored_b64, server_b64 = keys.split(":")
    assert method == "SCRAM-SHA-256"
    assert iterations == "4096"
    assert base64.b64decode(salt_b64) == salt
    salted = hashlib.pbkdf2_hmac("sha256", b"s3cret", salt, 4096)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    assert base64.b64decode(stored_b64) == hashlib.sha256(client_key).digest()
    assert base64.b64decode(server_b64) == hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    assert "s3cret" not in verifier


def test_random_salt_differs() -> None:
    assert scram_sha256_verifier("same") != scram_sha256_verifier("same")


def test_rejects_empty_password_before_connecting() -> None:
    with pytest.raises(ValueError, match="Empty password"):
        provision("postgresql://x@localhost/db", {"app": ""})


def test_remote_provisioning_requires_tls() -> None:
    assert "sslmode=require" in libpq_url("postgresql://su@db.example.com/hermes")
    assert libpq_url("postgresql://su@db/hermes").startswith("postgresql://")


def test_rejects_unknown_role() -> None:
    with pytest.raises(ValueError, match="Not a Hermes login role"):
        provision("postgresql://x@localhost/db", {"postgres": "pw"})


def test_main_requires_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PROVISION_DATABASE_URL", raising=False)
    assert main() == 2
    monkeypatch.setenv("PROVISION_DATABASE_URL", "postgresql://x@localhost/db")
    for env in ("MIGRATOR_DB_PASSWORD", "APP_DB_PASSWORD", "RETENTION_DB_PASSWORD"):
        monkeypatch.delenv(env, raising=False)
    assert main() == 2


def test_superuser_password_never_in_connection_errors() -> None:
    """The superuser password goes as a parameter: a failing connection must not echo it."""
    with_spaces = " ".join(["p", "w", "with", "spaces"])
    with pytest.raises(psycopg.OperationalError) as error:
        provision("postgresql://su@127.0.0.1:1/db", {"app": "x"}, superuser_password=with_spaces)
    assert with_spaces not in str(error.value)
