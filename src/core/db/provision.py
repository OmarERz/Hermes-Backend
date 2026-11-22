"""Database provisioning: run once per start as a superuser, before Alembic (DAT-05).

Applies `migrations/provision.sql` (idempotent: extensions, Hermes-marked roles, schema owner) and gives the login
roles their passwords as client-side SCRAM-SHA-256 verifiers (computed by libpq, with SASLprep), so the server
never receives a plaintext password (not in statements, logs or process arguments; SEG-20).

CLI (compose service `provision`):
    PROVISION_DATABASE_URL=postgresql://<superuser>@db:5432/hermes PGPASSWORD=<superuser password> \\
    MIGRATOR_DB_PASSWORD=... APP_DB_PASSWORD=... RETENTION_DB_PASSWORD=... python -m core.db.provision
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
import sys
import time
from collections.abc import Mapping
from pathlib import Path

import psycopg
from psycopg import sql

from core.config import read_secret
from core.db.session import connection_url
from core.logging import configure_logging

log = logging.getLogger("core.db.provision")

SCRAM_ITERATIONS = 4096
LOGIN_ROLES = {"migrator": "MIGRATOR_DB_PASSWORD", "app": "APP_DB_PASSWORD", "retention": "RETENTION_DB_PASSWORD"}
DEFAULT_SQL = Path("migrations") / "provision.sql"


def scram_sha256_verifier(password: str, *, salt: bytes | None = None, iterations: int = SCRAM_ITERATIONS) -> str:
    """The verifier PostgreSQL stores for SCRAM-SHA-256 (RFC 5802/7677), computed on the client."""
    salt = salt if salt is not None else secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()

    def b64(data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    return f"SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"


def libpq_url(raw: str) -> str:
    """The connection URL with the TLS policy of core.db.session (TLS required off-host), in libpq form."""
    return connection_url(raw).replace("postgresql+psycopg://", "postgresql://", 1)


def provision(
    superuser_url: str,
    passwords: Mapping[str, str],
    sql_path: Path = DEFAULT_SQL,
    superuser_password: str | None = None,
) -> None:
    """Apply the provisioning SQL and set login passwords (only for the roles given), all in one transaction.

    Inputs are validated before anything is written; a failure leaves roles and passwords as they were.
    Verifiers come from libpq (PQencryptPasswordConn), which applies SASLprep exactly like the login does.
    """
    unknown = set(passwords) - set(LOGIN_ROLES)
    if unknown:
        raise ValueError(f"Not a Hermes login role: {sorted(unknown)}")
    empty = sorted(role for role, password in passwords.items() if not password)
    if empty:
        raise ValueError(f"Empty password for roles: {empty}")
    script = sql_path.read_text(encoding="utf-8")
    # The superuser password goes as a separate parameter: never inside a URL that a parser could echo.
    with psycopg.connect(libpq_url(superuser_url), password=superuser_password) as conn, conn.transaction():
        # Defence in depth: even a verifier is not worth logging.
        conn.execute("SET LOCAL log_statement = 'none'")
        conn.execute(script.encode("utf-8"))
        for role, password in passwords.items():
            verifier = conn.pgconn.encrypt_password(password.encode("utf-8"), role.encode(), b"scram-sha-256")
            conn.execute(
                sql.SQL("ALTER ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(role), sql.Literal(verifier.decode()))
            )


def wait_for_database(url: str, timeout_s: float = 60.0, password: str | None = None) -> None:
    """Wait until PostgreSQL accepts TCP connections (the init phase of the image listens on a socket only)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            with psycopg.connect(libpq_url(url), connect_timeout=3, password=password):
                return
        except psycopg.OperationalError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)


def main() -> int:
    passwords = {role: read_secret(env) or "" for role, env in LOGIN_ROLES.items()}
    superuser_password = read_secret("postgres_password") or os.environ.get("PGPASSWORD", "")
    configure_logging([*passwords.values(), superuser_password])
    url = os.environ.get("PROVISION_DATABASE_URL")
    if not url:
        log.error("Set PROVISION_DATABASE_URL to the superuser connection (see core/db/provision.py)")
        return 2
    missing = [LOGIN_ROLES[role] for role, password in passwords.items() if not password]
    if missing:
        log.error("Missing settings: %s", ", ".join(missing))
        return 2
    wait_for_database(url, password=superuser_password or None)
    provision(url, passwords, superuser_password=superuser_password or None)
    log.info("database provisioned")
    return 0


if __name__ == "__main__":
    sys.exit(main())
