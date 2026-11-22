"""The engine connects to PostgreSQL 18 with the psycopg 3 driver."""

from __future__ import annotations

import pytest
from pydantic import SecretStr
from sqlalchemy import text
from testcontainers.core.config import testcontainers_config

from core.config import Settings
from core.db.session import connection_url, is_local_host, make_engine, make_session_factory, sqlalchemy_url

pytestmark = pytest.mark.integration


def test_connects_to_postgres_18(postgres_url: str) -> None:
    engine = make_engine(postgres_url)
    with engine.connect() as conn:
        version = conn.execute(text("SHOW server_version_num")).scalar_one()
        available = conn.execute(
            text("SELECT count(*) FROM pg_available_extensions WHERE name = 'vector'")
        ).scalar_one()
    engine.dispose()
    assert int(version) >= 180000
    assert available == 1


@pytest.mark.parametrize("raw", ["postgresql://u:p@h/db", "postgres://u:p@h/db", "postgresql+psycopg://u:p@h/db"])
def test_url_uses_psycopg3(raw: str) -> None:
    assert sqlalchemy_url(raw) == "postgresql+psycopg://u:p@h/db"


def test_rejects_non_postgres_url() -> None:
    with pytest.raises(ValueError, match="PostgreSQL"):
        sqlalchemy_url("sqlite:///x.db")


def test_ryuk_helper_disabled_and_pinned() -> None:
    assert testcontainers_config.ryuk_disabled
    assert "@sha256:" in testcontainers_config.ryuk_image


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "::1", "db", None, "/var/run/postgresql"])
def test_local_hosts(host: str | None) -> None:
    assert is_local_host(host)


@pytest.mark.parametrize("host", ["db.example.com", "10.0.0.5", "203.0.113.7", "pgserver"])
def test_remote_hosts(host: str) -> None:
    assert not is_local_host(host)


def test_remote_connection_requires_tls() -> None:
    assert "sslmode=require" in connection_url("postgresql://u:p@db.example.com:5432/hermes")


def test_explicit_sslmode_is_kept() -> None:
    assert "sslmode=verify-full" in connection_url("postgresql://u:p@db.example.com/hermes?sslmode=verify-full")


def test_local_connection_unchanged() -> None:
    assert "sslmode" not in connection_url("postgresql://u:p@db:5432/hermes")


@pytest.mark.parametrize("mode", ["disable", "allow", "prefer"])
def test_remote_plaintext_sslmode_rejected(mode: str) -> None:
    with pytest.raises(ValueError, match="TLS"):
        connection_url(f"postgresql://u:p@db.example.com/hermes?sslmode={mode}")


def test_remote_host_in_query_parameter_requires_tls() -> None:
    assert "sslmode=require" in connection_url("postgresql://u:p@localhost/hermes?host=db.example.com")


def test_remote_hostaddr_with_plaintext_rejected() -> None:
    with pytest.raises(ValueError, match="TLS"):
        connection_url("postgresql://u:p@db/hermes?hostaddr=203.0.113.7&sslmode=disable")


def test_session_factory_queries_the_database(postgres_url: str) -> None:
    settings = Settings(  # type: ignore[call-arg]
        _env_file=None,
        database_url=SecretStr(postgres_url),
        firebase_project_id="demo-hermes",
        cursor_signing_key=SecretStr("k" * 40),
    )
    factory = make_session_factory(settings)
    with factory() as session:
        assert session.execute(text("SELECT 1")).scalar_one() == 1
    factory.kw["bind"].dispose()


def test_multihost_url_rejected_clearly() -> None:
    with pytest.raises(ValueError, match="Multi-host"):
        connection_url("postgresql://u:p@db1.example.com:5432,db2.example.com:5433/hermes")


def test_hostless_url_with_remote_pghost_requires_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PGHOST", "db.example.com")
    assert "sslmode=require" in connection_url("postgresql://u:p@/hermes")


def test_hostless_url_with_service_requires_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PGHOST", raising=False)
    monkeypatch.setenv("PGSERVICE", "hermes")
    assert "sslmode=require" in connection_url("postgresql://u:p@/hermes")


def test_hostless_url_without_env_is_local_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("PGHOST", "PGHOSTADDR", "PGSERVICE"):
        monkeypatch.delenv(name, raising=False)
    assert "sslmode" not in connection_url("postgresql://u:p@/hermes")
