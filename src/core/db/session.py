"""Engine and session factory. URLs use the psycopg 3 driver."""

from __future__ import annotations

import ipaddress
import os

from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from core.config import Settings


def sqlalchemy_url(raw: str) -> str:
    """Map a plain postgresql:// URL to the psycopg 3 SQLAlchemy driver."""
    for prefix in ("postgresql+psycopg://", "postgresql://", "postgres://"):
        if raw.startswith(prefix):
            return "postgresql+psycopg://" + raw[len(prefix) :]
    raise ValueError("DATABASE_URL must be a PostgreSQL URL")


# Hosts that never leave this machine: Unix sockets, loopback and the compose database service.
LOCAL_SERVICE_HOSTS = frozenset({"localhost", "db"})
PLAINTEXT_SSLMODES = frozenset({"disable", "allow", "prefer"})


def is_local_host(host: str | None) -> bool:
    """A Unix socket, loopback address, `localhost` or the compose service `db`."""
    if not host or host.startswith("/"):
        return True
    if host in LOCAL_SERVICE_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def connection_url(raw: str) -> str:
    """psycopg 3 URL; a connection that leaves the host must use TLS (docs/14 §10.4).

    Every effective host counts (the URL host and any `host`/`hostaddr` query parameter). A remote target
    gets `sslmode=require` by default and an explicit mode that allows plaintext is rejected.
    """
    netloc = sqlalchemy_url(raw).split("://", 1)[1].split("/", 1)[0].rsplit("@", 1)[-1]
    if "," in netloc:
        raise ValueError("Multi-host (failover) PostgreSQL URLs are not supported; use a single host")
    url = make_url(sqlalchemy_url(raw))
    # Without a host in the URL, libpq takes it from PGHOST/PGHOSTADDR or a service file: count those too.
    hosts: list[str | None] = [url.host] if url.host else [os.environ.get("PGHOST"), os.environ.get("PGHOSTADDR")]
    if not url.host and os.environ.get("PGSERVICE"):
        hosts.append("service:" + os.environ["PGSERVICE"])
    for key in ("host", "hostaddr"):
        value = url.query.get(key)
        values = value if isinstance(value, tuple) else (value,) if value else ()
        for item in values:
            hosts.extend(h.strip() for h in item.split(","))
    if all(is_local_host(h) for h in hosts):
        return url.render_as_string(hide_password=False)
    mode = url.query.get("sslmode")
    if mode is None:
        url = url.update_query_dict({"sslmode": "require"})
    elif not isinstance(mode, str) or mode in PLAINTEXT_SSLMODES:
        raise ValueError("A remote PostgreSQL connection must use TLS (sslmode require, verify-ca or verify-full)")
    return url.render_as_string(hide_password=False)


def make_engine(url: str, *, echo: bool = False) -> Engine:
    return create_engine(connection_url(url), echo=echo, pool_pre_ping=True)


def with_password(raw: str, password: str | None) -> str:
    """Add the password from a secret when the URL has none (compose mounts it as a Docker secret)."""
    url = make_url(sqlalchemy_url(raw))
    if url.password or not password:
        return raw
    return url.set(password=password).render_as_string(hide_password=False)


def make_session_factory(settings: Settings) -> sessionmaker[Session]:
    password = settings.pgpassword.get_secret_value() if settings.pgpassword else None
    engine = make_engine(with_password(settings.database_url.get_secret_value(), password))
    return sessionmaker(engine, expire_on_commit=False)
