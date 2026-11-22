"""Shared integration fixtures: one PostgreSQL 18 + pgvector container per test session (docs/14 §5)."""

from __future__ import annotations

import secrets
from collections.abc import Iterator

import pytest
from testcontainers.core.config import testcontainers_config
from testcontainers.postgres import PostgresContainer

# Ryuk (testcontainers' cleanup helper) mounts the Docker socket and publishes an unauthenticated control
# port on every interface. It stays disabled: the fixtures stop their containers on teardown, and a
# container left by a killed run is removed with `docker rm -f`. Its image stays pinned in case it is
# ever enabled again (docs/14 §10.4).
RYUK_IMAGE = "testcontainers/ryuk:0.8.1@sha256:bf3f74a47dee0acda89aba4b2fc9c7fdcf994a084db02a2d06566f07baae022e"
testcontainers_config.ryuk_image = RYUK_IMAGE
testcontainers_config.ryuk_disabled = True

# Same image as compose.yaml
POSTGRES_IMAGE = "pgvector/pgvector:pg18@sha256:38681dc6eaf55308e2a4c6de392d131652dcfac70e1263e35cd9b5ea3fe39782"


@pytest.fixture(scope="session")
def postgres_url() -> Iterator[str]:
    """Superuser URL (plain postgresql://) of a throwaway database."""
    throwaway = {"username": "postgres", "password": secrets.token_urlsafe(16), "dbname": "hermes"}
    with PostgresContainer(POSTGRES_IMAGE, driver=None, **throwaway) as pg:
        yield pg.get_connection_url()
