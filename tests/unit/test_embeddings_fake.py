"""The CI stand-in of the embeddings service (`docker/embeddings-fake/server.py`): same contract, standard library."""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import httpx
import pytest

from core.ingestion.embeddings import EMBEDDING_DIMENSIONS, EMBEDDING_MODEL, HttpEmbedder

pytestmark = pytest.mark.unit
SERVER = Path(__file__).resolve().parents[2] / "docker" / "embeddings-fake" / "server.py"


def load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("embeddings_fake_server", SERVER)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def fake() -> Iterator[tuple[ModuleType, str]]:
    module = load()
    server = module.serve("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield module, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def test_the_worker_client_accepts_the_fake(fake: tuple[ModuleType, str]) -> None:
    _, url = fake
    vectors = HttpEmbedder(url)(["passage: acme firewall flaw", "passage: acme firewall flaw reported", "passage: "])
    assert [len(v) for v in vectors] == [EMBEDDING_DIMENSIONS] * 3
    similar = sum(a * b for a, b in zip(vectors[0], vectors[1], strict=True))
    assert 0.8 < similar < 1.0  # shared words, deterministic


def client(url: str) -> httpx.Client:
    return httpx.Client(base_url=url, timeout=5.0)


def test_health_and_unknown_paths(fake: tuple[ModuleType, str]) -> None:
    _, url = fake
    with client(url) as http:
        assert http.get("/health").json() == {"status": "ok", "model": EMBEDDING_MODEL, "revision": "ci-fake"}
        assert http.get("/other").status_code == 404
        assert http.post("/other", json={}).status_code == 404


@pytest.mark.parametrize(
    "body",
    [b"not json", b"[]", b'{"texts": []}', b'{"texts": [1]}', b'{"texts": ["x"], "extra": 1}', b'{"texts": "x"}'],
)
def test_invalid_requests_are_422(fake: tuple[ModuleType, str], body: bytes) -> None:
    _, url = fake
    with client(url) as http:
        assert http.post("/embed", content=body).status_code == 422


def test_limits_match_the_real_service(fake: tuple[ModuleType, str]) -> None:
    module, url = fake
    too_many = json.dumps({"texts": ["x"] * (module.MAX_TEXTS + 1)})
    big = b"x" * (module.MAX_BODY_BYTES + 1)

    def chunked(*parts: bytes) -> Iterator[bytes]:  # no Content-Length: sent with Transfer-Encoding chunked
        yield from parts

    with client(url) as http:
        assert http.post("/embed", content=too_many).status_code == 422
        assert http.post("/embed", content=json.dumps({"texts": ["x" * 4_001]})).status_code == 422
        assert http.post("/embed", content=big).status_code == 413
        valid = http.post("/embed", content=chunked(b'{"texts": ', b'["passage: a"]}'))
        assert (valid.status_code, len(valid.json()["vectors"])) == (200, 1)
    with client(url) as http:  # the server closes the connection after a 413 on a chunked body
        assert http.post("/embed", content=chunked(*[b"x" * module.MAX_BODY_BYTES] * 2)).status_code == 413
