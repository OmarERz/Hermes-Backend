"""The embeddings service (`docker/embeddings/app.py`) with a fake encoder: no torch, no model download."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.unit
APP = Path(__file__).resolve().parents[2] / "docker" / "embeddings" / "app.py"


def service() -> ModuleType:
    spec = importlib.util.spec_from_file_location("embeddings_service_app", APP)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # FastAPI resolves the postponed annotations through the module
    spec.loader.exec_module(module)
    return module


def fake(texts: Sequence[str]) -> list[list[float]]:
    return [[float(len(text))] * 384 for text in texts]


def client() -> TestClient:
    return TestClient(service().create_app(fake))


def test_embed_returns_one_vector_per_text_in_order() -> None:
    response = client().post("/embed", json={"texts": ["passage: a", "passage: bbb"]})
    assert response.status_code == 200
    body = response.json()
    assert (body["model"], body["dimensions"]) == ("intfloat/multilingual-e5-small", 384)
    assert [row[0] for row in body["vectors"]] == [10.0, 12.0]


@pytest.mark.parametrize(
    "body",
    [
        {"texts": []},
        {"texts": ["x"] * 65},
        {"texts": ["x" * 4_001]},
        {"texts": [1]},
        {"texts": ["x"], "extra": True},
        {},
    ],
)
def test_out_of_bounds_requests_are_rejected(body: object) -> None:
    assert client().post("/embed", json=body).status_code == 422


def test_health_and_no_documentation_routes() -> None:
    api = client()
    assert api.get("/health").json() == {"status": "ok", "model": "intfloat/multilingual-e5-small"}
    assert api.get("/docs").status_code == 404
    assert api.get("/openapi.json").status_code == 404


def test_the_real_encoder_needs_sentence_transformers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Outside the service image sentence-transformers is missing: building the real encoder fails loudly."""
    module = service()
    monkeypatch.setitem(sys.modules, "sentence_transformers", None)
    with pytest.raises(ImportError):
        module.create_app()
