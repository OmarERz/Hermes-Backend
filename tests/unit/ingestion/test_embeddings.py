"""Embedding adapter without downloading a model: a fake loader stands in for sentence-transformers."""

from __future__ import annotations

import importlib
from typing import Any

import pytest

from core.ingestion.embeddings import (
    EMBEDDING_DIMENSIONS,
    MAX_EMBED_CHARS,
    EmbeddingError,
    SentenceTransformerEmbedder,
    check_vectors,
    embedding_input,
)


class FakeModel:
    def __init__(self, width: int = EMBEDDING_DIMENSIONS, value: float = 0.5) -> None:
        self.width, self.value, self.calls = width, value, 0

    def encode(self, texts: list[str], **_kwargs: Any) -> list[list[float]]:
        self.calls += 1
        return [[self.value] * self.width for _ in texts]


def test_input_is_an_e5_passage_with_title_and_start_of_text() -> None:
    value = embedding_input(" Title ", "body")
    assert value == "passage: Title\nbody"
    assert embedding_input("T", None) == "passage: T\n"
    assert len(embedding_input("T", "x" * 10_000)) == MAX_EMBED_CHARS


def test_model_loads_lazily_once_and_vectors_have_the_schema_width() -> None:
    model = FakeModel()
    loaded: list[str] = []

    def loader(name: str) -> FakeModel:
        loaded.append(name)
        return model

    embed = SentenceTransformerEmbedder(loader=loader)
    assert loaded == []
    assert embed([]) == []
    vectors = embed(["a", "b"])
    embed(["c"])
    assert loaded == ["intfloat/multilingual-e5-small"]
    assert model.calls == 2
    assert len(vectors) == 2
    assert len(vectors[0]) == EMBEDDING_DIMENSIONS


def test_wrong_width_and_non_finite_vectors_are_rejected() -> None:
    with pytest.raises(EmbeddingError, match="wrong shape"):
        SentenceTransformerEmbedder(loader=lambda _n: FakeModel(width=10))(["a"])
    with pytest.raises(EmbeddingError, match="non-finite"):
        SentenceTransformerEmbedder(loader=lambda _n: FakeModel(value=float("nan")))(["a"])
    with pytest.raises(EmbeddingError, match="wrong shape"):
        check_vectors([[0.0] * EMBEDDING_DIMENSIONS], 2)


def test_missing_extra_gives_a_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(_name: str) -> Any:
        raise ImportError

    monkeypatch.setattr(importlib, "import_module", fail)
    with pytest.raises(EmbeddingError, match="embeddings"):
        SentenceTransformerEmbedder()(["a"])
