"""Local embeddings (ING-07): an injectable function and the sentence-transformers adapter.

The pipeline depends only on `EmbedFn`, so tests pass a deterministic fake and never download a model. The real
model loads lazily on the first call, from the optional `embeddings` extra (it pulls torch).
"""

from __future__ import annotations

import importlib
import math
from collections.abc import Callable, Sequence
from typing import Any

EmbedFn = Callable[[Sequence[str]], list[list[float]]]

# TODO(P-019): confirm the model with the team; it must handle Spanish and English and run on CPU.
EMBEDDING_MODEL = "intfloat/multilingual-e5-small"
EMBEDDING_DIMENSIONS = 384  # story.embedding is vector(384)
MAX_EMBED_CHARS = 1_500  # title plus the start of the text: enough for a 512-token model


def embedding_input(title: str, text: str | None) -> str:
    """The text that represents an article (ING-05 layer 3: title plus summary), as an e5 passage."""
    body = (text or "").strip()
    return f"passage: {title.strip()}\n{body}"[:MAX_EMBED_CHARS]


class EmbeddingError(RuntimeError):
    """The embedding backend is missing or returned vectors that do not fit the schema."""


def check_vectors(vectors: list[list[float]], expected: int) -> list[list[float]]:
    if len(vectors) != expected or any(len(v) != EMBEDDING_DIMENSIONS for v in vectors):
        raise EmbeddingError("The embedding function returned vectors of the wrong shape")
    if any(not math.isfinite(x) for v in vectors for x in v):
        raise EmbeddingError("The embedding function returned a non-finite value")
    return vectors


class SentenceTransformerEmbedder:
    """`EmbedFn` backed by sentence-transformers; the model is loaded on first use."""

    def __init__(self, model_name: str = EMBEDDING_MODEL, loader: Callable[[str], Any] | None = None) -> None:
        self.model_name = model_name
        self._loader = loader or self._load_sentence_transformer
        self._model: Any = None

    @staticmethod
    def _load_sentence_transformer(name: str) -> Any:
        try:
            module = importlib.import_module("sentence_transformers")
        except ImportError as exc:
            raise EmbeddingError("Install the 'embeddings' extra to compute embeddings") from exc
        return module.SentenceTransformer(name, device="cpu")

    def __call__(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            return []
        if self._model is None:
            self._model = self._loader(self.model_name)
        raw = self._model.encode(list(texts), normalize_embeddings=True, show_progress_bar=False)
        vectors = [[float(x) for x in row] for row in raw]
        return check_vectors(vectors, len(texts))
