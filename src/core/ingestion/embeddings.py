"""Local embeddings (ING-07): an injectable function and the client of the embeddings service.

The pipeline depends only on `EmbedFn`, so tests pass a deterministic fake and never download a model. In production
the vectors come from the embeddings service (`docker/embeddings`, sentence-transformers on CPU) over the internal
Compose network: the API and the worker do not install torch (user decision of 22 nov 2026, docs/02 §4).
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Final

import httpx

EmbedFn = Callable[[Sequence[str]], list[list[float]]]

# TODO(P-019): confirm the model with the team; it must handle Spanish and English and run on CPU.
EMBEDDING_MODEL = "intfloat/multilingual-e5-small"
EMBEDDING_DIMENSIONS = 384  # story.embedding is vector(384)
MAX_EMBED_CHARS = 1_500  # title plus the start of the text: enough for a 512-token model
HTTP_OK: Final = 200
HTTP_SERVER_ERROR: Final = 500


def embedding_input(title: str, text: str | None) -> str:
    """The text that represents an article (ING-05 layer 3: title plus summary), as an e5 passage."""
    body = (text or "").strip()
    return f"passage: {title.strip()}\n{body}"[:MAX_EMBED_CHARS]


class EmbeddingError(RuntimeError):
    """The embedding backend is missing or returned vectors that do not fit the schema."""


@dataclass(frozen=True)
class HttpEmbedderConfig:
    """Timeouts and retries of the embeddings client (CPU encoding of a batch takes seconds, not minutes)."""

    timeout_seconds: float = 60.0
    connect_seconds: float = 5.0
    max_attempts: int = 3
    backoff_seconds: float = 1.0
    batch_size: int = 32  # the service accepts up to 64 texts per request
    sleep: Callable[[float], None] = field(default=time.sleep, repr=False)


def check_vectors(vectors: list[list[float]], expected: int) -> list[list[float]]:
    if len(vectors) != expected or any(len(v) != EMBEDDING_DIMENSIONS for v in vectors):
        raise EmbeddingError("The embedding function returned vectors of the wrong shape")
    if any(not math.isfinite(x) for v in vectors for x in v):
        raise EmbeddingError("The embedding function returned a non-finite value")
    return vectors


class HttpEmbedder:
    """`EmbedFn` backed by the embeddings service: `POST {EMBEDDINGS_URL}/embed` (user decision of 22 nov 2026).

    Fails closed: a network error, a timeout, a non-200 answer or vectors that do not fit the schema raise
    `EmbeddingError` after `max_attempts`, so the news cycle reports the service down and keeps the articles for the
    next cycle instead of storing bad vectors. Transport errors and 5xx answers are retried with a short backoff; a
    4xx answer is not (it would fail again). Texts go in batches the service accepts.
    """

    def __init__(self, url: str, config: HttpEmbedderConfig | None = None, http: httpx.Client | None = None) -> None:
        self.url = url.rstrip("/") + "/embed"
        self.config = config or HttpEmbedderConfig()
        self._http = http

    def __call__(self, texts: Sequence[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        size = self.config.batch_size
        for start in range(0, len(texts), size):
            batch = list(texts[start : start + size])
            vectors.extend(check_vectors(self._post(batch), len(batch)))
        return vectors

    def _post(self, batch: list[str]) -> list[list[float]]:
        config = self.config
        timeout = httpx.Timeout(config.timeout_seconds, connect=config.connect_seconds)
        client = self._http or httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False)
        try:
            problem = "no attempt"
            for attempt in range(1, config.max_attempts + 1):
                try:
                    response = client.post(self.url, json={"texts": batch}, timeout=timeout)
                except httpx.TransportError as exc:
                    problem = f"no answer ({type(exc).__name__})"
                else:
                    if response.status_code == HTTP_OK:
                        return _vectors(response)
                    problem = f"HTTP {response.status_code}"
                    if response.status_code < HTTP_SERVER_ERROR:
                        break  # a client error does not get better with retries
                if attempt < config.max_attempts:
                    config.sleep(config.backoff_seconds * 2 ** (attempt - 1))
            raise EmbeddingError(f"The embeddings service is unavailable: {problem}")
        finally:
            if self._http is None:
                client.close()


def _vectors(response: httpx.Response) -> list[list[float]]:
    try:
        body = response.json()
    except ValueError:
        raise EmbeddingError("The embeddings service did not answer JSON") from None
    vectors = body.get("vectors") if isinstance(body, dict) else None
    if not isinstance(vectors, list) or not all(isinstance(v, list) for v in vectors):
        raise EmbeddingError("The embeddings service answered an unexpected shape")
    try:
        return [[float(x) for x in vector] for vector in vectors]
    except (TypeError, ValueError):
        raise EmbeddingError("The embeddings service answered non-numeric vectors") from None
