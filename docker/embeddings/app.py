"""Embeddings service (ING-07; user decision of 22 nov 2026, docs/02 §4): sentence-transformers behind local HTTP.

The API and the worker do not install torch: the worker posts the texts here and stores the vectors. The service is
reachable only on the Compose network (no published port), keeps no state and never calls the network: the model is
copied into the image at build time and loaded from that directory.

Endpoints: `POST /embed` (texts in, L2-normalised vectors out) and `GET /health`.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from typing import Annotated, Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

# TODO(P-019): confirm the model with the team; it must handle Spanish and English and run on CPU.
MODEL_NAME = os.environ.get("EMBEDDINGS_MODEL_NAME", "intfloat/multilingual-e5-small")
MODEL_DIR = os.environ.get("EMBEDDINGS_MODEL_DIR", "/opt/model")
DIMENSIONS = 384  # story.embedding is vector(384)
MAX_TEXTS = 64
MAX_CHARS = 4_000  # the worker sends at most 1 500 characters per text (title plus the start of the article)

Encoder = Callable[[Sequence[str]], Sequence[Sequence[float]]]
Text = Annotated[str, StringConstraints(max_length=MAX_CHARS)]


class EmbedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    texts: list[Text] = Field(min_length=1, max_length=MAX_TEXTS)


class EmbedResponse(BaseModel):
    model: str
    dimensions: int
    vectors: list[list[float]]


def sentence_transformer_encoder(model_dir: str = MODEL_DIR) -> Encoder:
    """The real model, loaded once from the directory baked into the image (CPU only)."""
    from sentence_transformers import SentenceTransformer  # noqa: PLC0415 - installed only in the service image

    model: Any = SentenceTransformer(model_dir, device="cpu", local_files_only=True)

    def encode(texts: Sequence[str]) -> Sequence[Sequence[float]]:
        rows = model.encode(list(texts), normalize_embeddings=True, show_progress_bar=False, convert_to_numpy=True)
        return [[float(x) for x in row] for row in rows]

    return encode


def create_app(encoder: Encoder | None = None) -> FastAPI:
    encode = encoder if encoder is not None else sentence_transformer_encoder()
    app = FastAPI(title="Hermes embeddings", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "model": MODEL_NAME}

    @app.post("/embed")
    def embed(request: EmbedRequest) -> EmbedResponse:
        vectors = [list(vector) for vector in encode(request.texts)]
        return EmbedResponse(model=MODEL_NAME, dimensions=DIMENSIONS, vectors=vectors)

    return app
