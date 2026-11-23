"""Embeddings service (ING-07; user decision of 22 nov 2026, docs/02 §4): sentence-transformers behind local HTTP.

The API and the worker do not install torch: the worker posts the texts here and stores the vectors. The service is
reachable only on its internal Compose network (no published port), keeps no state and never calls the network.

The model is pinned: the image build downloads one Hugging Face commit (`EMBEDDINGS_MODEL_REVISION`), checks that the
snapshot is that commit and writes a manifest with the SHA-256 of every file. At start the service checks the manifest
against the configured name and revision and every file against its hash, and refuses to start on any difference.

Endpoints: `POST /embed` (texts in, L2-normalised vectors out) and `GET /health`. A request body above
`MAX_BODY_BYTES` is answered 413 before it is read whole or validated.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Annotated, Any, Final

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# TODO(P-019): confirm the model with the team; it must handle Spanish and English and run on CPU.
MODEL_NAME = os.environ.get("EMBEDDINGS_MODEL_NAME", "intfloat/multilingual-e5-small")
MODEL_REVISION = os.environ.get("EMBEDDINGS_MODEL_REVISION", "614241f622f53c4eeff9890bdc4f31cfecc418b3")
MODEL_DIR = os.environ.get("EMBEDDINGS_MODEL_DIR", "/opt/model")
MANIFEST: Final = "hermes-model.json"
DIMENSIONS: Final = 384  # story.embedding is vector(384)
MAX_TEXTS: Final = 64
MAX_CHARS: Final = 4_000  # the worker sends at most 1 500 characters per text (title plus the start of the article)
# 64 texts of 4 000 characters, each escaped as \uXXXX in the worst case, still fit: 64 * 4 000 * 6 < 2 MiB.
MAX_BODY_BYTES: Final = 2 * 1024 * 1024
# Only what sentence-transformers loads; the repository also carries ONNX, OpenVINO and a duplicate .bin.
SKIPPED_FILES: Final = ["onnx/*", "openvino/*", "pytorch_model.bin", "*.onnx", ".eval_results/*"]
CHUNK: Final = 1024 * 1024

Encoder = Callable[[Sequence[str]], Sequence[Sequence[float]]]
Text = Annotated[str, StringConstraints(max_length=MAX_CHARS)]


class ModelIntegrityError(RuntimeError):
    """The model directory is not the pinned model (other name or revision, or a file changed after the build)."""


class EmbedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    texts: list[Text] = Field(min_length=1, max_length=MAX_TEXTS)


class EmbedResponse(BaseModel):
    model: str
    revision: str
    dimensions: int
    vectors: list[list[float]]


# --- the pinned model ---------------------------------------------------------------------------------------------
def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def write_manifest(model_dir: Path, name: str, revision: str) -> dict[str, Any]:
    files = {
        str(path.relative_to(model_dir)): _sha256(path)
        for path in sorted(model_dir.rglob("*"))
        if path.is_file() and path.name != MANIFEST
    }
    manifest = {"name": name, "revision": revision, "files": files}
    (model_dir / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest


def verify_model(model_dir: Path, name: str, revision: str) -> None:
    """Refuse a model directory that is not exactly the pinned build (ModelIntegrityError)."""
    try:
        manifest = json.loads((model_dir / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ModelIntegrityError(f"model manifest missing or unreadable in {model_dir}") from exc
    if (manifest.get("name"), manifest.get("revision")) != (name, revision):
        raise ModelIntegrityError(
            f"model is {manifest.get('name')}@{manifest.get('revision')}, expected {name}@{revision}"
        )
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ModelIntegrityError("model manifest lists no files")
    present = {str(path.relative_to(model_dir)) for path in model_dir.rglob("*") if path.is_file()} - {MANIFEST}
    if present != set(files):
        extra, missing = sorted(present - set(files)), sorted(set(files) - present)
        raise ModelIntegrityError(f"model files differ from the manifest: extra {extra}, missing {missing}")
    for relative, expected in files.items():
        path = model_dir / relative
        if not path.is_file() or _sha256(path) != expected:
            raise ModelIntegrityError(f"model file changed after the build: {relative}")


def _installed(module: str) -> Any:
    """sentence-transformers and huggingface_hub exist only in the service image, never in the backend."""
    return importlib.import_module(module)


def prepare_model(name: str, revision: str, target: Path) -> None:
    """Image build only: download the pinned commit, check it is that commit, save it and write the manifest."""
    hub = _installed("huggingface_hub")
    snapshot = Path(hub.snapshot_download(name, revision=revision, ignore_patterns=SKIPPED_FILES))
    if snapshot.name != revision:
        raise ModelIntegrityError(f"downloaded snapshot {snapshot.name}, expected commit {revision}")
    model = _installed("sentence_transformers").SentenceTransformer(str(snapshot), device="cpu", local_files_only=True)
    model.save(str(target))
    write_manifest(target, name, revision)


def sentence_transformer_encoder(model_dir: str = MODEL_DIR) -> Encoder:
    """The real model, checked against its manifest and loaded once from the image directory (CPU only)."""
    verify_model(Path(model_dir), MODEL_NAME, MODEL_REVISION)
    model = _installed("sentence_transformers").SentenceTransformer(model_dir, device="cpu", local_files_only=True)

    def encode(texts: Sequence[str]) -> Sequence[Sequence[float]]:
        rows = model.encode(list(texts), normalize_embeddings=True, show_progress_bar=False, convert_to_numpy=True)
        return [[float(x) for x in row] for row in rows]

    return encode


# --- request size limit -------------------------------------------------------------------------------------------
class BodyLimit:
    """413 for a body above `limit`, before the app reads or validates it.

    A declared Content-Length above the limit is refused at once; otherwise the body is read here, at most `limit`
    bytes (a chunked body is cut as soon as it passes), and replayed to the app.
    """

    def __init__(self, app: ASGIApp, limit: int = MAX_BODY_BYTES) -> None:
        self.app, self.limit = app, limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope.get("headers", [])).get(b"content-length", b"")
        if declared.isdigit() and int(declared) > self.limit:
            await _too_large(send)
            return
        chunks: list[bytes] = []
        size, more = 0, True
        while more:
            message = await receive()
            if message["type"] != "http.request":
                return  # the client went away
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > self.limit:
                await _too_large(send)
                return
            chunks.append(chunk)
            more = bool(message.get("more_body", False))
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if replayed:
                return await receive()
            replayed = True
            return {"type": "http.request", "body": b"".join(chunks), "more_body": False}

        await self.app(scope, replay, send)


async def _too_large(send: Send) -> None:
    body = json.dumps({"detail": f"request body above {MAX_BODY_BYTES} bytes"}).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
    await send({"type": "http.response.start", "status": 413, "headers": headers})
    await send({"type": "http.response.body", "body": body})


# --- the app ------------------------------------------------------------------------------------------------------
def create_app(encoder: Encoder | None = None) -> FastAPI:
    encode = encoder if encoder is not None else sentence_transformer_encoder()
    app = FastAPI(title="Hermes embeddings", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(BodyLimit, limit=MAX_BODY_BYTES)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "model": MODEL_NAME, "revision": MODEL_REVISION}

    @app.post("/embed")
    def embed(request: EmbedRequest) -> EmbedResponse:
        vectors = [list(vector) for vector in encode(request.texts)]
        return EmbedResponse(model=MODEL_NAME, revision=MODEL_REVISION, dimensions=DIMENSIONS, vectors=vectors)

    return app


def main(argv: Sequence[str]) -> None:
    """`python app.py prepare NAME REVISION DIR`, run by the image build."""
    match list(argv):
        case ["prepare", name, revision, target]:
            prepare_model(name, revision, Path(target))
        case _:
            raise SystemExit("usage: python app.py prepare NAME REVISION DIR")


if __name__ == "__main__":
    main(sys.argv[1:])
