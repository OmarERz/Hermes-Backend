"""The embeddings service (`docker/embeddings/app.py`) with a fake encoder: no torch, no model download."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.unit
APP = Path(__file__).resolve().parents[2] / "docker" / "embeddings" / "app.py"
NAME, REVISION = "intfloat/multilingual-e5-small", "614241f622f53c4eeff9890bdc4f31cfecc418b3"


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
    assert (body["model"], body["revision"], body["dimensions"]) == (NAME, REVISION, 384)
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


def test_the_largest_valid_request_fits_under_the_body_limit() -> None:
    module = service()
    worst = json.dumps({"texts": ["é" * module.MAX_CHARS] * module.MAX_TEXTS}, ensure_ascii=True)
    assert len(worst.encode()) < module.MAX_BODY_BYTES
    assert client().post("/embed", content=worst, headers={"content-type": "application/json"}).status_code == 200


def test_a_large_body_is_413_before_validation() -> None:
    module = service()
    big = b'{"texts": ["' + b"x" * module.MAX_BODY_BYTES + b'"]}'
    response = client().post("/embed", content=big, headers={"content-type": "application/json"})
    assert response.status_code == 413
    assert "request body above" in response.json()["detail"]


def test_a_chunked_body_is_cut_at_the_limit() -> None:
    module = service()

    def chunks() -> Iterator[bytes]:
        yield b'{"texts": ["'
        for _ in range(3):
            yield b"x" * module.MAX_BODY_BYTES  # no Content-Length: counted while it arrives
        yield b'"]}'

    response = client().post("/embed", content=chunks(), headers={"content-type": "application/json"})
    assert response.status_code == 413


def test_health_reports_the_pinned_model_and_no_documentation_routes() -> None:
    api = client()
    assert api.get("/health").json() == {"status": "ok", "model": NAME, "revision": REVISION}
    assert api.get("/docs").status_code == 404
    assert api.get("/openapi.json").status_code == 404


def model_dir(tmp_path: Path) -> Path:
    root = tmp_path / "model"
    (root / "1_Pooling").mkdir(parents=True)
    (root / "model.safetensors").write_bytes(b"weights")
    (root / "1_Pooling" / "config.json").write_text("{}", encoding="utf-8")
    return root


def test_the_manifest_pins_name_revision_and_every_file(tmp_path: Path) -> None:
    module = service()
    root = model_dir(tmp_path)
    manifest = module.write_manifest(root, NAME, REVISION)
    assert sorted(manifest["files"]) == ["1_Pooling/config.json", "model.safetensors"]
    module.verify_model(root, NAME, REVISION)  # the build it describes passes


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda root: (root / "model.safetensors").write_bytes(b"tampered"), "changed after the build"),
        (lambda root: (root / "1_Pooling" / "config.json").unlink(), "changed after the build"),
        (lambda root: (root / "hermes-model.json").unlink(), "missing or unreadable"),
        (lambda root: (root / "hermes-model.json").write_text("not json", encoding="utf-8"), "missing or unreadable"),
        (
            lambda root: (root / "hermes-model.json").write_text(
                json.dumps({"name": NAME, "revision": REVISION, "files": {}}), encoding="utf-8"
            ),
            "lists no files",
        ),
    ],
)
def test_a_changed_model_directory_is_refused(tmp_path: Path, change: Any, message: str) -> None:
    module = service()
    root = model_dir(tmp_path)
    module.write_manifest(root, NAME, REVISION)
    change(root)
    with pytest.raises(module.ModelIntegrityError, match=message):
        module.verify_model(root, NAME, REVISION)


def test_another_revision_or_model_is_refused(tmp_path: Path) -> None:
    module = service()
    root = model_dir(tmp_path)
    module.write_manifest(root, NAME, "0" * 40)
    with pytest.raises(module.ModelIntegrityError, match=f"expected {NAME}@{REVISION}"):
        module.verify_model(root, NAME, REVISION)


def test_the_real_encoder_verifies_the_model_before_loading_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Outside the service image there is no manifest: the service refuses to start instead of loading anything."""
    module = service()
    loaded: list[str] = []
    monkeypatch.setattr(module, "_installed", loaded.append)
    with pytest.raises(module.ModelIntegrityError):
        module.create_app()  # default /opt/model does not exist here
    root = model_dir(tmp_path)
    module.write_manifest(root, NAME, REVISION)

    class Model:
        def __init__(self, path: str, **_options: object) -> None:
            loaded.append(path)

        def encode(self, texts: list[str], **_options: object) -> list[list[float]]:
            return [[0.5] * 384 for _ in texts]

    monkeypatch.setattr(module, "_installed", lambda _name: type("Module", (), {"SentenceTransformer": Model}))
    encode = module.sentence_transformer_encoder(str(root))
    assert loaded == [str(root)]
    assert len(encode(["a"])[0]) == 384


def test_the_build_command_line_only_accepts_prepare() -> None:
    module = service()
    with pytest.raises(SystemExit, match="usage"):
        module.main(["serve"])


def fake_hub(snapshot: Path, calls: list[dict[str, Any]]) -> Any:
    class Model:
        def __init__(self, path: str, **_options: object) -> None:
            self.path = Path(path)

        def save(self, target: str) -> None:
            Path(target).mkdir(parents=True)
            for item in self.path.iterdir():
                (Path(target) / item.name).write_bytes(item.read_bytes())

    def snapshot_download(name: str, **options: Any) -> str:
        calls.append({"name": name, **options})
        return str(snapshot)

    return {
        "huggingface_hub": type("Hub", (), {"snapshot_download": staticmethod(snapshot_download)}),
        "sentence_transformers": type("ST", (), {"SentenceTransformer": Model}),
    }


def test_the_build_downloads_the_pinned_commit_and_writes_the_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = service()
    snapshot = tmp_path / "snapshots" / REVISION
    snapshot.mkdir(parents=True)
    (snapshot / "model.safetensors").write_bytes(b"weights")
    calls: list[dict[str, Any]] = []
    modules = fake_hub(snapshot, calls)
    monkeypatch.setattr(module, "_installed", lambda name: modules[name])
    module.main(["prepare", NAME, REVISION, str(tmp_path / "model")])
    assert calls == [{"name": NAME, "revision": REVISION, "ignore_patterns": module.SKIPPED_FILES}]
    module.verify_model(tmp_path / "model", NAME, REVISION)


def test_the_build_refuses_a_snapshot_of_another_commit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = service()
    snapshot = tmp_path / "snapshots" / ("f" * 40)
    snapshot.mkdir(parents=True)
    modules = fake_hub(snapshot, [])
    monkeypatch.setattr(module, "_installed", lambda name: modules[name])
    with pytest.raises(module.ModelIntegrityError, match="expected commit"):
        module.prepare_model(NAME, REVISION, tmp_path / "model")


def test_the_body_limit_passes_other_scopes_and_stops_on_a_disconnect() -> None:
    module = service()
    calls: list[str] = []
    sent: list[object] = []

    async def app(scope: Any, _receive: Any, _send: Any) -> None:
        calls.append(scope["type"])

    async def disconnect() -> dict[str, str]:
        return {"type": "http.disconnect"}

    async def record(message: object) -> None:
        sent.append(message)

    limit = module.BodyLimit(app, limit=10)
    asyncio.run(limit({"type": "lifespan"}, disconnect, record))
    asyncio.run(limit({"type": "http", "headers": []}, disconnect, record))
    assert (calls, sent) == (["lifespan"], [])  # the client left before sending a body: nothing to answer
