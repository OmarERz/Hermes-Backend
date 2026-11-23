"""Error envelope (API-02) and cursor pagination."""

from __future__ import annotations

import base64
import logging

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field, SecretStr, ValidationError

from api.app import create_app
from api.errors import ApiError, ErrorDetail, install_error_handlers
from api.pagination import CursorSigner, Page, PageQuery, Signer
from core.config import Settings

pytestmark = pytest.mark.unit

KEY = "k" * 40
SIGNER = CursorSigner(KEY)


class Body(BaseModel):
    sensitivity: int = Field(ge=1, le=5)


class Item(BaseModel):
    id: int


def build() -> TestClient:
    app = FastAPI()
    app.state.cursor_signer = SIGNER
    install_error_handlers(app)

    @app.post("/body")
    def body(payload: Body) -> dict[str, int]:
        return {"ok": payload.sensitivity}

    @app.get("/http")
    def http() -> None:
        raise HTTPException(status_code=403, detail="secret internal detail", headers={"X-Test": "1"})

    @app.get("/teapot")
    def teapot() -> None:
        raise HTTPException(status_code=418)

    @app.get("/boom")
    def boom() -> None:
        raise RuntimeError("db password=hunter2")

    @app.get("/api-error")
    def api_error() -> None:
        raise ApiError(
            409, "version_conflict", "La versión cambió.", [ErrorDetail(field="body.version", issue="stale")]
        )

    @app.get("/items")
    def items(params: PageQuery, signer: Signer) -> Page[Item]:
        start = int(params.keyset["after"]) if params.keyset and isinstance(params.keyset["after"], int) else 0
        rows = [Item(id=i) for i in range(start + 1, start + 1 + params.limit)]
        return Page[Item](items=rows, next_cursor=signer.encode({"after": rows[-1].id}))

    return TestClient(app, raise_server_exceptions=False)


def test_validation_error_lists_paths_and_never_echoes_input() -> None:
    response = build().post("/body", json={"sensitivity": "SECRET-VALUE-123"})
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert error["details"] == [{"field": "body.sensitivity", "issue": "int_parsing"}]
    assert "SECRET-VALUE-123" not in response.text


def test_http_exception_uses_envelope_and_keeps_headers() -> None:
    response = build().get("/http")
    assert response.status_code == 403
    assert response.json() == {
        "error": {"code": "forbidden", "message": "No tienes permiso para realizar esta acción.", "details": []}
    }
    assert response.headers["x-test"] == "1"
    assert "secret internal detail" not in response.text


def test_unknown_route_and_unmapped_status() -> None:
    client = build()
    assert client.get("/nope").json()["error"]["code"] == "not_found"
    assert client.get("/teapot").json()["error"]["code"] == "http_error"


def test_unhandled_exception_is_generic_and_logged(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.ERROR, logger="api.errors"):
        response = build().get("/boom")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    assert "hunter2" not in response.text
    assert "unhandled error on GET /boom" in caplog.text


def test_api_error_carries_code_and_details() -> None:
    response = build().get("/api-error")
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "version_conflict"
    assert response.json()["error"]["details"] == [{"field": "body.version", "issue": "stale"}]


def test_server_error_status_exception_is_internal_error() -> None:
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/x")
    def x() -> None:
        raise HTTPException(status_code=503)

    assert TestClient(app).get("/x").json()["error"]["code"] == "internal_error"


def test_cursor_round_trip() -> None:
    keyset = {"created_at": "2026-01-01T00:00:00Z", "id": 7, "flag": None}
    cursor = SIGNER.encode(keyset)
    assert cursor.count(".") == 1
    assert SIGNER.decode(cursor) == keyset


def _tampered_variants() -> dict[str, str]:
    payload, signature = SIGNER.encode({"after": 5}).split(".")
    forged = CursorSigner(KEY).encode({"after": 999}).split(".")[0]
    other_key = CursorSigner("z" * 40).encode({"after": 5})
    flipped = ("A" if signature[0] != "A" else "B") + signature[1:]
    return {
        "payload-swapped": f"{forged}.{signature}",
        "signature-flipped": f"{payload}.{flipped}",
        "signature-truncated": f"{payload}.{signature[:-4]}",
        "signature-missing": f"{payload}.",
        "no-signature": payload,
        "wrong-key": other_key,
        "extra-part": f"{payload}.{signature}.x",
        "garbage": "!!!.???",
        "non-ascii": "é.é",
        "too-long": "A" * 2000,
        "unsigned-legacy": "eyJhZnRlciI6NX0",
    }


@pytest.mark.parametrize("name", sorted(_tampered_variants()))
def test_tampered_cursor_is_rejected(name: str) -> None:
    with pytest.raises(ApiError) as caught:
        SIGNER.decode(_tampered_variants()[name])
    assert caught.value.status_code == 400
    assert caught.value.code == "invalid_cursor"


def test_validly_signed_but_malformed_payloads_are_rejected() -> None:
    for payload in (b"{}", b"[]", b"\xff", b'{"a":[1]}'):
        b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()  # noqa: E731
        cursor = f"{b64(payload)}.{b64(SIGNER._mac(payload))}"
        with pytest.raises(ApiError):
            SIGNER.decode(cursor)


def test_empty_key_is_refused() -> None:
    with pytest.raises(ValueError, match="empty"):
        CursorSigner("")


def test_create_app_signs_with_the_configured_key_and_fails_closed_without_it() -> None:
    base: dict[str, object] = {
        "_env_file": None,
        "database_url": SecretStr("postgresql://a:b@db/h"),
        "firebase_project_id": "p",
    }
    app = create_app(Settings(**base, cursor_signing_key=SecretStr(KEY)))  # type: ignore[arg-type]
    assert app.state.cursor_signer.decode(SIGNER.encode({"a": 1})) == {"a": 1}
    with pytest.raises(ValidationError):
        Settings(**base)  # type: ignore[arg-type]


def test_pagination_defaults_and_cursor_flow() -> None:
    client = build()
    first = client.get("/items").json()
    assert len(first["items"]) == 50
    second = client.get("/items", params={"limit": 2, "cursor": first["next_cursor"]}).json()
    assert [i["id"] for i in second["items"]] == [51, 52]


@pytest.mark.parametrize("limit", [0, 201, "x"])
def test_limit_out_of_range_is_422(limit: object) -> None:
    response = build().get("/items", params={"limit": limit})
    assert response.status_code == 422
    assert response.json()["error"]["details"][0]["field"] == "query.limit"


def test_invalid_cursor_is_400_envelope() -> None:
    response = build().get("/items", params={"cursor": "abc.def"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_cursor"


def test_malformed_cursor_is_rejected_by_the_documented_pattern() -> None:
    response = build().get("/items", params={"cursor": "garbage!"})
    assert response.status_code == 422
    assert response.json()["error"]["details"][0]["field"] == "query.cursor"


def test_envelope_forwards_exception_headers_and_lists_every_allowed_method() -> None:
    client = build()
    forbidden = client.get("/http")
    assert forbidden.headers["x-test"] == "1"
    wrong_method = client.options("/items")
    assert wrong_method.status_code == 405
    assert wrong_method.headers["allow"] == "GET"
    assert wrong_method.json()["error"]["code"] == "method_not_allowed"
