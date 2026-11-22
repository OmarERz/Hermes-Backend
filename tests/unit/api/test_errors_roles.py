"""Error envelope (API-02) and role parsing."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.auth import Role
from api.auth.roles import parse_role
from api.errors import ApiError, install_error_handlers


def test_role_hierarchy() -> None:
    assert Role.ADMIN.at_least(Role.ANALYST)
    assert Role.ANALYST.at_least(Role.READER)
    assert Role.READER.at_least(Role.READER)
    assert not Role.READER.at_least(Role.ANALYST)
    assert not Role.ANALYST.at_least(Role.ADMIN)


@pytest.mark.parametrize(
    ("value", "expected"), [("admin", Role.ADMIN), ("root", None), ("ADMIN", None), (1, None), (None, None)]
)
def test_parse_role_fails_closed(value: Any, expected: Role | None) -> None:
    assert parse_role(value) == expected


def test_envelope_for_api_validation_and_http_errors() -> None:
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/x/{n}")
    def get_x(n: int) -> int:
        return n

    @app.get("/boom")
    def boom() -> None:
        raise ApiError(401, "unauthorized", "Falta autenticación.")

    c = TestClient(app)
    missing = c.get("/nothing")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "not_found"
    bad = c.get("/x/abc")
    assert bad.status_code == 422
    body = bad.json()["error"]
    assert body["code"] == "validation_error"
    assert body["details"] == [{"field": "path.n", "issue": "int_parsing"}]
    assert c.post("/x/1").json()["error"]["code"] == "method_not_allowed"
    denied = c.get("/boom")
    assert denied.status_code == 401
    assert denied.json() == {"error": {"code": "unauthorized", "message": "Falta autenticación.", "details": []}}
