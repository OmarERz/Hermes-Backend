"""Path parameters (F12.3, ASVS V2.2.1): row ids are UUIDs, other path values are bounded and printable.

A malformed value answers 422 with the field in `details` before any lookup (the token is checked first: 401/403 stay
as they were), and every path parameter of the published OpenAPI carries its pattern or its bounds.
"""

from __future__ import annotations

import re

import pytest
from authfakes import SETTINGS, FakeVerifier, bearer
from fastapi.testclient import TestClient

from api.app import create_app
from api.auth import InMemoryUserDirectory, Role
from api.routes._paths import UUID_PATTERN

pytestmark = pytest.mark.unit

# Every route whose path id is a row UUID, with a body its model accepts (so only the path can fail).
UUID_ROUTES: list[tuple[str, str, dict[str, object] | None]] = [
    ("GET", "/api/vulnerabilities/{}", None),
    ("GET", "/api/findings/{}/history", None),
    ("GET", "/api/assessments/{}/breakdown", None),
    ("GET", "/api/recommendations/{}", None),
    ("GET", "/api/recommendations/{}/feedback", None),
    ("PUT", "/api/mappings/{}", {"cpe": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"}),
    (
        "PUT",
        "/api/peer-companies/{}",
        {"name": "Par", "aliases": [], "domain": None, "sector": "finance", "country": "MX"},
    ),
    ("DELETE", "/api/peer-companies/{}", None),
    ("PATCH", "/api/sources/{}", {"active": True}),
    ("POST", "/api/calibration/proposals/{}/approve", None),
    ("POST", "/api/calibration/proposals/{}/reject", None),
    ("POST", "/api/notifications/events/{}/retry", None),
    ("GET", "/api/runs/{}/events", None),
]
MALFORMED = ["nope", "0196a6f0000070008000000000000001", "0196a6f0-0000-7000-8000-00000000000g", "x" * 300]


@pytest.fixture(scope="module")
def client() -> TestClient:
    verifier = FakeVerifier()
    verifier.add("admin", Role.ADMIN, uid="paths-admin")
    app = create_app(SETTINGS, token_verifier=verifier, user_directory=InMemoryUserDirectory(), role_manager=object())
    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize("value", MALFORMED)
@pytest.mark.parametrize(("method", "template", "body"), UUID_ROUTES)
def test_a_path_id_that_is_not_a_uuid_is_a_422(
    client: TestClient, method: str, template: str, body: dict[str, object] | None, value: str
) -> None:
    answer = client.request(method, template.format(value), json=body, headers=bearer("admin"))
    assert answer.status_code == 422, answer.text
    error = answer.json()["error"]
    assert error["code"] == "validation_error"
    assert error["details"][0]["field"].startswith("path.")
    assert value not in answer.text  # the error never echoes the input


def test_the_token_is_still_checked_before_the_path() -> None:
    app = create_app(SETTINGS, token_verifier=FakeVerifier(), role_manager=object())
    assert TestClient(app).get("/api/vulnerabilities/nope").status_code == 401


@pytest.mark.parametrize("value", ["CI%00", "CI%1F", "CI%C2%85", "CI%E2%80%AE", "x" * 101])
def test_a_ci_id_with_control_or_bidi_characters_or_too_long_is_a_422(client: TestClient, value: str) -> None:
    assert client.get(f"/api/assets/{value}", headers=bearer("admin")).status_code == 422


def _bounded(schema: dict[str, object]) -> bool:
    """A number needs a maximum; a string a maxLength or a pattern without unbounded repetition (`*`, `+`)."""
    if schema.get("type") == "integer":
        return "maximum" in schema
    if "maxLength" in schema:
        return True
    pattern = schema.get("pattern")
    return isinstance(pattern, str) and not re.search(r"(?<!\\)[*+]", re.sub(r"\[[^\]]*\]", "", pattern))


def test_every_path_parameter_is_published_with_a_pattern_or_bounds() -> None:
    paths = create_app(SETTINGS, token_verifier=FakeVerifier(), role_manager=object()).openapi()["paths"]
    unbounded = []
    for path, operations in paths.items():
        for method, operation in operations.items():
            for parameter in operation.get("parameters", []):
                if parameter["in"] != "path":
                    continue
                schema = parameter["schema"]
                if not _bounded(schema):
                    unbounded.append((method, path, parameter["name"]))
                if schema.get("pattern") == UUID_PATTERN:
                    assert schema["maxLength"] == 36
    assert unbounded == []
