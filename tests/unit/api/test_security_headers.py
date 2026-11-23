"""Every API answer carries the security headers (docs/14 §10.4; ZAP 10021 and 90004), errors included."""

from __future__ import annotations

import pytest
from authfakes import SETTINGS, FakeVerifier
from fastapi.testclient import TestClient

from api.app import create_app

pytestmark = pytest.mark.unit


def client(docs: bool = False, subdomains: bool = False) -> TestClient:
    settings = SETTINGS.model_copy(update={"api_docs_enabled": docs, "hsts_include_subdomains": subdomains})
    return TestClient(create_app(settings, token_verifier=FakeVerifier(), role_manager=object()))


@pytest.mark.parametrize(("path", "status"), [("/api/health", 200), ("/api/me", 401), ("/api/nope", 404)])
def test_security_headers_on_success_and_errors(path: str, status: int) -> None:
    response = client().get(path)
    assert response.status_code == status
    headers = response.headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["cross-origin-resource-policy"] == "same-origin"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cache-control"] == "no-store"
    assert headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert "camera=()" in headers["permissions-policy"]
    assert headers["strict-transport-security"] == "max-age=31536000"


def test_hsts_covers_subdomains_only_when_configured() -> None:
    """includeSubDomains forces HTTPS on every subdomain of the host for a year, so it is opt-in (23 nov)."""
    assert client().get("/api/health").headers["strict-transport-security"] == "max-age=31536000"
    with_subdomains = client(subdomains=True).get("/api/health").headers["strict-transport-security"]
    assert with_subdomains == "max-age=31536000; includeSubDomains"


def test_the_development_docs_keep_a_csp_that_lets_swagger_load() -> None:
    response = client(docs=True).get("/api/docs")
    assert response.status_code == 200
    csp = response.headers["content-security-policy"]
    assert "https://cdn.jsdelivr.net" in csp
    assert "frame-ancestors 'none'" in csp


def test_a_header_set_by_a_route_is_not_duplicated() -> None:
    response = client().get("/api/me")  # the 401 sets WWW-Authenticate; nothing else is overwritten twice
    assert response.headers.get_list("x-content-type-options") == ["nosniff"]
