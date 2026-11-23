"""Every operation of the published OpenAPI has a Bruno request (D-070), checked without a running stack.

Each request file names the operation it calls with an `operationId: <id>` line in its `docs` block. The test fails
when an operation has no request, when a tag names an unknown operation, when the tagged request calls another
method or path, or when no request of an operation expects a success (2xx).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

pytestmark = pytest.mark.contract
ROOT = Path(__file__).resolve().parents[2]
OPENAPI = json.loads((ROOT / "openapi" / "openapi.json").read_text(encoding="utf-8"))
METHODS = ("get", "post", "put", "patch", "delete")
HTTP = re.compile(r"^meta \{[^}]*^\s*type: http\s*$", re.MULTILINE | re.DOTALL)
REQUEST = re.compile(r"^(get|post|put|patch|delete) \{\s*\n\s*url: \{\{baseUrl\}\}(\S+)", re.MULTILINE)
TAG = re.compile(r"^\s*operationId: ([a-z_]+)\s*$", re.MULTILINE)
# Operations a client cannot call successfully yet, with the reason; each still needs a request (its error path).
KNOWN_GAPS = {
    "get_finding_history": "no API response carries a finding id yet (reported in F13.6)",
}
# An explicit success: `res.status: eq 2xx` in `assert`, or `expect(res.status).to.equal(2xx)` in `tests`.
SUCCESS = re.compile(r"^\s*res\.status: eq 2\d\d\s*$|expect\(res\.status\)\.to\.equal\(2\d\d\)", re.MULTILINE)


@dataclass(frozen=True)
class Request:
    file: Path
    method: str
    url: str
    operation: str
    expects_success: bool


def operations() -> dict[str, tuple[str, re.Pattern[str]]]:
    found = {}
    for path, item in OPENAPI["paths"].items():
        for method, operation in item.items():
            if method in METHODS:
                pattern = re.compile("^" + re.sub(r"\\\{[^}]+\\\}", r"[^/?]+", re.escape(path)) + r"(\?.*)?$")
                found[operation["operationId"]] = (method, pattern)
    return found


def requests() -> list[Request]:
    found = []
    for file in sorted((ROOT / "bruno").rglob("*.bru")):
        text = file.read_text(encoding="utf-8")
        if not HTTP.search(text):
            continue  # collection, folder and environment files
        call = REQUEST.search(text)
        assert call is not None, f"{file}: an HTTP request must call {{{{baseUrl}}}}/api/... with a known method"
        tag = TAG.search(text)
        url = re.sub(r"\{\{[^}]+\}\}", "x", call.group(2))
        found.append(Request(file, call.group(1), url, tag.group(1) if tag else "", bool(SUCCESS.search(text))))
    return found


OPERATIONS = operations()
REQUESTS = requests()


def test_every_request_names_a_published_operation_it_really_calls() -> None:
    problems = []
    for request in REQUESTS:
        name = request.file.relative_to(ROOT)
        if request.operation not in OPERATIONS:
            problems.append(f"{name}: operationId {request.operation or '(missing)'} is not in openapi/openapi.json")
            continue
        method, path = OPERATIONS[request.operation]
        if request.method != method or not path.match(request.url):
            problems.append(f"{name}: {request.method.upper()} {request.url} is not {request.operation}")
    assert not problems, "\n".join(problems)


def test_every_operation_has_a_request_that_expects_success() -> None:
    covered = {r.operation for r in REQUESTS}
    succeeding = {r.operation for r in REQUESTS if r.expects_success}
    missing = sorted(set(OPERATIONS) - covered)
    unhappy = sorted(set(OPERATIONS) - succeeding - set(missing) - set(KNOWN_GAPS))
    assert not missing, f"operations without a Bruno request: {missing}"
    assert not unhappy, f"operations whose Bruno requests never expect a 2xx: {unhappy}"
    stale = sorted(gap for gap in KNOWN_GAPS if gap in succeeding or gap not in OPERATIONS)
    assert not stale, f"known gaps that are closed or gone, remove them: {stale}"


def test_protected_routes_are_checked_without_a_token_and_with_a_lower_role() -> None:
    texts = [r.file.read_text(encoding="utf-8") for r in REQUESTS]
    unauthenticated = sum("res.status: eq 401" in t for t in texts)
    forbidden = sum("res.status: eq 403" in t for t in texts)
    assert unauthenticated >= 3
    assert forbidden >= 3
