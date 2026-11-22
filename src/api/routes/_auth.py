"""Role table of the API routes (API-06), enforced with the real authentication of F0.2.

`ROUTE_ROLES` is the single table of minimum roles, taken from docs/13 API-06. Routes get their dependency from
`guard(method, path)`, so a route cannot declare a different role than the table; the dependency is
`require_role` (Firebase ID token, effective role = the lower of the claim and the database copy).
"""

from __future__ import annotations

from fastapi import Depends
from fastapi.params import Depends as DependsParam

from api.auth import Role, require_role

# Minimum role per route. Routes of F0.2 (/api/health, /api/me, PUT /api/admin/users/{uid}/role) are not here.
# Rows whose docs/13 role depends on the parameter or field changed (PUT /api/config, PATCH /api/sources/{id})
# carry the lowest role; the finer check belongs to the real implementation.
ROUTE_ROLES: dict[tuple[str, str], Role] = {
    ("GET", "/api/config/schema"): Role.READER,
    ("GET", "/api/config"): Role.READER,
    ("PUT", "/api/config"): Role.READER,
    ("GET", "/api/config/versions"): Role.READER,
    ("POST", "/api/config/versions/{v}/restore"): Role.ADMIN,
    ("POST", "/api/formula/simulate"): Role.ADMIN,
    ("GET", "/api/profile"): Role.READER,
    ("PUT", "/api/profile"): Role.ADMIN,
    ("GET", "/api/peer-companies"): Role.READER,
    ("POST", "/api/peer-companies"): Role.ADMIN,
    ("PUT", "/api/peer-companies/{id}"): Role.ADMIN,
    ("DELETE", "/api/peer-companies/{id}"): Role.ADMIN,
    ("GET", "/api/sources"): Role.READER,
    ("POST", "/api/sources"): Role.ADMIN,
    ("PATCH", "/api/sources/{id}"): Role.ANALYST,
    ("GET", "/api/pending/inventory"): Role.READER,
    ("GET", "/api/cpe/candidates"): Role.ANALYST,
    ("PUT", "/api/mappings/{software}"): Role.ANALYST,
    ("GET", "/api/vulnerabilities"): Role.READER,
    ("GET", "/api/vulnerabilities/{group_id}"): Role.READER,
    ("GET", "/api/assets/{ci_id}"): Role.READER,
    ("GET", "/api/findings/{id}/history"): Role.READER,
    ("GET", "/api/comparison/summary"): Role.READER,
    ("GET", "/api/comparison/table"): Role.READER,
    ("GET", "/api/assessments/{id}/breakdown"): Role.READER,
    ("GET", "/api/recommendations"): Role.READER,
    ("GET", "/api/recommendations/{assessment_id}"): Role.READER,
    ("POST", "/api/feedback"): Role.ANALYST,
    ("GET", "/api/recommendations/{id}/feedback"): Role.READER,
    ("GET", "/api/tickets"): Role.READER,
    ("GET", "/api/alerts"): Role.READER,
    ("POST", "/api/scans"): Role.ANALYST,
    ("GET", "/api/runs"): Role.READER,
    ("GET", "/api/runs/{id}/events"): Role.READER,
    ("POST", "/api/stix/export"): Role.ANALYST,
    ("GET", "/api/calibration/proposals"): Role.READER,
    ("POST", "/api/calibration/proposals/{id}/approve"): Role.ADMIN,
    ("POST", "/api/calibration/proposals/{id}/reject"): Role.ADMIN,
    ("GET", "/api/metrics"): Role.READER,
    ("GET", "/api/notifications/events"): Role.ADMIN,
    ("POST", "/api/notifications/events/{id}/retry"): Role.ADMIN,
    ("GET", "/api/connections/status"): Role.ADMIN,
    ("POST", "/api/connections/test"): Role.ADMIN,
    ("GET", "/api/setup/status"): Role.ADMIN,
    ("PUT", "/api/setup/steps/{n}"): Role.ADMIN,
    ("GET", "/api/audit"): Role.ADMIN,
}


def guard(method: str, path: str) -> DependsParam:
    """The dependency of a route, looked up in ROUTE_ROLES so the table stays the single source."""
    dependency: DependsParam = Depends(require_role(ROUTE_ROLES[(method, path)]))
    return dependency
