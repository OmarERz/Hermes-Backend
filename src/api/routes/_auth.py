"""Role table and the placeholder authorization dependency of the sample routes (API-06).

`ROUTE_ROLES` is the single table of minimum roles, taken from docs/13 API-06. Routes get their dependency from
`guard(method, path)`, so a route cannot declare a different role than the table. `authenticate` is a
placeholder that always answers 401 until F0.2 replaces it with the real token verification: that swap is one
line (the body of `authenticate`, or pointing `requires` at `require_role`).
"""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from typing import Annotated

from fastapi import Depends
from fastapi.params import Depends as DependsParam

from api.errors import ApiError


class Role(StrEnum):
    reader = "reader"
    analyst = "analyst"
    admin = "admin"


_RANK = {Role.reader: 0, Role.analyst: 1, Role.admin: 2}

# Minimum role per route. Routes of F0.2 (/api/health, /api/me, PUT /api/admin/users/{uid}/role) are not here.
# Rows whose docs/13 role depends on the parameter or field changed (PUT /api/config, PATCH /api/sources/{id})
# carry the lowest role; the finer check belongs to the real implementation.
ROUTE_ROLES: dict[tuple[str, str], Role] = {
    ("GET", "/api/config/schema"): Role.reader,
    ("GET", "/api/config"): Role.reader,
    ("PUT", "/api/config"): Role.reader,
    ("GET", "/api/config/versions"): Role.reader,
    ("POST", "/api/config/versions/{v}/restore"): Role.admin,
    ("POST", "/api/formula/simulate"): Role.admin,
    ("GET", "/api/profile"): Role.reader,
    ("PUT", "/api/profile"): Role.admin,
    ("GET", "/api/peer-companies"): Role.reader,
    ("POST", "/api/peer-companies"): Role.admin,
    ("PUT", "/api/peer-companies/{id}"): Role.admin,
    ("DELETE", "/api/peer-companies/{id}"): Role.admin,
    ("GET", "/api/sources"): Role.reader,
    ("POST", "/api/sources"): Role.admin,
    ("PATCH", "/api/sources/{id}"): Role.analyst,
    ("GET", "/api/pending/inventory"): Role.reader,
    ("GET", "/api/cpe/candidates"): Role.analyst,
    ("PUT", "/api/mappings/{software}"): Role.analyst,
    ("GET", "/api/vulnerabilities"): Role.reader,
    ("GET", "/api/vulnerabilities/{group_id}"): Role.reader,
    ("GET", "/api/assets/{ci_id}"): Role.reader,
    ("GET", "/api/findings/{id}/history"): Role.reader,
    ("GET", "/api/comparison/summary"): Role.reader,
    ("GET", "/api/comparison/table"): Role.reader,
    ("GET", "/api/assessments/{id}/breakdown"): Role.reader,
    ("GET", "/api/recommendations"): Role.reader,
    ("GET", "/api/recommendations/{assessment_id}"): Role.reader,
    ("POST", "/api/feedback"): Role.analyst,
    ("GET", "/api/recommendations/{id}/feedback"): Role.reader,
    ("GET", "/api/tickets"): Role.reader,
    ("GET", "/api/alerts"): Role.reader,
    ("POST", "/api/scans"): Role.analyst,
    ("GET", "/api/runs"): Role.reader,
    ("GET", "/api/runs/{id}/events"): Role.reader,
    ("POST", "/api/stix/export"): Role.analyst,
    ("GET", "/api/calibration/proposals"): Role.reader,
    ("POST", "/api/calibration/proposals/{id}/approve"): Role.admin,
    ("POST", "/api/calibration/proposals/{id}/reject"): Role.admin,
    ("GET", "/api/metrics"): Role.reader,
    ("GET", "/api/notifications/events"): Role.admin,
    ("POST", "/api/notifications/events/{id}/retry"): Role.admin,
    ("GET", "/api/connections/status"): Role.admin,
    ("POST", "/api/connections/test"): Role.admin,
    ("GET", "/api/setup/status"): Role.admin,
    ("PUT", "/api/setup/steps/{n}"): Role.admin,
    ("GET", "/api/audit"): Role.admin,
}


def authenticate() -> Role:
    """Placeholder (F0.2 replaces it): no token verification exists yet, so every call is unauthenticated."""
    raise ApiError(401, "unauthorized", "Se requiere autenticación válida.")


def requires(minimum: Role) -> Callable[[Role], Role]:
    """Dependency factory: the caller's role must be at least `minimum`, else 403."""

    def check(role: Annotated[Role, Depends(authenticate)]) -> Role:
        if _RANK[role] < _RANK[minimum]:
            raise ApiError(403, "forbidden", "No tienes permiso para realizar esta acción.")
        return role

    return check


def guard(method: str, path: str) -> DependsParam:
    """The dependency of a route, looked up in ROUTE_ROLES so the table stays the single source."""
    dependency: DependsParam = Depends(requires(ROUTE_ROLES[(method, path)]))
    return dependency
