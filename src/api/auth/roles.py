"""Roles (D-030): reader < analyst < admin. The role lives in the Firebase custom claim ``role``."""

from __future__ import annotations

from enum import StrEnum

ROLE_CLAIM = "role"


class Role(StrEnum):
    READER = "reader"
    ANALYST = "analyst"
    ADMIN = "admin"

    @property
    def rank(self) -> int:
        return _RANKS[self]

    def at_least(self, minimum: Role) -> bool:
        return self.rank >= minimum.rank


_RANKS = {Role.READER: 1, Role.ANALYST: 2, Role.ADMIN: 3}


def parse_role(value: object) -> Role | None:
    """Return the role for a claim value, or None when it is missing or not a known role (fail closed)."""
    if not isinstance(value, str):
        return None
    try:
        return Role(value)
    except ValueError:
        return None
