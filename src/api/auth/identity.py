"""Identity data and the ``TokenVerifier`` contract (D-030, SEG-25)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from api.auth.roles import Role


class TokenError(Exception):
    """The token is not acceptable. ``reason`` is a stable code; it never contains the token."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class AuthUnavailableError(Exception):
    """The token could not be checked (certificates or revocation backend unreachable): fail closed."""


@dataclass(frozen=True, slots=True)
class VerifiedIdentity:
    """What a verified ID token proves: who (uid, e-mail) and the role from the custom claim."""

    uid: str
    email: str
    display_name: str | None
    role: Role


class TokenVerifier(Protocol):
    def verify(self, token: str) -> VerifiedIdentity:
        """Return the identity or raise ``TokenError`` / ``AuthUnavailableError``. Never returns on doubt."""
        ...
