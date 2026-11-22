"""Authentication and roles (D-030, SEG-25)."""

from api.auth.firebase import FirebaseTokenVerifier
from api.auth.identity import AuthUnavailableError, TokenError, TokenVerifier, VerifiedIdentity
from api.auth.roles import Role

__all__ = [
    "AuthUnavailableError",
    "FirebaseTokenVerifier",
    "Role",
    "TokenError",
    "TokenVerifier",
    "VerifiedIdentity",
]
