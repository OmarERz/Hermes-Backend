"""Authentication and roles (D-030, SEG-25)."""

from api.auth.dependencies import CurrentUser, get_current_user, require_role
from api.auth.directory import InMemoryUserDirectory, UserDirectory, UserRecord
from api.auth.firebase import FirebaseTokenVerifier
from api.auth.identity import AuthUnavailableError, TokenError, TokenVerifier, VerifiedIdentity
from api.auth.roles import Role

__all__ = [
    "AuthUnavailableError",
    "CurrentUser",
    "FirebaseTokenVerifier",
    "InMemoryUserDirectory",
    "Role",
    "TokenError",
    "TokenVerifier",
    "UserDirectory",
    "UserRecord",
    "VerifiedIdentity",
    "get_current_user",
    "require_role",
]
