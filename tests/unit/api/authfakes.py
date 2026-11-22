"""Shared fakes for the API auth unit tests."""

from __future__ import annotations

from pydantic import SecretStr

from api.auth import Role, TokenError, VerifiedIdentity
from core.config import Settings

SETTINGS = Settings(
    _env_file=None, database_url=SecretStr("postgresql://app:pw@db/hermes"), firebase_project_id="demo-hermes"
)


class FakeVerifier:
    def __init__(self) -> None:
        self.identities: dict[str, VerifiedIdentity | Exception] = {}

    def add(self, token: str, role: Role, uid: str | None = None) -> VerifiedIdentity:
        uid = uid or f"uid-{token}"
        identity = VerifiedIdentity(uid=uid, email=f"{uid}@example.com", display_name="Ana", role=role)
        self.identities[token] = identity
        return identity

    def verify(self, token: str) -> VerifiedIdentity:
        result = self.identities.get(token)
        if result is None:
            raise TokenError("token_invalid")
        if isinstance(result, Exception):
            raise result
        return result


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
