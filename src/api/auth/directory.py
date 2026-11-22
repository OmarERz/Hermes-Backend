"""User directory: the copy of Firebase users kept in ``app_user`` (docs/datos/modelo-v1).

The SQL implementation arrives with the database branch; until then the in-memory one serves tests and
local runs. The role stored here is a copy: the custom claim stays the master (D-030).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid4

from api.auth.identity import VerifiedIdentity
from api.auth.roles import Role


@dataclass(frozen=True, slots=True)
class UserRecord:
    """Mirror of an ``app_user`` row."""

    id: UUID
    firebase_uid: str
    email: str
    display_name: str | None
    role: Role
    active: bool
    created_at: datetime
    last_login_at: datetime | None


class UserDirectory(Protocol):
    def sync_login(self, identity: VerifiedIdentity) -> UserRecord:
        """Create the user on first login or refresh e-mail, name, role copy and ``last_login_at``."""
        ...


class InMemoryUserDirectory:
    def __init__(self) -> None:
        self._users: dict[str, UserRecord] = {}
        self._lock = threading.Lock()

    def sync_login(self, identity: VerifiedIdentity) -> UserRecord:
        now = datetime.now(UTC)
        with self._lock:
            current = self._users.get(identity.uid)
            if current is None:
                record = UserRecord(
                    id=uuid4(),
                    firebase_uid=identity.uid,
                    email=identity.email,
                    display_name=identity.display_name,
                    role=identity.role,
                    active=True,
                    created_at=now,
                    last_login_at=now,
                )
            else:
                record = replace(
                    current,
                    email=identity.email,
                    display_name=identity.display_name,
                    role=identity.role,
                    last_login_at=now,
                )
            self._users[identity.uid] = record
            return record

    def get(self, uid: str) -> UserRecord | None:
        """Read a user without touching it."""
        with self._lock:
            return self._users.get(uid)

    def deactivate(self, uid: str) -> None:
        """Test and admin helper: mark a user inactive."""
        with self._lock:
            self._users[uid] = replace(self._users[uid], active=False)
