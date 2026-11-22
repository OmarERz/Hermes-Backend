"""UUID version 7 identifiers (time-ordered, model v1 §0). Python 3.12 has no uuid.uuid7()."""

from __future__ import annotations

import secrets
import time
import uuid


def new_id(now_ms: int | None = None) -> uuid.UUID:
    """A UUIDv7 (RFC 9562): 48-bit Unix milliseconds, version 7, RFC variant, 74 random bits."""
    ms = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    raw = bytearray(ms.to_bytes(6, "big") + secrets.token_bytes(10))
    raw[6] = (raw[6] & 0x0F) | 0x70
    raw[8] = (raw[8] & 0x3F) | 0x80
    return uuid.UUID(bytes=bytes(raw))
