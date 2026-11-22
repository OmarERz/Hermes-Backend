"""Cursor pagination (`?cursor=&limit=`, API-02, D-068): generic page model, query params, opaque cursors.

The cursor carries a JSON keyset (the sort-key values of the last item returned) signed with HMAC-SHA256 using
CURSOR_SIGNING_KEY. It is opaque to clients; anything tampered, truncated or signed with another key is
rejected with a 400 error envelope.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, Query, Request
from pydantic import BaseModel, Field

from api.errors import ApiError

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
MAX_CURSOR_LENGTH = 1024

Keyset = dict[str, str | int | float | bool | None]


class Page[T](BaseModel):
    """One page of a list endpoint. `next_cursor` is null on the last page."""

    items: list[T]
    next_cursor: str | None = Field(default=None, description="Opaque cursor for the next page; null if none")


def _invalid_cursor() -> ApiError:
    return ApiError(400, "invalid_cursor", "El cursor de paginación no es válido.")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    """Decode unpadded base64url; anything but the canonical encoding of some bytes is rejected."""
    try:
        raw = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _invalid_cursor() from exc
    if _b64(raw) != text:
        raise _invalid_cursor()
    return raw


class CursorSigner:
    """Signs and verifies cursors: `base64url(payload).base64url(HMAC-SHA256(key, payload))`.

    A cursor from another key, or edited in any way, fails verification (constant-time comparison)
    and is answered with 400 `invalid_cursor`. The payload is a JSON keyset.
    """

    def __init__(self, key: str | bytes) -> None:
        self._key = key.encode("utf-8") if isinstance(key, str) else key
        if not self._key:
            raise ValueError("cursor signing key is empty")

    def _mac(self, payload: bytes) -> bytes:
        return hmac.new(self._key, payload, hashlib.sha256).digest()

    def encode(self, keyset: Keyset) -> str:
        payload = json.dumps(keyset, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return f"{_b64(payload)}.{_b64(self._mac(payload))}"

    def decode(self, cursor: str) -> Keyset:
        """Verify and decode a cursor; raise a 400 `invalid_cursor` ApiError if it is not ours and intact."""
        if not cursor or len(cursor) > MAX_CURSOR_LENGTH or not cursor.isascii():
            raise _invalid_cursor()
        parts = cursor.split(".")
        if len(parts) != 2:  # noqa: PLR2004 - payload and signature
            raise _invalid_cursor()
        payload, signature = _unb64(parts[0]), _unb64(parts[1])
        if not hmac.compare_digest(signature, self._mac(payload)):
            raise _invalid_cursor()
        try:
            data: Any = json.loads(payload)
        except ValueError as exc:  # UnicodeDecodeError and JSONDecodeError are ValueErrors
            raise _invalid_cursor() from exc
        if not isinstance(data, dict) or not data:
            raise _invalid_cursor()
        if not all(
            isinstance(k, str) and isinstance(v, str | int | float | bool | type(None)) for k, v in data.items()
        ):
            raise _invalid_cursor()
        return data


def get_cursor_signer(request: Request) -> CursorSigner:
    signer: CursorSigner = request.app.state.cursor_signer
    return signer


Signer = Annotated[CursorSigner, Depends(get_cursor_signer)]


@dataclass(frozen=True)
class PageParams:
    """Validated pagination query parameters."""

    keyset: Keyset | None
    limit: int


def page_params(
    signer: Signer,
    cursor: Annotated[str | None, Query(max_length=MAX_CURSOR_LENGTH, description="Opaque cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT, description="Page size")] = DEFAULT_LIMIT,
) -> PageParams:
    """FastAPI dependency: `params: Annotated[PageParams, Depends(page_params)]`."""
    return PageParams(keyset=signer.decode(cursor) if cursor else None, limit=limit)


PageQuery = Annotated[PageParams, Depends(page_params)]
