"""Cursor pagination (`?cursor=&limit=`, API-02, D-068): generic page model, query params, opaque cursors.

The cursor is the base64url of a JSON keyset (the sort-key values of the last item returned). It is opaque to
clients; the server validates its shape and rejects anything malformed with a 400 error envelope.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, Query
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


def encode_cursor(keyset: Keyset) -> str:
    """Encode a keyset as an opaque URL-safe string."""
    raw = json.dumps(keyset, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_cursor(cursor: str) -> Keyset:
    """Decode a cursor; raise a 400 `invalid_cursor` ApiError if it is tampered with or malformed."""
    if not cursor or len(cursor) > MAX_CURSOR_LENGTH or not cursor.isascii():
        raise _invalid_cursor()
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        data: Any = json.loads(raw)
    except (binascii.Error, ValueError) as exc:  # UnicodeDecodeError and JSONDecodeError are ValueErrors
        raise _invalid_cursor() from exc
    if not isinstance(data, dict) or not data:
        raise _invalid_cursor()
    if not all(isinstance(k, str) and isinstance(v, str | int | float | bool | type(None)) for k, v in data.items()):
        raise _invalid_cursor()
    # Reject non-canonical encodings (e.g. altered padding or alphabet) so a cursor has one valid form.
    if encode_cursor(data) != cursor:
        raise _invalid_cursor()
    return data


@dataclass(frozen=True)
class PageParams:
    """Validated pagination query parameters."""

    keyset: Keyset | None
    limit: int


def page_params(
    cursor: Annotated[str | None, Query(max_length=MAX_CURSOR_LENGTH, description="Opaque cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT, description="Page size")] = DEFAULT_LIMIT,
) -> PageParams:
    """FastAPI dependency: `params: Annotated[PageParams, Depends(page_params)]`."""
    return PageParams(keyset=decode_cursor(cursor) if cursor else None, limit=limit)


PageQuery = Annotated[PageParams, Depends(page_params)]
