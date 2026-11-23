"""Path parameters (F12.3, ASVS 5.0 V2.2.1): every value in a route path is checked before any work and published.

Ids of rows (assessments, groups, findings, peer companies, sources, products, proposals, notification events, runs)
are UUIDs: anything else answers 422 with the field in `details`, never a database lookup, and the OpenAPI shows the
pattern. An iTop CI id gets a maximum length and the characters `check_text` allows in bodies, minus the C1
controls. The descriptions of the published parameters are the Spanish ones of `api.openapi_docs.PARAMS`.
"""

from __future__ import annotations

from typing import Annotated, Any, Final

from fastapi import Path

UUID_PATTERN: Final = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
UUID_EXAMPLE: Final = "0196a6f0-0000-7000-8000-000000000001"
MAX_PATH_TEXT: Final = 100
# One path segment without C0/C1 controls, DEL, bidirectional controls or a slash (`check_text`'s set plus C1).
TEXT_PATTERN: Final = r"^[^\x00-\x1f\x7f-\x9f/\u202a-\u202e\u2066-\u2069]+$"


def uuid_path(alias: str | None = None) -> Any:
    """A UUID path parameter (canonical 8-4-4-4-12 form, as every id the API returns)."""
    return Path(alias=alias, pattern=UUID_PATTERN, max_length=36, examples=[UUID_EXAMPLE])


def text_path() -> Any:
    """A free path value: at most `MAX_PATH_TEXT` characters, printable."""
    return Path(pattern=TEXT_PATTERN, min_length=1, max_length=MAX_PATH_TEXT)


UuidId = Annotated[str, uuid_path()]
UuidAliasId = Annotated[str, uuid_path(alias="id")]
CiId = Annotated[str, text_path()]
