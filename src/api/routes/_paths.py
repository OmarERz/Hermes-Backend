"""Path parameters (F12.3, ASVS 5.0 V2.2.1): every value in a route path is checked before any work and published.

Ids of rows (assessments, groups, findings, peer companies, sources, products, proposals, notification events) are
UUIDs: anything else answers 422 with the field in `details`, never a database lookup, and the OpenAPI shows the
pattern. The other path values (an iTop CI id, a run id) get a maximum length and no control characters.
"""

from __future__ import annotations

from typing import Annotated, Any, Final

from fastapi import Path

UUID_PATTERN: Final = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
UUID_EXAMPLE: Final = "0196a6f0-0000-7000-8000-000000000001"
MAX_PATH_TEXT: Final = 100
# One printable path segment: no control characters, no slash (a slash never reaches here, but say it).
TEXT_PATTERN: Final = r"^[^\x00-\x1f\x7f/]+$"


def uuid_path(alias: str | None = None) -> Any:
    """A UUID path parameter (canonical 8-4-4-4-12 form, as every id the API returns)."""
    return Path(alias=alias, pattern=UUID_PATTERN, max_length=36, examples=[UUID_EXAMPLE], description="UUID")


def text_path(description: str) -> Any:
    """A free path value: at most `MAX_PATH_TEXT` characters, printable."""
    return Path(pattern=TEXT_PATTERN, min_length=1, max_length=MAX_PATH_TEXT, description=description)


UuidId = Annotated[str, uuid_path()]
UuidAliasId = Annotated[str, uuid_path(alias="id")]
CiId = Annotated[str, text_path("iTop id of the CI")]
RunId = Annotated[str, text_path("Run id")]
