"""Deterministic STIX identifiers: the same data always gives the same ids (STX-01)."""

from __future__ import annotations

import uuid
from typing import Final

NAMESPACE: Final = uuid.UUID("6f1c2b0e-4a3d-5c7e-9d11-2f6a8b3c4d5e")


def stix_id(object_type: str, *key: str) -> str:
    """`<type>--<uuid5>` from the type and the natural key of the object."""
    return f"{object_type}--{uuid.uuid5(NAMESPACE, object_type + '|' + '|'.join(key))}"
