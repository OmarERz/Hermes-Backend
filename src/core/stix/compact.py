"""Compact view of a bundle for the judge (STX-04): the same ids, only what the judge needs.

The STIX bundle is the source of truth; this view is derived from it and saves tokens. It keeps the type, the id,
the name or the pattern, the dates that matter, the relationships and the `x_` scoring properties; it drops
descriptions, external references and markings.
"""

from __future__ import annotations

from typing import Any, Final

KEEP: Final = ("type", "id", "name", "pattern", "published", "valid_from", "aliases", "sectors", "is_family")
RELATION_KEEP: Final = ("type", "id", "relationship_type", "source_ref", "target_ref")


def compact_view(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """One small dict per object, in bundle order; marking definitions are left out."""
    view: list[dict[str, Any]] = []
    for obj in bundle.get("objects", []):
        kind = obj.get("type")
        if kind == "marking-definition":
            continue
        if kind == "relationship":
            view.append({key: obj[key] for key in RELATION_KEEP if key in obj})
            continue
        item = {key: obj[key] for key in KEEP if key in obj}
        item.update({key: value for key, value in obj.items() if key.startswith("x_")})
        if kind == "report":
            item["object_refs"] = obj.get("object_refs", [])
        view.append(item)
    return view
