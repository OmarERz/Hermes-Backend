"""Synthetic review packages for the judge tests (schemas/review_package.schema.json; no third-party text)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "judge"


def finding_package(**overrides: Any) -> dict[str, Any]:
    """A fresh finding package (two CIs, one CVE element, an N3 and an N2 news item); top-level keys can be
    replaced through keyword arguments."""
    content: dict[str, Any] = json.loads((FIXTURES / "finding_package.json").read_text(encoding="utf-8"))
    content.update(copy.deepcopy(overrides))
    return content
