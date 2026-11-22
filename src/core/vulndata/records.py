"""Source-neutral CVE records: what NVD and CVE.org parsers produce and `store` saves."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Final

CVE_ID: Final = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_ID: Final = re.compile(r"^CWE-\d+$")
NVD_CPE: Final = "nvd_cpe"
CNA_AFFECTED: Final = "cna_affected"


@dataclass(frozen=True)
class ReferenceRecord:
    url: str
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class RangeRecord:
    """An affected version range of a product. All version fields None = every version."""

    source: str  # nvd_cpe | cna_affected
    vendor: str
    product: str
    version_start: str | None = None
    start_inclusive: bool | None = None
    version_end: str | None = None
    end_inclusive: bool | None = None


@dataclass(frozen=True)
class WorkaroundRecord:
    text: str
    source: str  # cna | vendor
    source_url: str | None = None


@dataclass
class CveRecord:
    cve_id: str
    origin: str  # nvd | cna: which source produced this record
    description: str | None = None
    published_at: datetime | None = None
    last_modified_at: datetime | None = None
    cvss_version: str | None = None  # 3.0 | 3.1 | 4.0
    cvss_vector: str | None = None
    cvss_score: Decimal | None = None
    cvss_source: str | None = None  # nvd | cna
    cwes: list[str] = field(default_factory=list)
    references: list[ReferenceRecord] = field(default_factory=list)
    ranges: list[RangeRecord] = field(default_factory=list)
    workarounds: list[WorkaroundRecord] = field(default_factory=list)


def parse_timestamp(raw: object) -> datetime | None:
    """ISO 8601 as the sources write it; a value without offset is UTC."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        parsed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse_score(raw: object) -> Decimal | None:
    """A CVSS base score 0-10 with one decimal, or None."""
    try:
        score = Decimal(str(raw))
    except ArithmeticError:
        return None
    return score.quantize(Decimal("0.1")) if score.is_finite() and Decimal(0) <= score <= Decimal(10) else None
