"""Save and remove the mapping of a software product to NVD (CPE) and CNA names (ESC-05, manual origin).

The mapping is made once per product; the version comes from `installed_software`. NVD names follow the CPE
rules (lower case, no spaces); CNA names are free text as CVE.org writes them. Mode 3 (`origin = "mode3"`) is a
later, optional feature and is never overwritten silently: only an analyst's manual mapping replaces it.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from sqlalchemy.orm import Session

from core.db import models as m

CPE_NAME: Final = re.compile(r"^[a-z0-9][a-z0-9._~+\-]{0,199}$")
MAX_CNA_LENGTH: Final = 200
FIRST_PRINTABLE: Final = 32


class MappingError(ValueError):
    """The mapping is invalid; the message is safe to show to the analyst (Spanish text for people)."""


@dataclass(frozen=True)
class MappingInput:
    nvd_vendor: str | None = None
    nvd_product: str | None = None
    cna_vendor: str | None = None
    cna_product: str | None = None


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return text or None


def _cna(value: str | None) -> str | None:
    text = _clean(value)
    if text is None:
        return None
    if len(text) > MAX_CNA_LENGTH or any(ord(ch) < FIRST_PRINTABLE for ch in text):
        raise MappingError("El nombre del CNA es demasiado largo o tiene caracteres de control.")
    return text


def validate(data: MappingInput) -> MappingInput:
    nvd_vendor, nvd_product = _clean(data.nvd_vendor), _clean(data.nvd_product)
    cna_vendor, cna_product = _cna(data.cna_vendor), _cna(data.cna_product)
    if (nvd_vendor is None) != (nvd_product is None) or (cna_vendor is None) != (cna_product is None):
        raise MappingError("Fabricante y producto van juntos, tanto en NVD como en el CNA.")
    if nvd_product is None and cna_product is None:
        raise MappingError("Se necesita al menos un par fabricante y producto (NVD o CNA).")
    if nvd_vendor is not None and nvd_product is not None:
        nvd_vendor, nvd_product = nvd_vendor.lower(), nvd_product.lower()
        if not CPE_NAME.match(nvd_vendor) or not CPE_NAME.match(nvd_product):
            raise MappingError("Los nombres de NVD solo admiten minúsculas, números y . _ ~ + -")
    return MappingInput(nvd_vendor, nvd_product, cna_vendor, cna_product)


def set_mapping(
    session: Session,
    software_product_id: uuid.UUID,
    data: MappingInput,
    *,
    mapped_by: uuid.UUID | None = None,
    now: datetime | None = None,
) -> m.CpeMapping:
    """Create or replace the manual mapping of a product. The caller owns the transaction."""
    clean = validate(data)
    if session.get(m.SoftwareProduct, software_product_id) is None:
        raise LookupError("software product not found")
    row = session.get(m.CpeMapping, software_product_id)
    if row is None:
        row = m.CpeMapping(software_product_id=software_product_id)
        session.add(row)
    row.nvd_vendor, row.nvd_product = clean.nvd_vendor, clean.nvd_product
    row.cna_vendor, row.cna_product = clean.cna_vendor, clean.cna_product
    row.origin, row.confidence = "manual", None
    row.mapped_by, row.mapped_at = mapped_by, now or datetime.now(UTC)
    session.flush()
    return row


def remove_mapping(session: Session, software_product_id: uuid.UUID) -> bool:
    row = session.get(m.CpeMapping, software_product_id)
    if row is None:
        return False
    session.delete(row)
    session.flush()
    return True
