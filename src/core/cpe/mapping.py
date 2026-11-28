"""Save and remove the mapping of a software product to NVD (CPE) and CNA names (ESC-05, manual origin).

The mapping is made once per product; the version comes from `installed_software`. NVD names follow the CPE
rules (lower case, no spaces) and keep the part of the CPE name (`a` application, `o` operating system, `h`
hardware; D-107); CNA names are free text as CVE.org writes them. Mode 3 (`origin = "mode3"`) is a
later, optional feature and is never overwritten silently: only an analyst's manual mapping replaces it.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from core.cpe.fields import CPE_PARTS
from core.db import models as m

CPE_NAME: Final = re.compile(r"^[a-z0-9][a-z0-9._~+:\-]{0,199}$")
MAX_CNA_LENGTH: Final = 200
FIRST_PRINTABLE: Final = 32


class MappingError(ValueError):
    """The mapping is invalid; the message is safe to show to the analyst (Spanish text for people). `field` names the
    part of the request at fault (`cpe` or `cna`), so the API never reads it from the message."""

    def __init__(self, message: str, field: str = "cpe") -> None:
        super().__init__(message)
        self.field = field


@dataclass(frozen=True)
class MappingInput:
    nvd_vendor: str | None = None
    nvd_product: str | None = None
    cna_vendor: str | None = None
    cna_product: str | None = None
    nvd_part: str | None = None  # required with an NVD pair, never without one (D-107)


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
        raise MappingError("El nombre del CNA es demasiado largo o tiene caracteres de control.", "cna")
    return text


def validate(data: MappingInput) -> MappingInput:
    nvd_vendor, nvd_product = _clean(data.nvd_vendor), _clean(data.nvd_product)
    cna_vendor, cna_product = _cna(data.cna_vendor), _cna(data.cna_product)
    if (cna_vendor is None) != (cna_product is None):
        raise MappingError("Fabricante y producto van juntos, tanto en NVD como en el CNA.", "cna")
    if (nvd_vendor is None) != (nvd_product is None):
        raise MappingError("Fabricante y producto van juntos, tanto en NVD como en el CNA.")
    if nvd_product is None and cna_product is None:
        raise MappingError("Se necesita al menos un par fabricante y producto (NVD o CNA).")
    part = _clean(data.nvd_part)
    if nvd_vendor is not None and nvd_product is not None:
        nvd_vendor, nvd_product = nvd_vendor.lower(), nvd_product.lower()
        if not CPE_NAME.match(nvd_vendor) or not CPE_NAME.match(nvd_product):
            raise MappingError("Los nombres de NVD solo admiten minúsculas, números y . _ ~ + : -")
        if part is None or part.lower() not in CPE_PARTS:
            raise MappingError("La parte del CPE debe ser a (aplicación), o (sistema operativo) o h (hardware).")
        part = part.lower()
    elif part is not None:
        raise MappingError("La parte del CPE solo va con el par de NVD.")
    return MappingInput(nvd_vendor, nvd_product, cna_vendor, cna_product, part)


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
    values = {
        "software_product_id": software_product_id,
        "nvd_part": clean.nvd_part,
        "nvd_vendor": clean.nvd_vendor,
        "nvd_product": clean.nvd_product,
        "cna_vendor": clean.cna_vendor,
        "cna_product": clean.cna_product,
        "origin": "manual",
        "confidence": None,
        "mapped_by": mapped_by,
        "mapped_at": now or datetime.now(UTC),
    }
    # one atomic statement: two analysts saving the first mapping of a product cannot collide
    upsert = insert(m.CpeMapping).values(**values)
    session.execute(
        upsert.on_conflict_do_update(
            index_elements=[m.CpeMapping.software_product_id],
            set_={k: v for k, v in values.items() if k != "software_product_id"},
        )
    )
    session.flush()
    session.expire_all()
    return session.get_one(m.CpeMapping, software_product_id)


def remove_mapping(session: Session, software_product_id: uuid.UUID) -> bool:
    row = session.get(m.CpeMapping, software_product_id)
    if row is None:
        return False
    session.delete(row)
    session.flush()
    return True
