"""Mitigation of a vulnerability group, assembled by code from the data (D-017, docs/06 §5).

The base never depends on an LLM: the corrected version from the affected ranges, the KEV required action, the
CNA workarounds, the indicators of compromise already linked to the CVE, a verification step and the advisory
links. An empty slot stays empty (detection has data only when ThreatFox or URLhaus indicators exist).
Text from NVD, CISA and CNAs is cleaned (`text.py`) and kept as data. Spanish is the output language.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from typing import Final

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from core.db import models as m
from core.mitigation.text import clean_text, safe_url
from core.scan.versions import bound_order, parse_version, wildcard_line

MAX_IOCS: Final = 20
MAX_WORKAROUNDS: Final = 10
TOKEN: Final = re.compile(r"\d+|[A-Za-z]+")

_DATA = text(
    "SELECT g.cve_id, d.fixed_versions, d.kev_required_action, d.kev_due_date, d.workarounds, "
    "(SELECT array_agg(DISTINCT i.ioc_type || ':' || i.value) FROM ioc_cve ic JOIN ioc i ON i.id = ic.ioc_id "
    "JOIN source s ON s.id = i.source_id WHERE ic.cve_id = g.cve_id AND s.code IN ('threatfox', 'urlhaus')) "
    "FROM finding_group g JOIN data_mitigation d ON d.finding_group_id = g.id WHERE g.id = :group_id"
)
_RANGES = text(
    "SELECT r.version_start, r.start_inclusive, r.version_end, r.end_inclusive "
    "FROM finding_group g JOIN cpe_mapping c ON c.software_product_id = g.software_product_id "
    "JOIN cve_affected_range r ON r.cve_id = g.cve_id "
    "AND ((r.source = 'nvd_cpe' AND r.vendor = c.nvd_vendor AND r.product = c.nvd_product) "
    "OR (r.source = 'cna_affected' AND r.vendor = c.cna_vendor AND r.product = c.cna_product)) "
    "WHERE g.id = :group_id"
)


@dataclass(frozen=True)
class MitigationData:
    """The raw inputs, as the `data_mitigation` view gives them."""

    cve_id: str
    fixed_versions: Sequence[str] = ()
    kev_required_action: str | None = None
    kev_due_date: date | None = None
    workarounds: Sequence[str] = ()
    iocs: Sequence[str] = ()
    patch_references: Sequence[str] = ()
    advisory_references: Sequence[str] = ()
    affected_ranges: Sequence[tuple[str | None, bool | None, str | None, bool | None]] = ()


@dataclass(frozen=True)
class Mitigation:
    cve_id: str
    correction: tuple[str, ...]
    temporal: tuple[str, ...]
    detection: tuple[str, ...]
    verification: tuple[str, ...]
    patch_references: tuple[str, ...]
    advisory_references: tuple[str, ...]

    @property
    def has_fix(self) -> bool:
        return any(step.startswith("Actualizar a ") for step in self.correction)


def version_key(version: str) -> tuple[tuple[int, int, str], ...]:
    """A sort key where numbers compare as numbers (`1.9` before `1.10`) and words after numbers."""
    return tuple((0, int(t), "") if t.isdigit() else (1, 0, t.lower()) for t in TOKEN.findall(version))


def _bound_order(version: str, bound: str) -> int:
    """-1, 0 or 1 for one range bound: the scan's comparator when it reads both (a CNA wildcard bound such as `6.1.*`
    is its whole line, F15.9), else the simple order."""
    order = bound_order(version, bound)
    if order is not None:
        return order
    left, right = version_key(version), version_key(bound)
    return (left > right) - (left < right)


def _inside(version: str, rng: tuple[str | None, bool | None, str | None, bool | None]) -> bool:
    """Is `version` inside the affected range? Each bound is compared on its own with the scan's comparator
    (pre-releases, trailing zeros) and falls back to the simple order only for a bound it cannot read (F4.4 #42)."""
    start, start_inclusive, end, end_inclusive = rng
    if start is not None:
        order = _bound_order(version, start)
        if order < 0 or (order == 0 and not start_inclusive):
            return False
    if end is not None:
        order = _bound_order(version, end)
        if order > 0 or (order == 0 and not end_inclusive):
            return False
    return True


def _order(version: str) -> tuple[int, object]:
    """Readable versions first, in the scan's order (`1.0rc1` before `1.0`); the rest in the simple order."""
    parsed = parse_version(version)
    return (0, parsed) if parsed is not None else (1, version_key(version))


Range = tuple[str | None, bool | None, str | None, bool | None]


def _correction(version: str, ranges: Sequence[Range]) -> str:
    """«o superior» only when no affected range lies after the fixed version; otherwise the advice stops before the
    first one, as the data say (F15.9 review: «6.1.192 o superior» must not cover the affected 6.6 line)."""
    later = [r for r in ranges if r[0] is not None and _starts_after(version, r)]
    if not later:
        return f"Actualizar a {version} o superior."
    start, inclusive = min(later, key=lambda r: _start_key(str(r[0])))[:2]
    line = wildcard_line(str(start))
    if line is not None:
        name = ".".join(map(str, line))
        if inclusive:
            return f"Actualizar a {version} o posterior, sin llegar a la línea {name}."
        return f"Actualizar a {version} o posterior dentro de la línea {name}."
    if inclusive:
        return f"Actualizar a {version} o posterior, sin llegar a {start}."
    return f"Actualizar a {version} o posterior, hasta {start}."


def _starts_after(version: str, rng: Range) -> bool:
    start, inclusive = rng[0], rng[1]
    if start is None:
        return False
    order = _bound_order(version, start)
    return order < 0 or (order == 0 and not inclusive)


def _start_key(start: str) -> tuple[int, object]:
    line = wildcard_line(start)
    return _order(".".join(map(str, line)) if line is not None else start)


def compose(data: MitigationData) -> Mitigation:
    """A fixed version is only advised when no affected range contains it ("1.5 or higher" must not mean 2.1), and
    «or higher» only reaches up to the next affected range."""
    candidates = {clean_text(v, 60) for v in data.fixed_versions if clean_text(v, 60)}
    versions = sorted((v for v in candidates if not any(_inside(v, r) for r in data.affected_ranges)), key=_order)
    if versions:
        correction = tuple(_correction(v, data.affected_ranges) for v in versions)
    else:
        correction = (
            "Los datos no publican una versión corregida: aplicar las medidas temporales y consultar al fabricante.",
        )
    temporal: list[str] = []
    if data.kev_required_action:
        due = f" Fecha límite: {data.kev_due_date.isoformat()}." if data.kev_due_date else ""
        temporal.append(f"CISA KEV exige: {clean_text(data.kev_required_action)}{due}")
    cleaned = [clean_text(w) for w in data.workarounds if clean_text(w)]
    temporal.extend(f"Alternativa publicada por el CNA: {w}" for w in cleaned[:MAX_WORKAROUNDS])
    if len(cleaned) > MAX_WORKAROUNDS:
        temporal.append(f"Hay {len(cleaned) - MAX_WORKAROUNDS} alternativas más en la ficha del CVE.")
    iocs = sorted({clean_text(i, 300) for i in data.iocs if clean_text(i, 300)})
    detection = [f"Buscar en registros y tráfico el indicador {i}." for i in iocs[:MAX_IOCS]]
    if len(iocs) > MAX_IOCS:
        detection.append(f"Hay {len(iocs) - MAX_IOCS} indicadores más ligados a este CVE.")
    verification = (
        "Comparar en iTop la versión instalada con la corregida.",
        "Volver a correr el escaneo y confirmar que el hallazgo queda corregido.",
    )
    return Mitigation(
        cve_id=data.cve_id,
        correction=correction,
        temporal=tuple(temporal),
        detection=tuple(detection),
        verification=verification,
        patch_references=tuple(sorted({u for r in data.patch_references if (u := safe_url(r))})),
        advisory_references=tuple(sorted({u for r in data.advisory_references if (u := safe_url(r))})),
    )


def _references(session: Session, cve_id: str, tag: str) -> list[str]:
    return list(
        session.scalars(
            select(m.CveReference.url)
            .join(m.CveReferenceTag, m.CveReferenceTag.reference_id == m.CveReference.id)
            .where(m.CveReference.cve_id == cve_id, m.CveReferenceTag.tag == tag)
            .order_by(m.CveReference.url)
        )
    )


def build_mitigation(session: Session, finding_group_id: uuid.UUID) -> Mitigation | None:
    """The data mitigation of a group, or None when the group does not exist."""
    row = session.execute(_DATA, {"group_id": finding_group_id}).first()
    if row is None:
        return None
    ranges = [tuple(r) for r in session.execute(_RANGES, {"group_id": finding_group_id})]
    cve_id, fixed, action, due, workarounds, iocs = row
    return compose(
        MitigationData(
            cve_id=cve_id,
            fixed_versions=fixed or (),
            kev_required_action=action,
            kev_due_date=due,
            workarounds=workarounds or (),
            iocs=iocs or (),
            patch_references=_references(session, cve_id, "Patch"),
            advisory_references=_references(session, cve_id, "Vendor Advisory"),
            affected_ranges=ranges,
        )
    )
