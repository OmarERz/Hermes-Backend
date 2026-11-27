"""What the front shows about each factory source (D-088, FE-2, FE-3), as a constant catalogue by source code.

No column holds this: the description and the provider of the factory sources are fixed text, and the refresh
interval is the worker's real schedule (`workers.pipeline_jobs` reads its periods from here). The news cycle reads
every enabled RSS or Atom feed (and every own feed) once an hour (D-010) and once more after each scan (ING-02); NVD,
KEV and EPSS are refreshed once a day (ESC-09). The others have no period of their own: OSV is asked during each scan,
and CVE.org, ransomware.live, URLhaus and ThreatFox are not read on a schedule yet (null period). Own feeds added from
the front have no description or provider and follow the news cycle.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

NEWS_CYCLE_MINUTES: Final = 60  # D-010
VULNDATA_REFRESH_MINUTES: Final = 24 * 60  # ESC-09


@dataclass(frozen=True)
class SourceInfo:
    description: str | None
    provider: str | None
    refresh_interval_minutes: int | None


SOURCE_INFO: Final[dict[str, SourceInfo]] = {
    "nvd": SourceInfo(
        "Base nacional de vulnerabilidades de EE. UU.: CVSS, configuraciones afectadas (CPE) y fechas de cada CVE.",
        "NIST",
        VULNDATA_REFRESH_MINUTES,
    ),
    "cve_org": SourceInfo(
        "Registros oficiales de cada CVE publicados por su CNA (lista CVEProject).",
        "CVE Program (MITRE)",
        None,
    ),
    "kev": SourceInfo(
        "Catálogo de vulnerabilidades explotadas activamente, con la acción requerida y su fecha límite.",
        "CISA",
        VULNDATA_REFRESH_MINUTES,
    ),
    "epss": SourceInfo(
        "Probabilidad de que cada CVE se explote en los próximos 30 días.", "FIRST", VULNDATA_REFRESH_MINUTES
    ),
    "osv": SourceInfo("Vulnerabilidades por paquete y ecosistema de código abierto.", "OSV.dev (Google)", None),
    "thn": SourceInfo(
        "Noticias de ciberseguridad; se usa el resumen de su RSS y la historia completa llega por los otros medios.",
        "The Hacker News",
        NEWS_CYCLE_MINUTES,
    ),
    "tenable": SourceInfo(
        "Investigación y análisis de vulnerabilidades del equipo de Tenable.", "Tenable", NEWS_CYCLE_MINUTES
    ),
    "bleepingcomputer": SourceInfo(
        "Noticias de seguridad: vulnerabilidades, ransomware y filtraciones.", "BleepingComputer", NEWS_CYCLE_MINUTES
    ),
    "ransomware_live": SourceInfo(
        "Víctimas recientes publicadas por los grupos de ransomware.", "ransomware.live", None
    ),
    "urlhaus": SourceInfo("URLs usadas para distribuir malware.", "abuse.ch", None),
    "threatfox": SourceInfo("Indicadores de compromiso (IOCs) de malware.", "abuse.ch", None),
}


def source_info(code: str) -> SourceInfo:
    """The catalogue entry of a factory source; an own feed gets no text and the news cycle's period."""
    return SOURCE_INFO.get(code, SourceInfo(None, None, NEWS_CYCLE_MINUTES))
