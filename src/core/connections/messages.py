"""Texts people read for the connection checks and the setup wizard, in the configured output language (D-060).

Spanish is the default; English is the other language offered. Any other configured language falls back to Spanish.
"""

from __future__ import annotations

from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db.models import CompanyProfile

DEFAULT_LANGUAGE: Final = "es"
CONNECTION_TEXT: Final[dict[str, dict[str, str]]] = {
    "es": {
        "ok": "Conexión correcta",
        "rejected": "Llave rechazada",
        "offline": "Sin conexión",
        "unexpected": "Respuesta inesperada del servicio",
        "missing": "Variable faltante: {variable}",
        "insecure": "La URL debe usar HTTPS para enviar la llave",
    },
    "en": {
        "ok": "Connection OK",
        "rejected": "Key rejected",
        "offline": "No connection",
        "unexpected": "Unexpected answer from the service",
        "missing": "Missing variable: {variable}",
        "insecure": "The URL must use HTTPS to send the key",
    },
}
STEP_NAMES: Final[dict[str, tuple[str, ...]]] = {
    "es": (
        "Conexiones",
        "Perfil de la empresa",
        "Empresas pares",
        "Fuentes",
        "Revisión del inventario",
        "Sensibilidad y fórmula",
        "Primer escaneo",
    ),
    "en": (
        "Connections",
        "Company profile",
        "Peer companies",
        "Sources",
        "Inventory review",
        "Sensitivity and formula",
        "First scan",
    ),
}


def output_language(session: Session) -> str:
    """`es` or `en`, from the company profile; Spanish when there is no profile or another language is set."""
    configured = session.scalar(select(CompanyProfile.output_language).limit(1)) or DEFAULT_LANGUAGE
    code = configured.split("-", 1)[0].lower()
    return code if code in CONNECTION_TEXT else DEFAULT_LANGUAGE


def connection_text(code: str, variable: str | None, language: str) -> str:
    texts = CONNECTION_TEXT.get(language, CONNECTION_TEXT[DEFAULT_LANGUAGE])
    return texts.get(code, texts["unexpected"]).format(variable=variable or "")
