"""FastAPI application factory. Run with: uvicorn --factory api.app:create_app"""

from __future__ import annotations

from fastapi import FastAPI

from api.errors import ERROR_RESPONSES, install_error_handlers
from api.pagination import CursorSigner
from api.routes import routers
from core.config import Settings
from core.logging import configure_logging


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the API. Settings load (and fail closed) here, never at import time."""
    settings = settings or Settings()
    configure_logging(settings.secret_values())
    docs = settings.api_docs_enabled
    app = FastAPI(
        title="Hermes API",
        version="0.1.0",
        docs_url="/api/docs" if docs else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if docs else None,
        responses=ERROR_RESPONSES,
    )

    app.state.cursor_signer = CursorSigner(settings.cursor_signing_key.get_secret_value())
    install_error_handlers(app)
    for router in routers:
        app.include_router(router)

    @app.get("/api/health", tags=["operations"])
    def health() -> dict[str, str]:
        """Liveness check; the only route without authentication (API-01)."""
        return {"status": "ok"}

    return app
