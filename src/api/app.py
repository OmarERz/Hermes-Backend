"""FastAPI application factory. Run with: uvicorn --factory api.app:create_app"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, FastAPI

from api.auth import FirebaseTokenVerifier, InMemoryUserDirectory, Role, TokenVerifier, UserDirectory, require_role
from api.auth.dependencies import CurrentUser
from api.errors import ErrorResponse, install_error_handlers
from core.config import Settings
from core.logging import configure_logging


def create_app(
    settings: Settings | None = None,
    token_verifier: TokenVerifier | None = None,
    user_directory: UserDirectory | None = None,
) -> FastAPI:
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
    )

    install_error_handlers(app)
    app.state.token_verifier = token_verifier or FirebaseTokenVerifier(
        settings.firebase_project_id, settings.firebase_credentials_file
    )
    # In-memory until the SQL directory lands with the database branch.
    app.state.user_directory = user_directory or InMemoryUserDirectory()

    @app.get("/api/health", tags=["operations"])
    def health() -> dict[str, str]:
        """Liveness check; the only route without authentication (API-01)."""
        return {"status": "ok"}

    @app.get(
        "/api/me",
        tags=["auth"],
        responses={
            401: {"model": ErrorResponse, "description": "Missing, invalid, expired or revoked token"},
            403: {"model": ErrorResponse, "description": "Inactive user"},
            503: {"model": ErrorResponse, "description": "Identity provider unavailable"},
        },
    )
    def me(user: Annotated[CurrentUser, Depends(require_role(Role.READER))]) -> CurrentUser:
        """Current user and role (API-01)."""
        return user

    return app
