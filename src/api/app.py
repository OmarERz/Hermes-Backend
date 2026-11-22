"""FastAPI application factory. Run with: uvicorn --factory api.app:create_app"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, FastAPI

from api.auth import FirebaseTokenVerifier, Role, TokenVerifier, UserDirectory, require_role
from api.auth.admin_routes import build_admin_router
from api.auth.dependencies import CurrentUser
from api.auth.directory import SqlUserDirectory
from api.auth.role_admin import FirebaseRoleManager, RoleManager
from api.errors import ERROR_RESPONSES, ErrorResponse, install_error_handlers
from api.pagination import CursorSigner
from api.routes import routers, samples
from core.config import Settings
from core.db.session import make_session_factory
from core.logging import configure_logging


def create_app(
    settings: Settings | None = None,
    token_verifier: TokenVerifier | None = None,
    user_directory: UserDirectory | None = None,
    role_manager: RoleManager | None = None,
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
        responses=ERROR_RESPONSES,
    )

    app.state.cursor_signer = CursorSigner(settings.cursor_signing_key.get_secret_value())
    app.state.runs = list(samples.RUNS)
    install_error_handlers(app)
    if token_verifier is None or role_manager is None:
        firebase = FirebaseTokenVerifier(settings.firebase_project_id, settings.firebase_credentials_file)
        token_verifier = token_verifier or firebase
        role_manager = role_manager or FirebaseRoleManager(firebase)
    app.state.token_verifier = token_verifier
    app.state.role_manager = role_manager
    # The engine connects lazily: building the app never opens a database connection.
    app.state.user_directory = user_directory or SqlUserDirectory(make_session_factory(settings))

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
            409: {"model": ErrorResponse, "description": "The e-mail belongs to another account"},
            503: {"model": ErrorResponse, "description": "Identity provider unavailable"},
        },
    )
    def me(user: Annotated[CurrentUser, Depends(require_role(Role.READER))]) -> CurrentUser:
        """Current user and role (API-01)."""
        return user

    app.include_router(build_admin_router())
    for router in routers:
        app.include_router(router)
    return app
