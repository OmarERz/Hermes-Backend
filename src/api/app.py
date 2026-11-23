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
from api.itop_webhook import build_itop_webhook_router
from api.pagination import CursorSigner
from api.routes import routers, samples
from core.config import Settings
from core.cpe.candidates import CpeDictionaryClient
from core.db.session import make_session_factory
from core.itop.client import reader_from_settings
from core.logging import configure_logging
from core.tickets.sync import TicketStateSync
from core.vulndata.nvd import nvd_client


def create_app(
    settings: Settings | None = None,
    token_verifier: TokenVerifier | None = None,
    user_directory: UserDirectory | None = None,
    role_manager: RoleManager | None = None,
    ticket_sync: TicketStateSync | None = None,
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
    app.state.itop_url = str(settings.itop_url) if settings.itop_url is not None else None  # for links to iTop
    app.state.runs = list(samples.RUNS)
    install_error_handlers(app)
    if token_verifier is None or role_manager is None:
        firebase = FirebaseTokenVerifier(settings.firebase_project_id, settings.firebase_credentials_file)
        token_verifier = token_verifier or firebase
        role_manager = role_manager or FirebaseRoleManager(firebase)
    app.state.token_verifier = token_verifier
    app.state.role_manager = role_manager
    # The engine connects lazily: building the app never opens a database connection.
    session_factory = make_session_factory(settings)
    app.state.session_factory = session_factory
    # NVD's CPE dictionary is queried only when a key is configured: without one the dynamic test stack (Schemathesis,
    # ZAP) would hit the real NVD, and the public rate limit is too low to share. Local candidates always work.
    app.state.cpe_dictionary = (
        CpeDictionaryClient(nvd_client(settings.nvd_api_key).source, settings.nvd_api_key)
        if settings.nvd_api_key is not None
        else None
    )
    app.state.user_directory = user_directory or SqlUserDirectory(session_factory)
    if ticket_sync is None and settings.itop_url is not None and settings.itop_token is not None:
        ticket_sync = TicketStateSync(session_factory, reader_from_settings(settings), settings.itop_system_user)

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
    app.include_router(build_itop_webhook_router(settings.itop_webhook_token, ticket_sync))
    for router in routers:
        app.include_router(router)
    return app
