"""Error envelope `{"error": {"code", "message", "details"}}` and its exception handlers (API-02).

Codes are English snake_case; messages are for people and in Spanish (D-060). Validation details list the
field path and the rule that failed, never the offending input value (SEG-21).
"""

from __future__ import annotations

import logging
import re
from http import HTTPStatus
from typing import Any, cast

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)

_STATUS_CODES: dict[int, tuple[str, str]] = {
    400: ("bad_request", "La solicitud no es válida."),
    401: ("unauthorized", "Se requiere autenticación válida."),
    403: ("forbidden", "No tienes permiso para realizar esta acción."),
    404: ("not_found", "El recurso solicitado no existe."),
    405: ("method_not_allowed", "Método no permitido para esta ruta."),
    409: ("conflict", "La solicitud entra en conflicto con el estado actual del recurso."),
    422: ("validation_error", "Los datos enviados no son válidos."),
    429: ("too_many_requests", "Demasiadas solicitudes; intenta de nuevo más tarde."),
}
_GENERIC_CLIENT = ("http_error", "No se pudo procesar la solicitud.")
_GENERIC_SERVER = ("internal_error", "Error interno del servidor.")


class ErrorDetail(BaseModel):
    """One problem inside an error: where it is and which rule failed (never the input value)."""

    field: str = Field(description="Dotted path of the offending field, e.g. 'body.sensitivity'")
    issue: str = Field(description="Machine-readable rule that failed, e.g. 'missing' or 'greater_than_equal'")


class ErrorBody(BaseModel):
    code: str = Field(description="Stable snake_case error code")
    message: str = Field(description="Message for people, in Spanish")
    details: list[ErrorDetail] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    """Body of every non-2xx response (API-02)."""

    error: ErrorBody


class ApiError(Exception):
    """Raise from a route to answer with the error envelope and a chosen code."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: list[ErrorDetail] | None = None,
    ) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or []


def internal_error_response() -> JSONResponse:
    """The generic 500 envelope (API-02): no internal detail ever reaches the client."""
    return error_response(500, *_GENERIC_SERVER)


def error_response(
    status_code: int,
    code: str,
    message: str,
    details: list[ErrorDetail] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    body = ErrorResponse(error=ErrorBody(code=code, message=message, details=details or []))
    return JSONResponse(status_code=status_code, content=jsonable_encoder(body), headers=headers)


def _api_error_handler(_request: Request, exc: Exception) -> JSONResponse:
    exc = cast(ApiError, exc)
    return error_response(exc.status_code, exc.code, exc.message, exc.details)


def _methods_for_path(app: FastAPI, path: str) -> list[str]:
    """Every method the OpenAPI document declares for a path. Starlette's own `Allow` lists only the methods of
    the first route that matched, because FastAPI registers each method as a separate route."""
    methods: set[str] = set()
    for template, operations in app.openapi().get("paths", {}).items():
        pattern = re.sub(r"\\\{[^/]+?\\\}", "[^/]+", re.escape(template))
        if re.fullmatch(pattern, path):
            methods.update(method.upper() for method in operations)
    return sorted(methods)


def _http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    exc = cast(StarletteHTTPException, exc)
    status = exc.status_code
    default = _GENERIC_SERVER if status >= HTTPStatus.INTERNAL_SERVER_ERROR else _GENERIC_CLIENT
    code, message = _STATUS_CODES.get(status, default)
    headers = dict(exc.headers) if exc.headers else {}
    if status == HTTPStatus.METHOD_NOT_ALLOWED:
        allowed = _methods_for_path(request.app, request.url.path)
        if allowed:
            headers["Allow"] = ", ".join(allowed)
    return error_response(status, code, message, headers=headers or None)


def _validation_handler(_request: Request, exc: Exception) -> JSONResponse:
    exc = cast(RequestValidationError, exc)
    details = [
        ErrorDetail(field=".".join(str(part) for part in error["loc"]), issue=str(error["type"]))
        for error in exc.errors()
    ]
    code, message = _STATUS_CODES[422]
    return error_response(422, code, message, details)


def _unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
    # The traceback goes to the (masked) log; the client only sees a generic message.
    logger.error("unhandled error on %s %s", request.method, request.url.path, exc_info=exc)
    code, message = _GENERIC_SERVER
    return error_response(500, code, message)


def install_error_handlers(app: FastAPI) -> None:
    """Make every error response use the envelope."""
    handlers: dict[Any, Any] = {
        ApiError: _api_error_handler,
        StarletteHTTPException: _http_exception_handler,
        RequestValidationError: _validation_handler,
        Exception: _unhandled_handler,
    }
    for exc_type, handler in handlers.items():
        app.add_exception_handler(exc_type, handler)


# Documented in OpenAPI for every route, so the frontend sees the envelope (and not FastAPI's default 422 body).
ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status: {"model": ErrorResponse, "description": message} for status, (_code, message) in _STATUS_CODES.items()
}
ERROR_RESPONSES[500] = {"model": ErrorResponse, "description": _GENERIC_SERVER[1]}


class UnhandledErrorMiddleware:
    """Turn an unhandled exception into the 500 envelope *inside* the user middleware stack.

    FastAPI's own catch-all runs in ServerErrorMiddleware, outside every middleware added with `add_middleware`, so
    a 500 would skip CORS and a browser on an allowed origin would only see a network error. Added before CORS,
    this keeps the 500 envelope (API-02) visible to the front. Once a response has started it re-raises.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def tracking_send(message: Any) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception:
            if started:
                raise
            logger.exception("unhandled error on %s %s", scope.get("method"), scope.get("path"))
            code, message = _GENERIC_SERVER
            await error_response(500, code, message)(scope, receive, send)
