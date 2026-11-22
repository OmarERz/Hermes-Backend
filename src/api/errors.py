"""Error envelope `{"error": {"code", "message", "details"}}` and its exception handlers (API-02).

Codes are English snake_case; messages are for people and in Spanish (D-060). Validation details list the
field path and the rule that failed, never the offending input value (SEG-21).
"""

from __future__ import annotations

import logging
from http import HTTPStatus
from typing import Any

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
    assert isinstance(exc, ApiError)  # noqa: S101 - registered for ApiError only
    return error_response(exc.status_code, exc.code, exc.message, exc.details)


def _http_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)  # noqa: S101 - registered for HTTPException only
    status = exc.status_code
    default = _GENERIC_SERVER if status >= HTTPStatus.INTERNAL_SERVER_ERROR else _GENERIC_CLIENT
    code, message = _STATUS_CODES.get(status, default)
    headers = dict(exc.headers) if exc.headers else None
    return error_response(status, code, message, headers=headers)


def _validation_handler(_request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)  # noqa: S101 - registered for RequestValidationError only
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
