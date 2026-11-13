"""Uniform API error envelope."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger, request_id_var

logger = get_logger(__name__)


class AppError(Exception):
    """Business error carrying a stable machine-readable code."""

    status_code = status.HTTP_400_BAD_REQUEST
    code = "BAD_REQUEST"

    def __init__(self, message: str, *, code: str | None = None, status_code: int | None = None):
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        if status_code:
            self.status_code = status_code


class NotFoundError(AppError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "NOT_FOUND"


class ForbiddenError(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "FORBIDDEN"


class UnauthorizedError(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "UNAUTHORIZED"


class ConflictError(AppError):
    status_code = status.HTTP_409_CONFLICT
    code = "CONFLICT"


class ValidationFailedError(AppError):
    status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
    code = "VALIDATION_FAILED"


class RateLimitedError(AppError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = "RATE_LIMITED"


def error_body(code: str, message: str, details: Any = None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "error": {"code": code, "message": message, "request_id": request_id_var.get()}
    }
    if details is not None:
        body["error"]["details"] = details
    return body


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(exc.code, exc.message),
            headers={"Cache-Control": "no-store"},
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(_request: Request, exc: RequestValidationError) -> JSONResponse:
        details = [
            {"field": ".".join(str(part) for part in err.get("loc", ())), "issue": err.get("msg")}
            for err in exc.errors()[:20]
        ]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content=error_body("VALIDATION_FAILED", "The request payload is invalid.", details),
            headers={"Cache-Control": "no-store"},
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        codes = {401: "UNAUTHORIZED", 403: "FORBIDDEN", 404: "NOT_FOUND", 429: "RATE_LIMITED"}
        code = codes.get(exc.status_code, "HTTP_ERROR")
        message = exc.detail if isinstance(exc.detail, str) else "Request failed."
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(code, message),
            headers={"Cache-Control": "no-store"},
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        logger.error("unhandled_exception", path=request.url.path, exc_info=exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_body("INTERNAL_ERROR", "An internal error occurred."),
            headers={"Cache-Control": "no-store"},
        )
