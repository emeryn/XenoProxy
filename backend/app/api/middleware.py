"""Request middlewares: correlation, body limits, CSRF, rate limiting, idempotency."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections import defaultdict, deque
from typing import Any
from urllib.parse import urlsplit

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.core.config import get_settings
from app.core.errors import error_body
from app.core.logging import get_logger, request_id_var

logger = get_logger(__name__)

_MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_IDEMPOTENCY_TTL_SECONDS = 86400


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request identifier and the standard response headers."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = uuid.uuid4().hex
        token = request_id_var.set(request_id)
        started = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)

        response.headers["X-Request-Id"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        logger.info(
            "request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
        return response


class BodyLimitMiddleware(BaseHTTPMiddleware):
    """Refuse oversized bodies before they are parsed."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        settings = get_settings()
        declared = request.headers.get("content-length")
        upload_paths = ("/files", "/admin/plugins")
        limit = (
            settings.max_upload_bytes
            if request.url.path.endswith(upload_paths)
            else settings.max_body_bytes
        )
        if declared and declared.isdigit() and int(declared) > limit:
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content=error_body("BODY_TOO_LARGE", "The request body is too large."),
            )
        return await call_next(request)


class CsrfMiddleware(BaseHTTPMiddleware):
    """Reject cross-site mutating requests that rely on the session cookie.

    Requests authenticated by a bearer API key are exempt: they carry no cookie,
    so they are not reachable by a cross-site form or image.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method not in _MUTATING or not request.url.path.startswith("/api/"):
            return await call_next(request)
        if request.headers.get("authorization", "").lower().startswith("bearer "):
            return await call_next(request)

        settings = get_settings()
        fetch_site = request.headers.get("sec-fetch-site")
        if fetch_site in {"cross-site", "same-site"} and fetch_site == "cross-site":
            return self._refuse()

        origin = request.headers.get("origin")
        if origin:
            allowed = {settings.public_url, *settings.cors_origin_list}
            normalised = origin.rstrip("/")
            if normalised not in allowed and not _same_host(origin, request):
                return self._refuse()

        if request.headers.get("x-requested-with") != "XMLHttpRequest":
            return self._refuse()
        return await call_next(request)

    @staticmethod
    def _refuse() -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=error_body("CSRF_REFUSED", "The request origin could not be verified."),
        )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Fixed-window in-process limiter for authentication and expensive routes."""

    _LIMITS: tuple[tuple[str, int, int], ...] = (
        ("/api/v1/auth/login", 10, 300),
        ("/api/v1/auth/password", 5, 300),
        ("/api/v1/auth/api-keys", 20, 3600),
        ("/api/v1/jobs", 60, 60),
    )

    def __init__(self, app: Any) -> None:
        super().__init__(app)
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method not in _MUTATING:
            return await call_next(request)

        rule = next(
            (entry for entry in self._LIMITS if request.url.path.startswith(entry[0])), None
        )
        if rule is None:
            return await call_next(request)

        _, limit, window = rule
        identity = request.client.host if request.client else "unknown"
        key = (rule[0], identity)
        now = time.monotonic()
        bucket = self._hits[key]
        while bucket and now - bucket[0] > window:
            bucket.popleft()
        if len(bucket) >= limit:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content=error_body("RATE_LIMITED", "Too many requests; retry later."),
                headers={"Retry-After": str(window)},
            )
        bucket.append(now)
        return await call_next(request)


class IdempotencyMiddleware(BaseHTTPMiddleware):
    """Replay the stored response when the same Idempotency-Key is retried.

    The same key with a different body is a client bug, so it is refused with 422
    rather than silently creating a second job.
    """

    def __init__(self, app: Any) -> None:
        super().__init__(app)
        self._store: dict[str, tuple[float, str, int, bytes]] = {}

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        key = request.headers.get("idempotency-key")
        if request.method != "POST" or not key or not request.url.path.startswith("/api/"):
            return await call_next(request)

        body = await request.body()
        digest = hashlib.sha256(body).hexdigest()
        self._evict()

        stored = self._store.get(key)
        if stored is not None:
            _, stored_digest, status_code, payload = stored
            if stored_digest != digest:
                return JSONResponse(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    content=error_body(
                        "IDEMPOTENCY_KEY_REUSED",
                        "This idempotency key was already used with a different payload.",
                    ),
                )
            return Response(
                content=payload,
                status_code=status_code,
                media_type="application/json",
                headers={"Idempotent-Replay": "true", "Cache-Control": "no-store"},
            )

        response = await call_next(request)
        if 200 <= response.status_code < 300:
            chunks = [chunk async for chunk in response.body_iterator]
            payload = b"".join(chunks)
            self._store[key] = (time.monotonic(), digest, response.status_code, payload)
            return Response(
                content=payload,
                status_code=response.status_code,
                media_type=response.media_type or "application/json",
                headers=dict(response.headers),
            )
        return response

    def _evict(self) -> None:
        now = time.monotonic()
        expired = [
            key
            for key, (stored_at, *_rest) in self._store.items()
            if now - stored_at > _IDEMPOTENCY_TTL_SECONDS
        ]
        for key in expired:
            del self._store[key]
        if len(self._store) > 10000:
            for key in list(self._store)[:5000]:
                del self._store[key]


def _same_host(origin: str, request: Request) -> bool:
    try:
        return urlsplit(origin).hostname == request.url.hostname
    except ValueError:
        return False


def json_dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"), default=str)
