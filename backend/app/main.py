"""Application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.middleware import (
    BodyLimitMiddleware,
    CsrfMiddleware,
    IdempotencyMiddleware,
    RateLimitMiddleware,
    RequestContextMiddleware,
)
from app.api.v1 import admin, assistant, auth, catalog, identity, intel, jobs, mcp, plugins
from app.api.v1 import settings as settings_routes
from app.core import http_client
from app.core.config import get_settings
from app.core.db import dispose_engine, get_session_factory
from app.core.errors import register_error_handlers
from app.core.logging import configure_logging, get_logger
from app.core.sandbox import install_exec_guard
from app.plugins import load_all
from app.services import app_settings
from app.services.bootstrap import provision

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)
    install_exec_guard()

    plugins = load_all()
    app.state.session_factory = get_session_factory()
    app.state.queue = await create_pool(
        RedisSettings(
            host=settings.redis_host,
            port=settings.redis_port,
            database=settings.redis_db,
            password=settings.redis_password or None,
        )
    )

    async with app.state.session_factory() as session:
        await provision(session)
        # The outbound route lives in the settings, and an analyzer that needs
        # it has no session of its own, so it is installed once here.
        http_client.set_network(await app_settings.load(session, "network"))

    logger.info("api_started", plugins=len(plugins), environment=settings.environment)
    try:
        yield
    finally:
        await app.state.queue.aclose()
        await dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    expose_docs = settings.docs_enabled and not settings.is_production

    app = FastAPI(
        title="XenoProxy",
        version="0.1.0",
        description="OSINT and threat-intelligence orchestration API.",
        lifespan=lifespan,
        docs_url="/api/docs" if expose_docs else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if expose_docs else None,
    )

    app.add_middleware(IdempotencyMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(CsrfMiddleware)
    app.add_middleware(BodyLimitMiddleware)
    app.add_middleware(RequestContextMiddleware)
    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Content-Type", "X-Requested-With", "Idempotency-Key", "Authorization"],
            max_age=600,
        )

    register_error_handlers(app)

    v1 = APIRouter(prefix="/api/v1")
    v1.include_router(auth.router)
    v1.include_router(assistant.router)
    v1.include_router(jobs.router)
    v1.include_router(catalog.router)
    v1.include_router(intel.router)
    v1.include_router(mcp.router)
    v1.include_router(admin.router)
    v1.include_router(plugins.router)
    v1.include_router(identity.router)
    v1.include_router(settings_routes.router)
    app.include_router(v1)

    @app.get("/api/health", tags=["system"], summary="Liveness and readiness probe")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": app.version}

    return app


app = create_app()
