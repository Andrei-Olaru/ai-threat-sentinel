"""FastAPI application factory.

Uses the 'app factory' pattern: a function creates and configures
the FastAPI instance. This enables:
- Different configs for testing vs production
- Clean dependency injection
- Testable startup/shutdown lifecycle
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sentinel.api.middleware.request_id import RequestIDMiddleware
from sentinel.api.middleware.security import SecurityHeadersMiddleware
from sentinel.api.v1.router import api_v1_router
from sentinel.config import Settings, get_settings
from sentinel.core.logging import get_logger, setup_logging

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan manager — runs on startup and shutdown."""
    settings: Settings = app.state.settings

    logger.info(
        "application_starting",
        app_name=settings.APP_NAME,
        environment=settings.APP_ENV.value,
        debug=settings.DEBUG,
    )

    # TODO (Module 2): Initialize Redis connection pool
    # TODO (Module 3): Load trained Isolation Forest model
    # TODO (Module 4): Initialize async DB session factory

    yield

    logger.info("application_shutting_down")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        settings: Optional settings override (used in tests).
                  If None, reads from environment/.env file.
    """
    if settings is None:
        settings = get_settings()

    setup_logging(
        log_level=settings.LOG_LEVEL,
        json_format=settings.is_production,
    )

    app = FastAPI(
        title=settings.APP_NAME,
        description="AI-Powered SIEM & Threat Intelligence Platform",
        version="0.1.0",
        docs_url="/docs" if settings.is_development else None,
        redoc_url="/redoc" if settings.is_development else None,
        lifespan=lifespan,
    )

    app.state.settings = settings

    # Middleware execution order is LIFO (last added runs first):
    # 1. RequestID (outermost — runs first on request, last on response)
    # 2. SecurityHeaders
    # 3. CORS
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api_v1_router, prefix="/api/v1")

    return app


app = create_app()
