"""Shared pytest fixtures for the test suite."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from httpx import ASGITransport, AsyncClient

from sentinel.config import Settings
from sentinel.main import create_app

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from fastapi import FastAPI


@pytest.fixture
def test_settings() -> Settings:
    """Provide test-specific settings (no real DB/Redis needed)."""
    return Settings(
        APP_NAME="sentinel-test",
        APP_ENV="development",
        DEBUG=True,
        LOG_LEVEL="DEBUG",
        DATABASE_URL="postgresql+asyncpg://test:test@localhost:5432/test_db",
        REDIS_URL="redis://localhost:6379/1",
        GROQ_API_KEY="test-key-not-real",
    )


@pytest.fixture
def app(test_settings: Settings) -> FastAPI:
    """Create a FastAPI test app with test settings."""
    return create_app(settings=test_settings)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    """Async HTTP test client — makes requests without a real server."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
