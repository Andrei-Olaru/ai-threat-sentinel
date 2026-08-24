"""Tests for health check endpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from httpx import AsyncClient


class TestHealthEndpoints:
    """Test suite for /healthz and /readyz endpoints."""

    async def test_healthz_returns_healthy(self, client: AsyncClient) -> None:
        """GET /healthz should return 200 with status=healthy."""
        response = await client.get("/api/v1/healthz")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data

    async def test_readyz_returns_ready(self, client: AsyncClient) -> None:
        """GET /readyz should return 200 with status=ready."""
        response = await client.get("/api/v1/readyz")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert "checks" in data
        assert "database" in data["checks"]
        assert "redis" in data["checks"]

    async def test_healthz_includes_timestamp(self, client: AsyncClient) -> None:
        """Timestamp should be ISO format."""
        response = await client.get("/api/v1/healthz")
        data = response.json()
        assert "T" in data["timestamp"]
