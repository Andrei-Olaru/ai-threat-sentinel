"""Unit tests for the Alerts API endpoints.

Tests the alert listing, detail retrieval, dashboard stats,
and IP blocking endpoints.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from sentinel.config import Environment, Settings
from sentinel.db.models import AlertEvent
from sentinel.main import create_app


def _sample_alert(
    alert_id: str | None = None,
    src_ip: str = "192.168.1.100",
    severity: str = "high",
) -> AlertEvent:
    """Helper to build a sample AlertEvent model instance."""
    return AlertEvent(
        id=1,
        alert_id=alert_id or str(uuid.uuid4()),
        event_id="evt_test_api_01",
        created_at=datetime.now(tz=UTC),
        src_ip=src_ip,
        event_type="ssh_brute_force",
        severity=severity,
        anomaly_score=-0.82,
        rule_matched="ssh_brute_force",
        rca="Automated credential guessing detected from external IP.",
        mitre_attack_id="T1110.001",
        mitre_technique="Password Guessing",
        remediation=["Block IP at firewall", "Enforce MFA"],
        is_blocked=False,
        raw_event={"event_type": "ssh_brute_force", "dst_port": 22},
    )


class TestAlertsApiWithoutDatabase:
    """Tests alert endpoints when database service is unavailable (returns 503)."""

    @pytest.fixture
    def no_db_app(self) -> object:
        """Create an app instance without a database session factory."""
        settings = Settings(
            APP_NAME="sentinel-test-no-db",
            APP_ENV=Environment.DEVELOPMENT,
            DATABASE_URL="",
            REDIS_URL="",
            GROQ_API_KEY="test-key",
        )
        app = create_app(settings=settings)
        app.state.db_session_factory = None
        return app

    @pytest.mark.asyncio
    async def test_list_alerts_503(self, no_db_app: object) -> None:
        """GET /api/v1/alerts returns 503 when DB is unavailable."""
        transport = ASGITransport(app=no_db_app)  # type: ignore[arg-type]
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/alerts")
            assert response.status_code == 503
            assert "available" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_alert_stats_503(self, no_db_app: object) -> None:
        """GET /api/v1/alerts/stats returns 503 when DB is unavailable."""
        transport = ASGITransport(app=no_db_app)  # type: ignore[arg-type]
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/alerts/stats")
            assert response.status_code == 503


class TestAlertsApiWithMockDatabase:
    """Tests alert endpoints with a mocked database session factory."""

    @pytest.fixture
    def mock_db_app(self) -> tuple[object, AsyncMock]:
        """Create app with mocked session factory yielding a mock session."""
        settings = Settings(
            APP_NAME="sentinel-test-mock-db",
            APP_ENV=Environment.DEVELOPMENT,
            DATABASE_URL="",
            REDIS_URL="",
            GROQ_API_KEY="test-key",
        )
        app = create_app(settings=settings)

        mock_session = AsyncMock()

        # Context manager for get_db_session: session_factory() -> session
        # async with session:
        mock_session.__aenter__.return_value = mock_session
        mock_session.__aexit__.return_value = None

        mock_factory = MagicMock(return_value=mock_session)
        app.state.db_session_factory = mock_factory

        return app, mock_session

    @pytest.mark.asyncio
    async def test_list_alerts_success(self, mock_db_app: tuple[object, AsyncMock]) -> None:
        """GET /api/v1/alerts returns paginated alert list."""
        app, mock_session = mock_db_app

        sample = _sample_alert()

        # Mock list response
        mock_list_result = MagicMock()
        mock_list_result.scalars.return_value.all.return_value = [sample]

        # Mock count response
        mock_count_result = MagicMock()
        mock_count_result.scalar_one.return_value = 1

        mock_session.execute.side_effect = [mock_list_result, mock_count_result]

        transport = ASGITransport(app=app)  # type: ignore[arg-type]
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/alerts")
            assert response.status_code == 200
            data = response.json()
            assert data["total"] == 1
            assert len(data["alerts"]) == 1
            assert data["alerts"][0]["event_id"] == "evt_test_api_01"
            assert data["alerts"][0]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_get_alert_by_id_found(self, mock_db_app: tuple[object, AsyncMock]) -> None:
        """GET /api/v1/alerts/{alert_id} returns single alert if found."""
        app, mock_session = mock_db_app
        test_id = str(uuid.uuid4())
        sample = _sample_alert(alert_id=test_id)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample
        mock_session.execute.return_value = mock_result

        transport = ASGITransport(app=app)  # type: ignore[arg-type]
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(f"/api/v1/alerts/{test_id}")
            assert response.status_code == 200
            data = response.json()
            assert data["alert_id"] == test_id
            assert data["src_ip"] == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_get_alert_by_id_not_found(self, mock_db_app: tuple[object, AsyncMock]) -> None:
        """GET /api/v1/alerts/{alert_id} returns 404 when alert does not exist."""
        app, mock_session = mock_db_app

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        transport = ASGITransport(app=app)  # type: ignore[arg-type]
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(f"/api/v1/alerts/{uuid.uuid4()}")
            assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_block_alert_ip_success(self, mock_db_app: tuple[object, AsyncMock]) -> None:
        """POST /api/v1/alerts/{alert_id}/block marks alert as blocked."""
        app, mock_session = mock_db_app
        test_id = str(uuid.uuid4())
        sample = _sample_alert(alert_id=test_id)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample
        mock_session.execute.return_value = mock_result

        transport = ASGITransport(app=app)  # type: ignore[arg-type]
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(f"/api/v1/alerts/{test_id}/block")
            assert response.status_code == 200
            data = response.json()
            assert data["is_blocked"] is True
            assert test_id in data["alert_id"]
