"""Unit tests for SQLAlchemy models and database session utilities.

Tests model structure, column types, default values, and session factory
without needing a live PostgreSQL instance.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import Float, Integer
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID

from sentinel.db.models import AlertEvent
from sentinel.db.repository import AlertRepository
from sentinel.db.session import build_engine, build_session_factory, get_session


class TestAlertEventModel:
    """Tests for AlertEvent SQLAlchemy model."""

    def test_tablename(self) -> None:
        """Verify the table name matches schema design."""
        assert AlertEvent.__tablename__ == "alert_events"

    def test_primary_key_column(self) -> None:
        """Verify internal auto-increment integer primary key."""
        pk = AlertEvent.id
        assert pk.primary_key is True
        assert isinstance(pk.type, Integer)

    def test_alert_id_column(self) -> None:
        """Verify external UUID identifier."""
        col = AlertEvent.alert_id
        assert isinstance(col.type, UUID)
        assert col.unique is True
        assert col.nullable is False

    def test_required_columns(self) -> None:
        """Verify required fields cannot be null."""
        cols = AlertEvent.__table__.columns
        assert cols["event_id"].nullable is False
        assert cols["src_ip"].nullable is False
        assert cols["event_type"].nullable is False
        assert cols["severity"].nullable is False
        assert cols["created_at"].nullable is False

    def test_jsonb_columns(self) -> None:
        """Verify JSONB columns for rich metadata."""
        cols = AlertEvent.__table__.columns
        assert isinstance(cols["remediation"].type, ARRAY)
        assert isinstance(cols["raw_event"].type, JSONB)

    def test_anomaly_score_type(self) -> None:
        """Verify anomaly score is a float."""
        cols = AlertEvent.__table__.columns
        assert isinstance(cols["anomaly_score"].type, Float)

    def test_instance_creation(self) -> None:
        """Test instantiation with sample data."""
        alert = AlertEvent(
            alert_id=str(uuid.uuid4()),
            event_id="evt_test_123",
            src_ip="192.168.1.50",
            event_type="sqli_attempt",
            severity="high",
            anomaly_score=-0.75,
            rule_matched="sqli_attempt",
            rca="Possible SQL injection attempt detected.",
            mitre_attack_id="T1190",
            mitre_technique="Exploit Public-Facing Application",
            remediation=["Block IP", "Inspect query parameters"],
            is_blocked=False,
            raw_event={"payload": "' OR 1=1 --"},
        )
        assert alert.event_id == "evt_test_123"
        assert alert.src_ip == "192.168.1.50"
        assert alert.severity == "high"
        assert alert.anomaly_score == -0.75
        assert alert.is_blocked is False

    def test_repr_method(self) -> None:
        """Test model string representation."""
        alert = AlertEvent(
            alert_id="test-uuid",
            event_type="ssh_brute_force",
            severity="critical",
            src_ip="10.0.0.1",
        )
        rep = repr(alert)
        assert "AlertEvent" in rep
        assert "test-uuid" in rep
        assert "critical" in rep
        assert "10.0.0.1" in rep


class TestSessionUtilities:
    """Tests for database session builder functions."""

    def test_build_engine(self) -> None:
        """Verify build_engine returns an AsyncEngine."""
        engine = build_engine("postgresql+asyncpg://user:pass@localhost:5432/db")
        assert engine is not None
        assert str(engine.url.drivername) == "postgresql+asyncpg"

    def test_build_session_factory(self) -> None:
        """Verify build_session_factory returns a callable sessionmaker."""
        engine = build_engine("postgresql+asyncpg://user:pass@localhost:5432/db")
        factory = build_session_factory(engine)
        assert callable(factory)

    @pytest.mark.asyncio
    async def test_get_session_yields_session(self) -> None:
        """Verify get_session generator yields a session and commits."""
        mock_session = AsyncMock()
        mock_session_ctx = AsyncMock()
        mock_session_ctx.__aenter__.return_value = mock_session
        mock_session_ctx.__aexit__.return_value = None
        mock_factory = MagicMock(return_value=mock_session_ctx)

        async for session in get_session(mock_factory):
            assert session is mock_session

        mock_session.commit.assert_awaited_once()


class TestAlertRepository:
    """Tests for AlertRepository CRUD operations using a mock session."""

    @pytest.mark.asyncio
    async def test_create_alert(self) -> None:
        """Test adding an alert to the session."""
        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        repo = AlertRepository(mock_session)

        alert = AlertEvent(
            alert_id=str(uuid.uuid4()),
            event_id="evt_001",
            src_ip="10.0.0.99",
            event_type="port_scan",
            severity="medium",
        )
        created = await repo.create(alert)

        assert created is alert
        mock_session.add.assert_called_once_with(alert)
        mock_session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_mark_blocked_not_found(self) -> None:
        """Test mark_blocked returns False when alert doesn't exist."""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        repo = AlertRepository(mock_session)
        result = await repo.mark_blocked("non-existent-uuid")

        assert result is False

    @pytest.mark.asyncio
    async def test_mark_blocked_success(self) -> None:
        """Test mark_blocked sets is_blocked=True and flushes."""
        mock_session = AsyncMock()
        alert = AlertEvent(
            alert_id="test-uuid",
            event_id="evt_002",
            src_ip="1.2.3.4",
            event_type="ssh_brute_force",
            severity="high",
            is_blocked=False,
        )
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = alert
        mock_session.execute.return_value = mock_result

        repo = AlertRepository(mock_session)
        success = await repo.mark_blocked("test-uuid")

        assert success is True
        assert alert.is_blocked is True
        mock_session.flush.assert_awaited_once()
