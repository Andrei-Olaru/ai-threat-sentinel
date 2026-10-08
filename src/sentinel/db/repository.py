"""Repository pattern for async database operations.

Why a repository?
=================
Instead of writing raw SQL or SQLAlchemy queries scattered across
route handlers, we encapsulate all database logic in one place.
This makes the code:
1. **Testable** — we can mock the repository in unit tests.
2. **Clean** — route handlers stay small and focused on HTTP concerns.
3. **Consistent** — all queries follow the same patterns.

Think of it as a "data access layer" that sits between the API
and the database — your routes never import SQLAlchemy directly.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from sentinel.core.logging import get_logger
from sentinel.db.models import AlertEvent

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from sentinel.core.schemas import AlertRecord

logger = get_logger(__name__)


class AlertRepository:
    """Async CRUD operations for alert_events table.

    Usage::

        repo = AlertRepository(session)
        alert = await repo.create_from_schema(alert_record)
        alerts = await repo.list_recent(limit=50)
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize with an async database session.

        Args:
            session: An active AsyncSession from the session factory.
        """
        self._session = session

    async def create(self, alert: AlertEvent) -> AlertEvent:
        """Add an AlertEvent instance to the database.

        Args:
            alert: The AlertEvent ORM instance to persist.

        Returns:
            The persisted AlertEvent instance.

        Raises:
            IntegrityError: If an alert with this alert_id already exists.
        """
        try:
            self._session.add(alert)
            await self._session.flush()  # Get the ID without committing
            logger.info(
                "alert_persisted",
                alert_id=alert.alert_id,
                severity=alert.severity,
                src_ip=alert.src_ip,
            )
        except IntegrityError:
            await self._session.rollback()
            logger.warning(
                "alert_duplicate",
                alert_id=alert.alert_id,
            )
            raise

        return alert

    async def create_from_schema(
        self,
        alert: AlertRecord,
        raw_event_data: dict[str, object] | None = None,
    ) -> AlertEvent:
        """Create a new alert in the database from a Pydantic schema.

        Args:
            alert: The AlertRecord schema from the detection pipeline.
            raw_event_data: Optional full log event as dict (for forensics).

        Returns:
            The created AlertEvent ORM object with its database ID.

        Raises:
            IntegrityError: If an alert with this alert_id already exists.
        """
        db_alert = AlertEvent(
            alert_id=alert.alert_id,
            event_id=alert.event_id,
            created_at=alert.timestamp,
            src_ip=alert.src_ip,
            event_type=alert.event_type.value,
            severity=alert.severity.value,
            anomaly_score=alert.anomaly_score,
            rule_matched=alert.rule_matched,
            rca=alert.rca,
            mitre_attack_id=alert.mitre_attack_id,
            mitre_technique=alert.mitre_technique,
            remediation=alert.remediation or [],
            is_blocked=alert.is_blocked,
            raw_event=raw_event_data,
        )
        return await self.create(db_alert)

    async def get_by_alert_id(self, alert_id: str) -> AlertEvent | None:
        """Fetch a single alert by its UUID.

        Args:
            alert_id: The alert's UUID string.

        Returns:
            The AlertEvent if found, else None.
        """
        stmt = select(AlertEvent).where(AlertEvent.alert_id == alert_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_recent(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: str | None = None,
        src_ip: str | None = None,
        since: datetime | None = None,
    ) -> list[AlertEvent]:
        """List recent alerts with optional filters.

        This powers the dashboard's alert table. Results are ordered
        by creation time (newest first) for real-time monitoring.

        Args:
            limit: Max results (default 50, capped at 200).
            offset: Pagination offset.
            severity: Filter by severity level (e.g. "critical").
            src_ip: Filter by source IP address.
            since: Only return alerts created after this timestamp.

        Returns:
            List of AlertEvent objects matching the filters.
        """
        limit = min(limit, 200)  # Safety cap

        stmt = select(AlertEvent).order_by(AlertEvent.created_at.desc())

        if severity is not None:
            stmt = stmt.where(AlertEvent.severity == severity)
        if src_ip is not None:
            stmt = stmt.where(AlertEvent.src_ip == src_ip)
        if since is not None:
            stmt = stmt.where(AlertEvent.created_at >= since)

        stmt = stmt.limit(limit).offset(offset)

        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def count(
        self,
        severity: str | None = None,
        since: datetime | None = None,
    ) -> int:
        """Count alerts matching filters.

        Args:
            severity: Filter by severity level.
            since: Only count alerts after this timestamp.

        Returns:
            Number of matching alerts.
        """
        stmt = select(func.count(AlertEvent.id))

        if severity is not None:
            stmt = stmt.where(AlertEvent.severity == severity)
        if since is not None:
            stmt = stmt.where(AlertEvent.created_at >= since)

        result = await self._session.execute(stmt)
        return result.scalar_one()

    async def get_severity_breakdown(
        self,
        since: datetime | None = None,
    ) -> dict[str, int]:
        """Get count of alerts per severity level.

        Useful for the dashboard's severity distribution chart.

        Args:
            since: Only include alerts after this timestamp.

        Returns:
            Dict like {"critical": 5, "high": 12, "medium": 30, "low": 8}.
        """
        stmt = (
            select(AlertEvent.severity, func.count(AlertEvent.id))
            .group_by(AlertEvent.severity)
        )

        if since is not None:
            stmt = stmt.where(AlertEvent.created_at >= since)

        result = await self._session.execute(stmt)
        return dict(result.all())  # type: ignore[arg-type]

    async def get_top_attackers(
        self,
        limit: int = 10,
        since: datetime | None = None,
    ) -> list[dict[str, object]]:
        """Get the top attacking IPs by alert count.

        Powers the dashboard's "Top Attackers" leaderboard.

        Args:
            limit: Number of IPs to return.
            since: Only include alerts after this timestamp.

        Returns:
            List of dicts with ``src_ip`` and ``alert_count``.
        """
        stmt = (
            select(AlertEvent.src_ip, func.count(AlertEvent.id).label("alert_count"))
            .group_by(AlertEvent.src_ip)
            .order_by(func.count(AlertEvent.id).desc())
            .limit(limit)
        )

        if since is not None:
            stmt = stmt.where(AlertEvent.created_at >= since)

        result = await self._session.execute(stmt)
        return [
            {"src_ip": row.src_ip, "alert_count": row.alert_count}
            for row in result.all()
        ]

    async def mark_blocked(self, alert_id: str) -> bool:
        """Mark an alert's source IP as blocked.

        Args:
            alert_id: The alert UUID to update.

        Returns:
            True if the alert was found and updated.
        """
        alert = await self.get_by_alert_id(alert_id)
        if alert is None:
            return False

        alert.is_blocked = True
        await self._session.flush()
        logger.info("alert_ip_blocked", alert_id=alert_id, src_ip=alert.src_ip)
        return True

    async def delete_old(self, before: datetime) -> int:
        """Delete alerts older than a given timestamp (retention policy).

        Args:
            before: Delete alerts created before this timestamp.

        Returns:
            Number of deleted rows.
        """
        from sqlalchemy import delete as sa_delete

        stmt = sa_delete(AlertEvent).where(AlertEvent.created_at < before)
        result = await self._session.execute(stmt)
        deleted = int(getattr(result, "rowcount", 0))
        logger.info("alerts_purged", deleted_count=deleted, before=before.isoformat())
        return deleted


async def get_dashboard_stats(
    session: AsyncSession,
    hours: int = 24,
) -> dict[str, object]:
    """Aggregate dashboard statistics.

    Provides a single endpoint response with everything the
    dashboard needs in one DB round-trip.

    Args:
        session: An active AsyncSession.
        hours: Look-back window in hours (default 24h).

    Returns:
        Dict with total_alerts, severity_breakdown, and top_attackers.
    """
    since = datetime.now(tz=UTC).replace(
        microsecond=0,
    ) - __import__("datetime").timedelta(hours=hours)

    repo = AlertRepository(session)

    total = await repo.count(since=since)
    breakdown = await repo.get_severity_breakdown(since=since)
    attackers = await repo.get_top_attackers(limit=10, since=since)

    return {
        "time_window_hours": hours,
        "total_alerts": total,
        "severity_breakdown": breakdown,
        "top_attackers": attackers,
    }
