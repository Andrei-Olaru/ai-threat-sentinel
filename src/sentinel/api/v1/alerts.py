"""Alert API endpoints — query and manage security alerts.

These endpoints expose the alert_events table to the frontend
dashboard and external integrations. All queries are async and
use the repository pattern for clean separation of concerns.

Endpoints:
    GET  /api/v1/alerts           — List recent alerts (paginated, filterable)
    GET  /api/v1/alerts/{id}      — Get a single alert by UUID
    GET  /api/v1/alerts/stats     — Dashboard aggregate statistics
    POST /api/v1/alerts/{id}/block — Mark an alert's IP as blocked
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from sentinel.core.logging import get_logger

if TYPE_CHECKING:
    from sentinel.db.models import AlertEvent

logger = get_logger(__name__)

router = APIRouter(tags=["alerts"])


# --- Response Schemas ---


class AlertResponse(BaseModel):
    """API representation of a single alert."""

    alert_id: str
    event_id: str
    created_at: datetime
    src_ip: str
    event_type: str
    severity: str
    anomaly_score: float
    rule_matched: str | None = None
    rca: str | None = None
    mitre_attack_id: str | None = None
    mitre_technique: str | None = None
    remediation: list[str] = Field(default_factory=list)
    is_blocked: bool = False


class AlertListResponse(BaseModel):
    """Paginated list of alerts."""

    alerts: list[AlertResponse]
    total: int
    limit: int
    offset: int


class AlertStatsResponse(BaseModel):
    """Dashboard statistics."""

    time_window_hours: int
    total_alerts: int
    severity_breakdown: dict[str, int]
    top_attackers: list[dict[str, object]]


class BlockResponse(BaseModel):
    """Response after blocking an IP."""

    alert_id: str
    is_blocked: bool
    message: str


# --- Helper ---


def _alert_to_response(alert: AlertEvent) -> AlertResponse:
    """Convert an AlertEvent ORM object to API response."""
    return AlertResponse(
        alert_id=str(alert.alert_id),
        event_id=alert.event_id,
        created_at=alert.created_at,
        src_ip=alert.src_ip,
        event_type=alert.event_type,
        severity=alert.severity,
        anomaly_score=alert.anomaly_score,
        rule_matched=alert.rule_matched,
        rca=alert.rca,
        mitre_attack_id=alert.mitre_attack_id,
        mitre_technique=alert.mitre_technique,
        remediation=alert.remediation or [],
        is_blocked=alert.is_blocked,
    )


# --- Endpoints ---


@router.get("/alerts/stats", response_model=AlertStatsResponse)
async def get_alert_stats(
    request: Request,
    hours: int = Query(default=24, ge=1, le=168, description="Look-back window in hours"),
) -> AlertStatsResponse:
    """Get aggregated alert statistics for the dashboard.

    Returns total alert count, severity breakdown, and top attacking IPs
    for the specified time window.
    """
    session_factory = getattr(request.app.state, "db_session_factory", None)
    if session_factory is None:
        raise HTTPException(
            status_code=503,
            detail="Database not available",
        )

    from sentinel.db.repository import get_dashboard_stats

    async with session_factory() as session:
        stats = await get_dashboard_stats(session, hours=hours)

    return AlertStatsResponse(
        time_window_hours=stats["time_window_hours"],  # type: ignore[arg-type]
        total_alerts=stats["total_alerts"],  # type: ignore[arg-type]
        severity_breakdown=stats["severity_breakdown"],  # type: ignore[arg-type]
        top_attackers=stats["top_attackers"],  # type: ignore[arg-type]
    )


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert(
    request: Request,
    alert_id: str,
) -> AlertResponse:
    """Get a single alert by its UUID."""
    session_factory = getattr(request.app.state, "db_session_factory", None)
    if session_factory is None:
        raise HTTPException(status_code=503, detail="Database not available")

    from sentinel.db.repository import AlertRepository

    async with session_factory() as session:
        repo = AlertRepository(session)
        alert = await repo.get_by_alert_id(alert_id)

    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    return _alert_to_response(alert)


@router.get("/alerts", response_model=AlertListResponse)
async def list_alerts(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200, description="Max results"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    severity: str | None = Query(default=None, description="Filter by severity"),
    src_ip: str | None = Query(default=None, description="Filter by source IP"),
    hours: int | None = Query(default=None, ge=1, le=168, description="Look-back window"),
) -> AlertListResponse:
    """List recent alerts with optional filters.

    Results are ordered by creation time (newest first).
    """
    session_factory = getattr(request.app.state, "db_session_factory", None)
    if session_factory is None:
        raise HTTPException(status_code=503, detail="Database not available")

    from sentinel.db.repository import AlertRepository

    since = None
    if hours is not None:
        since = datetime.now(tz=UTC) - timedelta(hours=hours)

    async with session_factory() as session:
        repo = AlertRepository(session)
        alerts = await repo.list_recent(
            limit=limit,
            offset=offset,
            severity=severity,
            src_ip=src_ip,
            since=since,
        )
        total = await repo.count(severity=severity, since=since)

    return AlertListResponse(
        alerts=[_alert_to_response(a) for a in alerts],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("/alerts/{alert_id}/block", response_model=BlockResponse)
async def block_alert_ip(
    request: Request,
    alert_id: str,
) -> BlockResponse:
    """Mark an alert's source IP as blocked.

    In a real system this would also update firewall rules.
    For now it sets the is_blocked flag in the database.
    """
    session_factory = getattr(request.app.state, "db_session_factory", None)
    if session_factory is None:
        raise HTTPException(status_code=503, detail="Database not available")

    from sentinel.db.repository import AlertRepository

    async with session_factory() as session:
        repo = AlertRepository(session)
        success = await repo.mark_blocked(alert_id)
        if not success:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
        await session.commit()

    return BlockResponse(
        alert_id=alert_id,
        is_blocked=True,
        message=f"IP associated with alert {alert_id} has been blocked",
    )
