"""Health check endpoints following Kubernetes probe conventions.

Two separate endpoints serve different purposes:

/healthz (Liveness Probe):
  "Is the process alive?" — Always returns 200 if the server is running.
  If this fails, Kubernetes/Render restarts the container.

/readyz (Readiness Probe):
  "Can the app serve traffic?" — Checks if PostgreSQL and Redis are reachable.
  If this fails, the load balancer stops sending traffic until it recovers.
  The app is NOT restarted — it might just be waiting for the DB to come up.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter

router = APIRouter(tags=["Health"])


@router.get("/healthz")
async def healthz() -> dict[str, str | str]:
    """Liveness probe — confirms the process is running."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(tz=UTC).isoformat(),
    }


@router.get("/readyz")
async def readyz() -> dict[str, object]:
    """Readiness probe — checks external dependency connectivity.

    TODO (Module 2+): Add actual Redis ping and DB query checks.
    For now, returns healthy to allow the app to start.
    """
    checks: dict[str, str] = {}

    # Placeholder checks — will be replaced with real connectivity tests
    checks["database"] = "not_configured"
    checks["redis"] = "not_configured"

    # Overall status: ready only if all checks pass
    all_ready = all(v in ("ok", "not_configured") for v in checks.values())

    return {
        "status": "ready" if all_ready else "not_ready",
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "checks": checks,
    }
