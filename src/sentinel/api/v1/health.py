"""Health check endpoints following Kubernetes probe conventions.

/healthz (Liveness Probe):
  "Is the process alive?" — Always returns 200 if the server is running.
  If this fails, Kubernetes/Render restarts the container.

/readyz (Readiness Probe):
  "Can the app serve traffic?" — Checks if Redis (and later PostgreSQL)
  are reachable. If this fails, the load balancer stops sending traffic.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Request

router = APIRouter(tags=["Health"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness probe — confirms the process is running."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(tz=UTC).isoformat(),
    }


@router.get("/readyz")
async def readyz(request: Request) -> dict[str, object]:
    """Readiness probe — checks external dependency connectivity."""
    checks: dict[str, str] = {}

    # --- Redis check ---
    redis = getattr(request.app.state, "redis", None)
    if redis is not None:
        try:
            await redis.ping()
            checks["redis"] = "ok"
        except Exception:
            checks["redis"] = "error"
    else:
        checks["redis"] = "not_configured"

    # --- Database check (Module 4) ---
    checks["database"] = "not_configured"

    # Overall status: ready only if no checks are in "error" state
    all_ready = all(v in ("ok", "not_configured") for v in checks.values())

    return {
        "status": "ready" if all_ready else "not_ready",
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "checks": checks,
    }
