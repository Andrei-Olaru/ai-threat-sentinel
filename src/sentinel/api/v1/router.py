"""API v1 aggregated router.

All v1 endpoints are registered here and mounted
on the app with prefix /api/v1 in main.py.
"""

from __future__ import annotations

from fastapi import APIRouter

from sentinel.api.v1.health import router as health_router
from sentinel.api.v1.ingest import router as ingest_router

api_v1_router = APIRouter()

# Health checks: /api/v1/healthz, /api/v1/readyz
api_v1_router.include_router(health_router)

# Ingestion: /api/v1/ingest, /api/v1/simulate, /api/v1/queue/stats
api_v1_router.include_router(ingest_router)
