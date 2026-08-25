"""Log ingestion API endpoints.

POST /api/v1/ingest      — Submit a single log event
POST /api/v1/ingest/batch — Submit multiple log events at once
POST /api/v1/simulate     — Generate fake events for testing/demo
GET  /api/v1/queue/stats  — View Redis queue metrics
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

from sentinel.core.logging import get_logger
from sentinel.core.schemas import IngestResponse, LogEvent
from sentinel.ingestion import queue, simulator

logger = get_logger(__name__)

router = APIRouter(tags=["Ingestion"])


def _get_redis(request: Request) -> Any:
    """Extract the Redis connection from app state."""
    redis = getattr(request.app.state, "redis", None)
    if redis is None:
        raise HTTPException(
            status_code=503,
            detail="Redis not available. Queue service is not configured.",
        )
    return redis


@router.post("/ingest", response_model=IngestResponse)
async def ingest_event(event: LogEvent, request: Request) -> IngestResponse:
    """Ingest a single log event into the processing queue.

    The event is validated by Pydantic, then pushed to Redis Stream
    for async processing by the detection engine.
    """
    redis = _get_redis(request)

    stream_id = await queue.enqueue(redis, event)
    stream_len = await queue.get_stream_length(redis)

    logger.info(
        "event_ingested",
        event_id=event.event_id,
        event_type=event.event_type.value,
        src_ip=event.src_ip,
        stream_id=stream_id,
    )

    return IngestResponse(
        event_id=event.event_id,
        status="accepted",
        queue_position=stream_len,
    )


@router.post("/ingest/batch")
async def ingest_batch(events: list[LogEvent], request: Request) -> dict[str, Any]:
    """Ingest multiple log events in a single request.

    More efficient than sending events one by one — reduces
    HTTP overhead for high-volume log sources.
    """
    redis = _get_redis(request)

    accepted: list[str] = []
    failed: list[str] = []

    for event in events:
        try:
            await queue.enqueue(redis, event)
            accepted.append(event.event_id)
        except Exception:
            logger.exception("batch_enqueue_failed", event_id=event.event_id)
            failed.append(event.event_id)

    logger.info(
        "batch_ingested",
        total=len(events),
        accepted=len(accepted),
        failed=len(failed),
    )

    return {
        "total": len(events),
        "accepted": len(accepted),
        "failed": len(failed),
        "failed_ids": failed,
    }


@router.post("/simulate")
async def simulate_events(
    request: Request,
    count: int = 50,
    attack_ratio: float = 0.3,
) -> dict[str, Any]:
    """Generate and ingest simulated log events for testing.

    This endpoint is the demo button — it generates realistic
    attack and normal traffic patterns and pushes them through
    the full pipeline.
    """
    redis = _get_redis(request)

    if count < 1 or count > 1000:
        raise HTTPException(status_code=400, detail="count must be between 1 and 1000")
    if attack_ratio < 0.0 or attack_ratio > 1.0:
        raise HTTPException(status_code=400, detail="attack_ratio must be between 0.0 and 1.0")

    events = simulator.generate_batch(count=count, attack_ratio=attack_ratio)

    # Count events by type for the response
    type_counts: dict[str, int] = {}
    for event in events:
        key = event.event_type.value
        type_counts[key] = type_counts.get(key, 0) + 1

    # Enqueue all events
    for event in events:
        await queue.enqueue(redis, event)

    stream_len = await queue.get_stream_length(redis)

    logger.info(
        "simulation_completed",
        count=count,
        attack_ratio=attack_ratio,
        type_breakdown=type_counts,
    )

    return {
        "generated": count,
        "attack_ratio": attack_ratio,
        "event_types": type_counts,
        "queue_length": stream_len,
    }


@router.get("/queue/stats")
async def queue_stats(request: Request) -> dict[str, Any]:
    """Get current Redis queue statistics."""
    redis = _get_redis(request)

    stream_len = await queue.get_stream_length(redis)

    try:
        pending = await queue.get_pending_count(redis)
    except Exception:
        pending = -1

    return {
        "stream_length": stream_len,
        "pending_events": pending,
        "stream_key": queue.STREAM_KEY,
        "consumer_group": queue.GROUP_NAME,
    }
