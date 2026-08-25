"""Redis Stream queue for async log event processing.

Uses Redis Streams (not simple pub/sub) because Streams provide:
- Persistent storage: events survive Redis restarts
- Consumer groups: multiple workers can process in parallel
- Acknowledgment: events aren't lost if a worker crashes
- Backpressure: if workers are slow, events queue up instead of being dropped

Data flow:
  API Gateway → enqueue(event) → Redis Stream → dequeue() → Worker
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sentinel.core.logging import get_logger
from sentinel.core.schemas import LogEvent

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = get_logger(__name__)

# Redis Stream key and consumer group name
STREAM_KEY = "sentinel:events"
GROUP_NAME = "sentinel-workers"
CONSUMER_NAME = "worker-1"


async def ensure_consumer_group(redis: Redis) -> None:
    """Create the consumer group if it doesn't exist.

    Consumer groups let multiple workers process events
    from the same stream without duplicating work.
    """
    try:
        await redis.xgroup_create(
            name=STREAM_KEY,
            groupname=GROUP_NAME,
            id="0",  # Start reading from the beginning
            mkstream=True,  # Create the stream if it doesn't exist
        )
        logger.info("consumer_group_created", stream=STREAM_KEY, group=GROUP_NAME)
    except Exception as exc:
        # "BUSYGROUP" means the group already exists — that's fine
        if "BUSYGROUP" in str(exc):
            logger.debug("consumer_group_exists", stream=STREAM_KEY, group=GROUP_NAME)
        else:
            raise


async def enqueue(redis: Redis, event: LogEvent) -> str:
    """Push a log event onto the Redis Stream.

    Args:
        redis: Async Redis connection.
        event: Validated log event to queue.

    Returns:
        The Redis Stream message ID (e.g. "1692345678901-0").
    """
    # Serialize the event to JSON and store as a single "data" field
    data = {"data": event.model_dump_json()}
    message_id: bytes = await redis.xadd(STREAM_KEY, data)
    msg_id_str = message_id.decode() if isinstance(message_id, bytes) else str(message_id)

    logger.debug(
        "event_enqueued",
        event_id=event.event_id,
        event_type=event.event_type.value,
        stream_id=msg_id_str,
    )
    return msg_id_str


async def dequeue(
    redis: Redis,
    count: int = 10,
    block_ms: int = 5000,
) -> list[tuple[str, LogEvent]]:
    """Read events from the Redis Stream using consumer group.

    Args:
        redis: Async Redis connection.
        count: Maximum number of events to read at once.
        block_ms: How long to wait for new events (milliseconds).
                  5000ms = poll every 5 seconds if no events.

    Returns:
        List of (stream_message_id, LogEvent) tuples.
    """
    results: list[tuple[str, LogEvent]] = []

    # XREADGROUP reads only events not yet delivered to this consumer
    response = await redis.xreadgroup(
        groupname=GROUP_NAME,
        consumername=CONSUMER_NAME,
        streams={STREAM_KEY: ">"},  # ">" means only new, undelivered messages
        count=count,
        block=block_ms,
    )

    if not response:
        return results

    # response format: [[stream_name, [(msg_id, {fields}), ...]]]
    for _stream_name, messages in response:
        for msg_id_raw, fields in messages:
            msg_id = msg_id_raw.decode() if isinstance(msg_id_raw, bytes) else str(msg_id_raw)
            try:
                raw_data = fields.get(b"data") or fields.get("data")
                if raw_data is None:
                    logger.warning("event_missing_data", stream_id=msg_id)
                    continue
                json_str = raw_data.decode() if isinstance(raw_data, bytes) else raw_data
                event = LogEvent.model_validate_json(json_str)
                results.append((msg_id, event))
            except Exception:
                logger.exception("event_deserialize_error", stream_id=msg_id)

    return results


async def acknowledge(redis: Redis, message_ids: list[str]) -> int:
    """Acknowledge processed events so they won't be re-delivered.

    After a worker successfully processes an event, it must ACK it.
    Unacknowledged events can be reclaimed by other workers if the
    original worker crashes (at-least-once delivery guarantee).
    """
    if not message_ids:
        return 0
    acked: int = await redis.xack(STREAM_KEY, GROUP_NAME, *message_ids)
    logger.debug("events_acknowledged", count=acked)
    return acked


async def get_stream_length(redis: Redis) -> int:
    """Get the current number of events in the stream."""
    return await redis.xlen(STREAM_KEY)


async def get_pending_count(redis: Redis) -> int:
    """Get the number of events delivered but not yet acknowledged."""
    info = await redis.xpending(STREAM_KEY, GROUP_NAME)
    # xpending returns a dict with 'pending' count
    if isinstance(info, dict):
        return info.get("pending", 0)
    # Some redis versions return a list: [pending_count, min_id, max_id, [[consumer, count]]]
    if isinstance(info, (list, tuple)) and len(info) > 0:
        return int(info[0])
    return 0
