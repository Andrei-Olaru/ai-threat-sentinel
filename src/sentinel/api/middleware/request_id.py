"""Request ID middleware — attaches a unique ID to every request.

Why this matters:
- When a user reports "I got an error", you can ask for the X-Request-ID
  and trace the EXACT request through logs, database, and queue
- In a distributed system, the request ID follows the event across services
- Essential for production debugging and incident response
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Inject X-Request-ID into every request/response cycle."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Use client-provided ID if present (for tracing across services),
        # otherwise generate a new one
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

        # Store on request state so handlers can access it
        request.state.request_id = request_id

        # Bind request_id to structlog context vars (available in all logs
        # within this request's async context, then cleared automatically)
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        response = await call_next(request)

        # Echo back in response header so clients can reference it
        response.headers["X-Request-ID"] = request_id
        return response
