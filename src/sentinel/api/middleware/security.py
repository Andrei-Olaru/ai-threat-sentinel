"""Security headers middleware.

Adds HTTP security headers to every response to protect against
common web attacks. These are defense-in-depth measures.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all HTTP responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        # Prevent MIME type sniffing (stops browser from guessing content type)
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking (stops your page from being embedded in an iframe)
        response.headers["X-Frame-Options"] = "DENY"

        # Enable XSS filter in older browsers
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Only send referrer for same-origin requests (privacy)
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Control what browser features the site can use
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

        # Strict Transport Security — force HTTPS (only in production)
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response
