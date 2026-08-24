"""Custom exception hierarchy for the Sentinel application.

Why a custom hierarchy instead of raising generic Exception?
- Consistent error responses across the API
- Granular error handling (catch SecurityError vs ValidationError)
- Each exception carries structured context (event_id, ip, etc.)
- Maps cleanly to HTTP status codes
"""

from __future__ import annotations


class SentinelError(Exception):
    """Base exception for all Sentinel errors."""

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        self.message = message
        self.detail = detail
        super().__init__(message)


class ConfigurationError(SentinelError):
    """Raised when application configuration is invalid or missing."""


class DatabaseError(SentinelError):
    """Raised when a database operation fails."""


class QueueError(SentinelError):
    """Raised when Redis queue operations fail."""


class IngestionError(SentinelError):
    """Raised when log ingestion validation or processing fails."""


class DetectionError(SentinelError):
    """Raised when the ML engine or rule engine encounters an error."""


class EnrichmentError(SentinelError):
    """Raised when LLM enrichment (Groq API) fails."""

    def __init__(
        self,
        message: str,
        *,
        detail: str | None = None,
        model_id: str | None = None,
    ) -> None:
        self.model_id = model_id
        super().__init__(message, detail=detail)


class RateLimitExceededError(SentinelError):
    """Raised when a client exceeds the rate limit."""

    def __init__(self, message: str = "Rate limit exceeded", *, retry_after: int = 60) -> None:
        self.retry_after = retry_after
        super().__init__(message)
