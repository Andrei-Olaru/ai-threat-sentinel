"""Application settings loaded from environment variables.

Uses pydantic-settings to read .env file with automatic validation,
type coercion, and fail-fast on missing required values.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    """Deployment environment."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Central application configuration.

    Values are read from environment variables (or .env file).
    Uppercase field names match env var names automatically.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- App ---
    APP_NAME: str = "ai-threat-sentinel"
    APP_ENV: Environment = Environment.DEVELOPMENT
    DEBUG: bool = True
    LOG_LEVEL: str = "DEBUG"

    # --- Server ---
    HOST: str = "0.0.0.0"  # noqa: S104
    PORT: int = 8000

    # --- PostgreSQL ---
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://sentinel:sentinel_dev_pass@localhost:5432/threat_sentinel",
        description="Async PostgreSQL connection string",
    )

    # --- Redis ---
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection string for message queue",
    )

    # --- Groq API ---
    GROQ_API_KEY: str = Field(
        default="",
        description="Groq API key for LLM inference",
    )
    GROQ_MODEL_ID: str = Field(
        default="llama-3.3-70b-versatile",
        description="Groq model ID for security analysis",
    )

    # --- ML Engine ---
    ML_CONTAMINATION: float = Field(
        default=0.1,
        ge=0.01,
        le=0.5,
        description="Expected proportion of anomalies in the dataset",
    )
    ML_N_ESTIMATORS: int = Field(
        default=100,
        ge=10,
        le=1000,
        description="Number of trees in Isolation Forest ensemble",
    )

    # --- Rate Limiting ---
    RATE_LIMIT_PER_MINUTE: int = Field(
        default=60,
        ge=1,
        description="Max API requests per minute per IP",
    )

    # --- CORS ---
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:8000"]

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Ensure log level is valid."""
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            msg = f"LOG_LEVEL must be one of {allowed}, got '{v}'"
            raise ValueError(msg)
        return upper

    @property
    def is_production(self) -> bool:
        """Check if running in production."""
        return self.APP_ENV == Environment.PRODUCTION

    @property
    def is_development(self) -> bool:
        """Check if running in development."""
        return self.APP_ENV == Environment.DEVELOPMENT


def get_settings() -> Settings:
    """Factory function for settings singleton.

    Using a function (not a global) enables overriding in tests
    via FastAPI's dependency_overrides.
    """
    return Settings()
