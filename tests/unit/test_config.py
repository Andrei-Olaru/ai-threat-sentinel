"""Tests for application configuration."""

from __future__ import annotations

import pytest

from sentinel.config import Environment, Settings


class TestSettings:
    """Test suite for Settings configuration class."""

    def test_default_values(self) -> None:
        """Settings should have sensible defaults."""
        settings = Settings(
            DATABASE_URL="postgresql+asyncpg://x:x@localhost/test",
            REDIS_URL="redis://localhost:6379/0",
        )
        assert settings.APP_NAME == "ai-threat-sentinel"
        assert settings.APP_ENV == Environment.DEVELOPMENT
        assert settings.DEBUG is True
        assert settings.PORT == 8000

    def test_production_detection(self) -> None:
        """is_production should be True only for production env."""
        settings = Settings(APP_ENV="production")
        assert settings.is_production is True
        assert settings.is_development is False

    def test_log_level_validation(self) -> None:
        """LOG_LEVEL should reject invalid values."""
        with pytest.raises(ValueError, match="LOG_LEVEL must be one of"):
            Settings(LOG_LEVEL="VERBOSE")

    def test_log_level_case_insensitive(self) -> None:
        """LOG_LEVEL should accept lowercase input."""
        settings = Settings(LOG_LEVEL="debug")
        assert settings.LOG_LEVEL == "DEBUG"

    def test_ml_contamination_bounds(self) -> None:
        """ML_CONTAMINATION should be between 0.01 and 0.5."""
        with pytest.raises(ValueError, match="greater than or equal"):
            Settings(ML_CONTAMINATION=0.0)
        with pytest.raises(ValueError, match="less than or equal"):
            Settings(ML_CONTAMINATION=0.9)

    def test_cors_origins_default(self) -> None:
        """CORS_ORIGINS should default to localhost entries."""
        settings = Settings()
        assert "http://localhost:8000" in settings.CORS_ORIGINS
